"""Knowledge base: ATT&CK loading and diffing, NVD/EPSS/OSV/KEV vulnerability
records, feed → graph linking, resolution and path finding. Everything runs
against recorded fixtures (tests/fixtures/kb) and a SQLite database."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.kb_helpers import KbUpstream, combined, kb_bytes, nvd_pool
from tests.test_collect import Clock, feed_handler
from threatlens.collect import Collector
from threatlens.kb import graph
from threatlens.kb.attack import DowngradeError, changed_fields, load_release, version_key
from threatlens.kb.base import KbContext
from threatlens.kb.epss import parse_epss
from threatlens.kb.ids import alias_key, indicator_stix_id, vulnerability_stix_id
from threatlens.kb.link import mentions
from threatlens.kb.vulns import exploit_signals, parse_cpe, parse_nvd
from threatlens.models import (
    AttackChange,
    AttackRelease,
    Entity,
    Relationship,
    Source,
    Vulnerability,
    VulnerabilityProduct,
)
from threatlens.net.http import SafeHttp
from threatlens.rawstore import RawStore
from threatlens.settings import Settings

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
EMOTET = "malware--32066e94-3112-48ca-b9eb-ba2b59d2f023"


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, s: float) -> None:
        self.calls.append(s)


def make(
    sm: SM,
    http: SafeHttp,
    tmp_path: Path,
    clock: Clock | None = None,
    sleep: Sleeps | None = None,
    **settings: Any,
) -> Collector:
    return Collector(
        sm,
        http,
        RawStore(tmp_path / "data"),
        Settings(**settings),  # type: ignore[arg-type]
        now=clock or Clock(),
        sleep=sleep or Sleeps(),
    )


async def count(sm: SM, model: type, *where: Any) -> int:
    async with sm() as s:
        return int(await s.scalar(select(func.count()).select_from(model).where(*where)) or 0)


# ── pure helpers ─────────────────────────────────────────────────────────────


def test_ids_are_deterministic() -> None:
    assert vulnerability_stix_id("cve-2024-3400") == vulnerability_stix_id("CVE-2024-3400")
    assert vulnerability_stix_id("CVE-2024-3400").startswith("vulnerability--")
    assert indicator_stix_id("ipv4-addr:1.2.3.4") != indicator_stix_id("ipv4-addr:1.2.3.5")
    assert alias_key("Cobalt Strike") == alias_key("cobalt-strike") == "cobaltstrike"


def test_version_order() -> None:
    assert version_key("19.10") > version_key("19.2") > version_key("9.0")


def test_parse_cpe() -> None:
    assert parse_cpe("cpe:2.3:o:fortinet:fortios:7.0.1:*:*:*:*:*:*:*") == ("o", "fortinet", "fortios")
    assert parse_cpe("cpe:2.3:a:*:*:*") is None
    assert parse_cpe("cpe:/a:old:format") is None
    assert parse_cpe("garbage") is None


def test_parse_nvd_panos() -> None:
    cve = next(v["cve"] for v in nvd_pool() if v["cve"]["id"] == "CVE-2024-3400")
    r = parse_nvd(cve)
    v = r.values
    assert (v["cvss_version"], v["cvss_score"], v["cvss_severity"]) == ("3.1", 10.0, "CRITICAL")
    assert v["cvss_vector"].startswith("CVSS:3.1/AV:N")
    assert v["kev"] is True
    assert str(v["kev_date_added"]) == "2024-04-12"
    assert str(v["kev_due_date"]) == "2024-04-19"
    assert v["ssvc"]["exploitation"] == "active"
    assert {"CWE-77", "CWE-20"} <= set(v["cwes"])
    assert ("o", "paloaltonetworks", "pan-os") in r.products
    assert any("unit42" in u for u in v["exploit_refs"])


def test_parse_nvd_versions() -> None:
    by_id = {v["cve"]["id"]: parse_nvd(v["cve"]) for v in nvd_pool()}
    v4 = by_id["CVE-2025-64118"].values
    assert v4["cvss_version"] == "4.0"
    assert v4["kev"] is False if "kev" in v4 else True
    log4j = by_id["CVE-2021-44228"].values
    assert log4j["cvss_version"] == "3.1"  # v3.1 beats v2
    assert {x["version"] for x in log4j["cvss"]} >= {"3.1", "2.0"}
    assert all(x["severity"] for x in log4j["cvss"])  # v2 severity sits outside cvssData


def test_parse_nvd_rejects_bad_records() -> None:
    from threatlens.connectors.base import SchemaDriftError

    with pytest.raises(SchemaDriftError):
        parse_nvd({"id": "not-a-cve"})


def test_parse_epss() -> None:
    meta, scores = parse_epss(kb_bytes("epss_scores.csv.gz"))
    assert meta["model_version"] == "v2026.06.15"
    assert meta["score_date"].startswith("2026-10-08")
    assert scores["CVE-2024-3400"][0] > 0.9
    from threatlens.connectors.base import SchemaDriftError

    with pytest.raises(SchemaDriftError):
        parse_epss(b"cve,score\nCVE-1,0.1\n")


def test_changed_fields_ignores_noise() -> None:
    a = {"name": "X", "revoked": None, "modified": "1", "x_mitre_attack_spec_version": "3.2.0"}
    b = {"name": "X", "revoked": False, "modified": "2", "x_mitre_attack_spec_version": "3.3.0"}
    assert changed_fields(a, b) == []
    assert changed_fields(a, {**b, "name": "Y"}) == ["name"]


@pytest.mark.parametrize(
    ("source", "ctx", "want"),
    [
        ("feodo", {"malware": "QakBot"}, [("malware", "QakBot", "malware")]),
        ("threatfox", {"malware": "Unknown malware"}, []),
        (
            "otx",
            {
                "malware_families": [{"id": "x", "display_name": "Emotet"}],
                "adversary": "Wizard Spider",
                "attack_ids": [{"id": "T1047"}, "t1059.001", "not-a-technique"],
            },
            [
                ("malware", "Emotet", "malware_families"),
                ("intrusion-set", "Wizard Spider", "adversary"),
                ("attack-pattern", "T1047", "attack_ids"),
                ("attack-pattern", "T1059.001", "attack_ids"),
            ],
        ),
        ("urlhaus", {"malware": "x"}, []),
    ],
)
def test_feed_mentions(source: str, ctx: dict[str, Any], want: list[tuple[str, str, str]]) -> None:
    assert mentions(source, ctx) == want


# ── ATT&CK ───────────────────────────────────────────────────────────────────


async def test_attack_baseline_then_diff(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    up = KbUpstream(attack_versions=["19.1"])
    clock = Clock()
    c = make(sm, mock_http(up), tmp_path, clock)

    first = await c.run("mitre_attack")
    assert first.status == "success", first.error
    assert "enterprise-attack 19.1" in (first.note or "")
    async with sm() as s:
        rel = await s.scalar(select(AttackRelease))
        assert rel is not None
        assert (rel.version, rel.baseline) == ("19.1", True)
        assert rel.counts["attack-pattern"] == 13
        emotet = await s.scalar(select(Entity).where(Entity.external_id == "S0367"))
        assert emotet is not None
        assert "Geodo" in emotet.aliases
        assert emotet.stix_id == EMOTET
        sub = await s.scalar(select(Entity).where(Entity.external_id == "T1110.001"))
        assert sub is not None
        assert sub.is_subtechnique
        assert sub.tactics == ["credential-access"]
    assert await count(sm, AttackChange) == 0  # a baseline lists nothing as "added"

    up.attack_versions = ["19.2", "19.1"]
    clock.advance(days=1)
    second = await c.run("mitre_attack")
    assert second.status == "success", second.error
    async with sm() as s:
        r2 = await s.scalar(select(AttackRelease).where(AttackRelease.version == "19.2"))
        assert r2 is not None
        assert (r2.baseline, r2.previous_version) == (False, "19.1")
        changes = (await s.scalars(select(AttackChange).where(AttackChange.release_id == r2.id))).all()
    added = {(ch.type, ch.name) for ch in changes if ch.change == "added"}
    assert ("intrusion-set", "TeamPCP") in added
    assert r2.summary["relationships_added"] >= 1
    assert r2.summary.get("touched", 0) > 0  # timestamp-only updates are counted, not listed
    assert all(ch.change != "modified" or ch.details["fields"] for ch in changes)

    clock.advance(days=1)
    third = await c.run("mitre_attack")
    assert third.note == "up to date"


async def test_attack_downgrade_needs_force(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = make(sm, mock_http(KbUpstream(attack_versions=["19.2"])), tmp_path)
    await c.run("mitre_attack")
    src = await c.source_row("mitre_attack")
    ctx = KbContext(c.sm, c.http, c.store, c.settings, c.now(), src.id, "mitre_attack", {}, c.sleep)
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json"
    with pytest.raises(DowngradeError):
        await load_release(ctx, "enterprise-attack", "19.1", url)
    res = await load_release(ctx, "enterprise-attack", "19.1", url, force=True)
    assert res.items_total > 0
    async with sm() as s:
        removed = (await s.scalars(select(AttackChange).where(AttackChange.change == "removed"))).all()
    assert [r.name for r in removed] == ["TeamPCP"]  # 19.1 predates it

    url2 = url.replace("19.1", "19.2")
    with pytest.raises(DowngradeError, match="already loaded"):
        await load_release(ctx, "enterprise-attack", "19.2", url2)
    await load_release(ctx, "enterprise-attack", "19.2", url2, force=True)  # back to 19.2: a diff vs 19.1
    async with sm() as s:
        releases = (await s.scalars(select(AttackRelease).order_by(AttackRelease.id))).all()
        restored = (await s.scalars(select(AttackChange.name).where(AttackChange.change == "restored"))).all()
        team = await s.scalar(select(Entity).where(Entity.name == "TeamPCP"))
    assert [(r.version, r.previous_version) for r in releases] == [("19.1", "19.2"), ("19.2", "19.1")]
    assert restored == ["TeamPCP"]
    assert team is not None
    assert team.domains == ["enterprise-attack"]
    assert not team.deprecated


async def test_attack_relationships_and_mentions(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = make(sm, mock_http(KbUpstream(attack_versions=["19.2"])), tmp_path)
    await c.run("mitre_attack")
    assert await count(sm, Relationship, Relationship.origin == "attack") == 15
    async with sm() as s:
        m = await s.scalar(
            select(Relationship).where(
                Relationship.origin == "attack-mention",
                Relationship.dst_ref == vulnerability_stix_id("CVE-2020-1472"),
            )
        )
        assert m is not None
        assert "CVE-2020-1472" in m.provenance["quote"]
        wizard = await s.scalar(select(Entity).where(Entity.name == "Wizard Spider"))
        assert wizard is not None
        assert m.src_ref == wizard.stix_id
        stub = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2020-1472"))
        assert stub is not None
        assert stub.nvd_modified is None  # a stub until NVD fills it


async def test_schema_drift_fails_the_source(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    def broken(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("index.json"):
            return httpx.Response(200, json={"not": "an index"})
        return httpx.Response(404)

    c = make(sm, mock_http(broken), tmp_path)
    r = await c.run("mitre_attack")
    assert r.status == "failed"
    assert "SchemaDriftError" in (r.error or "")
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "mitre_attack"))
    assert src is not None
    assert src.health == "failing"


# ── vulnerabilities ─────────────────────────────────────────────────────────


async def test_nvd_baseline_changes_and_stubs(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    up = KbUpstream()
    clock = Clock()
    sleeps = Sleeps()
    c = make(sm, mock_http(up), tmp_path, clock, sleeps)
    async with sm() as s, s.begin():
        from threatlens.kb.vulns import ensure_stubs

        await ensure_stubs(s, ["CVE-2099-0001"])  # a CVE some feed named; NVD has no record

    r = await c.run("nvd")
    assert r.status == "success", r.error
    params = [dict(q.url.params) for q in up.requests if q.url.host == "services.nvd.nist.gov"]
    assert any("hasKev" in p for p in params)
    assert any(
        p.get("virtualMatchString") == "cpe:2.3:o:fortinet:fortios" for p in params
    )  # org profile stack
    assert any(p.get("cveId") == "CVE-2099-0001" for p in params)
    assert sleeps.calls
    assert all(x == 6.5 for x in sleeps.calls)  # keyless pacing
    async with sm() as s:
        cves = set(
            (
                await s.scalars(select(Vulnerability.cve_id).where(Vulnerability.nvd_modified.is_not(None)))
            ).all()
        )
        src = await s.scalar(select(Source).where(Source.name == "nvd"))
        fortios = await s.scalar(
            select(func.count())
            .select_from(VulnerabilityProduct)
            .where(VulnerabilityProduct.product == "fortios")
        )
    assert {"CVE-2024-3400", "CVE-2021-44228", "CVE-2020-1472", "CVE-2025-43892", "CVE-2025-62675"} <= cves
    assert "CVE-2025-64118" not in cves  # not KEV, not in the stack, never seen: out of scope
    assert fortios
    assert src is not None
    assert src.checkpoint["baseline_done"] is True
    assert "CVE-2099-0001" in src.checkpoint["missing"]

    # Next run: the change feed. Only relevant CVEs are kept.
    clock.advance(hours=3)
    up.requests.clear()
    r2 = await c.run("nvd")
    assert r2.status == "success", r2.error
    params = [dict(q.url.params) for q in up.requests if q.url.host == "services.nvd.nist.gov"]
    assert "lastModStartDate" in params[0]
    assert params[0]["lastModEndDate"].endswith("Z")
    assert not any(p.get("cveId") == "CVE-2099-0001" for p in params)  # retried after a week, not now
    assert await count(sm, Vulnerability, Vulnerability.cve_id == "CVE-2025-64118") == 0


async def test_nvd_scope_all_keeps_everything(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = make(sm, mock_http(KbUpstream()), tmp_path, clock, nvd_scope="all")
    await c.run("nvd")
    clock.advance(hours=3)
    await c.run("nvd")
    assert await count(sm, Vulnerability, Vulnerability.cve_id == "CVE-2025-64118") == 1


async def test_nvd_budget_makes_runs_partial_and_resumable(
    sm: SM, mock_http: MakeHttp, tmp_path: Path
) -> None:
    up = KbUpstream()
    clock = Clock()
    c = make(sm, mock_http(up), tmp_path, clock, nvd_max_requests=1)
    r = await c.run("nvd")
    assert r.status == "partial"
    assert "continuing next run" in (r.note or "")
    src = await c.source_row("nvd")
    assert src.checkpoint["baseline_done"] is True  # the KEV pass finished and is kept
    assert not src.checkpoint.get("stack_done")

    clock.advance(hours=3)
    up.requests.clear()
    r2 = await c.run("nvd")  # one request: the change feed; the stack pass waits again
    assert r2.status == "partial"
    c.settings.nvd_max_requests = 10
    clock.advance(hours=3)
    r3 = await c.run("nvd")
    assert r3.status == "success", r3.error
    src = await c.source_row("nvd")
    assert src.checkpoint["stack_done"] == [
        "cpe:2.3:a:apache:tomcat",
        "cpe:2.3:o:fortinet:fortios",
        "cpe:2.3:o:microsoft:windows_server_2022",
    ]
    assert not any("hasKev" in q.url.params for q in up.requests)  # the KEV pass is never repeated


async def test_nvd_bad_key(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = make(sm, mock_http(KbUpstream(nvd_status=404)), tmp_path, nvd_api_key="wrong")
    r = await c.run("nvd")
    assert r.status == "failed"
    assert "API key is probably invalid" in (r.error or "")


async def test_epss_osv_and_kev(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    http = mock_http(combined(feed_handler(), KbUpstream()))
    c = make(sm, http, tmp_path, clock)
    assert (await c.run("cisa_kev")).status == "success"  # KEV via the Phase 1 connector
    assert (await c.run("nvd")).status == "success"
    e = await c.run("epss")
    assert e.status == "success", e.error
    assert e.items_updated == 5  # the KEV fixture CVEs are not in the trimmed EPSS fixture
    o = await c.run("osv")
    assert o.status == "success", o.error

    async with sm() as s:
        panos = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2024-3400"))
        log4j = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-44228"))
        kev_stub = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-59310"))
    assert panos is not None
    assert log4j is not None
    assert kev_stub is not None
    assert panos.kev
    assert panos.epss is not None
    assert panos.epss > 0.9
    assert str(panos.epss_date) == "2026-10-08"
    assert panos.osv_ids == []  # OSV has no open-source advisory for PAN-OS
    assert panos.osv_checked_at is not None
    assert log4j.osv_ids == ["GHSA-jfh8-c2jp-5v3q"]
    assert {p["name"] for p in log4j.packages} >= {"org.apache.logging.log4j:log4j-core"}
    # KEV facts arrive from the KEV connector even before NVD knows the CVE.
    assert kev_stub.kev
    assert kev_stub.kev_ransomware == "Known"
    assert kev_stub.description
    signals = {x["signal"] for x in exploit_signals(panos)}
    assert {"exploited-in-the-wild", "exploitation-active", "public-exploit-reference"} <= signals

    async with sm() as s, s.begin():
        from threatlens.kb.vulns import ensure_stubs

        await ensure_stubs(s, ["CVE-2025-64118"])  # a CVE first seen after the last EPSS download
    clock.advance(hours=7)
    again = await c.run("epss")
    assert again.status == "not_modified"
    assert again.items_updated == 1
    assert "from the archive" in (again.note or "")
    async with sm() as s:
        late = await s.scalar(select(Vulnerability.epss).where(Vulnerability.cve_id == "CVE-2025-64118"))
    assert late is not None


# ── linking and the graph ───────────────────────────────────────────────────


async def build_graph(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> Collector:
    c = make(sm, mock_http(combined(feed_handler(), KbUpstream(attack_versions=["19.2"]))), tmp_path)
    for name in ("mitre_attack", "cisa_kev", "feodo", "threatfox", "nvd"):
        r = await c.run(name)
        assert r.status in ("success", "skipped"), (name, r.error)
    return c


async def test_feed_names_link_to_attack_entities(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s:
        to_emotet = (
            await s.scalars(
                select(Relationship).where(Relationship.dst_ref == EMOTET, Relationship.origin == "feed")
            )
        ).all()
        qakbot = await s.scalar(select(Entity).where(Entity.name == "QakBot"))
        unknown = await s.scalar(select(Entity).where(func.lower(Entity.name) == "unknown malware"))
        identity = await s.scalar(
            select(func.count()).select_from(Relationship).where(Relationship.origin == "identity")
        )
    assert to_emotet
    assert to_emotet[0].rel_type == "indicates"
    assert to_emotet[0].provenance["field"] == "malware"
    assert qakbot is not None
    assert qakbot.origin == "feed"  # not in this ATT&CK subset: a local entity
    assert unknown is None
    assert identity == 3  # one per KEV CVE indicator


async def test_feed_entities_merge_into_attack_loaded_later(
    sm: SM, mock_http: MakeHttp, tmp_path: Path
) -> None:
    """Feeds collected before ATT&CK create local entities; loading ATT&CK folds them in."""
    c = make(sm, mock_http(combined(feed_handler(), KbUpstream(attack_versions=["19.2"]))), tmp_path)
    assert (await c.run("feodo")).status == "success"
    async with sm() as s:
        local = await s.scalar(select(Entity).where(Entity.name == "Emotet", Entity.origin == "feed"))
        assert local is not None
        local_ref = local.stix_id
    r = await c.run("mitre_attack")
    assert r.status == "success", r.error
    async with sm() as s:
        assert await s.scalar(select(Entity).where(Entity.stix_id == local_ref)) is None
        assert (
            await s.scalar(
                select(func.count()).select_from(Relationship).where(Relationship.dst_ref == local_ref)
            )
            == 0
        )
        edge = await s.scalar(
            select(Relationship).where(Relationship.dst_ref == EMOTET, Relationship.origin == "feed")
        )
        qakbot = await s.scalar(select(Entity).where(Entity.name == "QakBot"))
        rel = await s.scalar(select(AttackRelease))
    assert edge is not None
    assert edge.provenance["merged_from"] == "Emotet"
    assert qakbot is not None
    assert qakbot.origin == "feed"  # still unknown to this ATT&CK subset
    assert rel is not None
    assert rel.summary["feed_entities_merged"] == 1


async def test_resolve(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s:
        for ident in ("S0367", "emotet", "Geodo", EMOTET):
            n = await graph.resolve(s, ident)
            assert n is not None
            assert n.ref == EMOTET, ident
        t = await graph.resolve(s, "t1047")
        assert t is not None
        assert t.label == "Windows Management Instrumentation"
        v = await graph.resolve(s, "cve-2024-3400")
        assert v is not None
        assert v.kind == "vulnerability"
        assert v.extra["kev"] is True
        feodo_ip = json.loads((Path(__file__).parent / "fixtures" / "feodo.json").read_text())[0][
            "ip_address"
        ]
        ip = await graph.resolve(s, feodo_ip)
        assert ip is not None
        assert ip.kind == "indicator"
        assert "[.]" in ip.label  # defanged label
        assert await graph.resolve(s, f"indicator:{ip.extra['id']}") is not None
        assert await graph.resolve(s, "no such thing at all") is None
        assert await graph.resolve(s, "x" * 400) is None


async def test_paths_with_provenance(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    await build_graph(sm, mock_http, tmp_path)
    feodo = json.loads((Path(__file__).parent / "fixtures" / "feodo.json").read_text())
    emotet_ip = next(d["ip_address"] for d in feodo if d.get("malware") == "Emotet")
    async with sm() as s:
        ip = await graph.resolve(s, emotet_ip)
        tech = await graph.resolve(s, "T1047")
        cve = await graph.resolve(s, "CVE-2020-1472")
        assert ip is not None
        assert tech is not None
        assert cve is not None

        res = await graph.paths(s, ip.ref, tech.ref)
        assert res.length == 2
        (path,) = res.paths
        assert [e["rel_type"] for e in path] == ["indicates", "uses"]
        assert [e["source"] for e in path] == ["feodo", "mitre_attack"]
        assert path[0]["provenance"]["field"] == "malware"
        assert path[1]["provenance"]["attack_relationship"].startswith("relationship--")

        # indicator → malware ← group → CVE named in ATT&CK text
        res = await graph.paths(s, ip.ref, cve.ref)
        assert res.length == 3
        assert [e["origin"] for e in res.paths[0]] == ["feed", "attack", "attack-mention"]
        assert "CVE-2020-1472" in res.paths[0][2]["provenance"]["quote"]
        assert set(res.nodes) >= {ip.ref, EMOTET, cve.ref}

        none = await graph.paths(s, ip.ref, cve.ref, max_depth=2)
        assert none.paths == []
        assert none.length is None

        revoked_src = await s.scalar(select(Entity.stix_id).where(Entity.revoked.is_(True)))
        if revoked_src:
            items, _ = await graph.neighbors(s, revoked_src)
            assert all(i["edge"]["rel_type"] != "revoked-by" for i in items)


async def test_paths_respect_node_budget(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s:
        a = await graph.resolve(s, "TeamPCP")
        b = await graph.resolve(s, "CVE-2024-3400")
        assert a is not None
        assert b is not None
        res = await graph.paths(s, a.ref, b.ref, max_depth=6, max_nodes=1)
    assert res.paths == []
    assert res.truncated


async def test_otx_pulse_links_actor_malware_and_techniques(
    sm: SM, mock_http: MakeHttp, tmp_path: Path
) -> None:
    from datetime import UTC, datetime

    from threatlens.kb.link import link_source
    from threatlens.models import Indicator, Observable, Sighting

    c = make(sm, mock_http(KbUpstream(attack_versions=["19.2"])), tmp_path)
    await c.run("mitre_attack")
    await c.sync_sources()
    now = datetime(2026, 10, 9, tzinfo=UTC)
    async with sm() as s, s.begin():
        otx = await s.scalar(select(Source).where(Source.name == "otx"))
        assert otx is not None
        obs = Observable(
            type="domain-name",
            value="evil-c2.net",
            canonical_key="domain-name:evil-c2.net",
            defanged="evil-c2[.]net",
        )
        s.add(obs)
        await s.flush()
        ind = Indicator(observable_id=obs.id, stix_id=indicator_stix_id(obs.canonical_key), labels=[])
        s.add(ind)
        await s.flush()
        s.add(
            Sighting(
                indicator_id=ind.id, source_id=otx.id, confidence=60, labels=[], updated_at=now,
                context={
                    "pulse_id": "p1", "pulse": "Wizard Spider drops Emotet",
                    "adversary": "Wizard Spider",
                    "malware_families": [{"id": "m", "display_name": "Emotet"}],
                    "attack_ids": [{"id": "T1047"}],
                },
            )
        )  # fmt: skip
    written = await link_source(sm, "otx", now)
    assert written == 5  # 3 indicates, actor uses malware, malware uses technique
    async with sm() as s:
        wizard = await graph.resolve(s, "Wizard Spider")
        t1047 = await graph.resolve(s, "T1047")
        assert wizard is not None
        assert t1047 is not None
        claims = (
            await s.scalars(
                select(Relationship).where(Relationship.origin == "feed", Relationship.rel_type == "uses")
            )
        ).all()
    pairs = {(r.src_ref, r.dst_ref) for r in claims}
    assert (wizard.ref, EMOTET) in pairs
    assert (EMOTET, t1047.ref) in pairs
    assert all(r.confidence == 40 and r.provenance["pulse"] == "p1" for r in claims)  # a community claim
