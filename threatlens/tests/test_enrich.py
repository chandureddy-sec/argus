"""Enrichment (Phase 3): each enricher against recorded answers, the policy
engine (cache, TLP, active mode, keys, budget, quota, timeouts), provenance
storage, the interim verdict, and the lookup / bulk API."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.conftest import FIXTURES
from tests.test_collect import Clock, collector, feed_handler
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich import REGISTRY
from threatlens.enrich.base import Enricher, EnricherInfo, Outcome, Quota
from threatlens.enrich.dns import Dns
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.rdap import Rdap
from threatlens.enrich.reputation import GreyNoise, UrlScan, vt_url_id
from threatlens.enrich.ripestat import RipeStat
from threatlens.enrich.service import EnrichmentService, stricter_tlp, tlp_blocks
from threatlens.ioc.types import IOCType, Observable
from threatlens.models import AllowlistEntry, AuditLog, Enrichment, Indicator, Source
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.tlp import RED

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
E = FIXTURES / "enrich"
FEODO_IP = "162.243.103.246"  # in feodo.json; RDAP/RIPEstat fixtures are for this IP
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
KEYS = {"abuseipdb_api_key": "k1", "virustotal_api_key": "k2", "abusech_auth_key": "k3"}


def fx(name: str) -> bytes:
    return (E / name).read_bytes()


def ok(name: str, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, content=fx(name), headers={"content-type": "application/json", **headers})


class Upstream:
    """Every provider, answered from fixtures; counts requests per host."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.greynoise_headers: dict[str, str] = {
            "X-Ratelimit-Remaining": "20",
            "X-Ratelimit-Reset": "4102444800",
        }
        self.fail: dict[str, int] = {}  # host -> HTTP status to answer with
        self.hang: set[str] = set()

    async def __call__(self, req: httpx.Request) -> httpx.Response:
        host, path = req.url.host, req.url.path
        self.calls.append(host)
        if host in self.hang:
            await asyncio.sleep(30)
        if host in self.fail:
            return httpx.Response(self.fail[host], headers={"Retry-After": "120"})
        q = parse_qs(req.url.query.decode())
        if host == "data.iana.org":
            return ok(f"iana_{path.rsplit('/', 1)[1]}")
        if host == "rdap.verisign.com":
            return (
                ok("rdap_domain_github.json")
                if path.endswith("/github.com")
                else ok("rdap_domain_404.json", 404)
            )
        if host == "rdap.arin.net":
            return ok("rdap_ip_arin.json")
        if host == "stat.ripe.net":
            return ok("ripestat_prefix.json" if "prefix-overview" in path else "ripestat_geo.json")
        if host == "cloudflare-dns.com":
            name, rtype = q["name"][0], q["type"][0]
            return ok(f"doh_github_{rtype}.json" if name == "github.com" else "doh_nx_A.json")
        if host == "api.greynoise.io":
            if path.endswith("/71.6.199.23"):
                return ok("greynoise_benign.json", **self.greynoise_headers)
            return ok("greynoise_404.json", 404, **self.greynoise_headers)
        if host == "api.abuseipdb.com":
            return ok(
                "abuseipdb_check.json", **{"X-RateLimit-Remaining": "999", "X-RateLimit-Reset": "4102444800"}
            )
        if host == "www.virustotal.com":
            if path.endswith(f"/ip_addresses/{FEODO_IP}"):
                return ok("virustotal_ip.json")
            if path.endswith(f"/files/{EICAR}"):
                return ok("virustotal_file.json")
            return ok("virustotal_404.json", 404)
        if host == "urlscan.io":
            return ok("urlscan_search.json" if "github.com" in q["q"][0] else "urlscan_empty.json")
        if host == "mb-api.abuse.ch":
            form = parse_qs(req.content.decode())
            return ok("malwarebazaar_hit.json" if form["hash"][0] == EICAR else "malwarebazaar_miss.json")
        if host == "crt.sh":
            return ok("crtsh.json")
        return httpx.Response(599)


@pytest.fixture
def upstream() -> Upstream:
    return Upstream()


@pytest.fixture
def http(upstream: Upstream) -> SafeHttp:
    async def no_sleep(_: float) -> None:
        return None

    return SafeHttp(transport=httpx.MockTransport(upstream), sleep=no_sleep, retries=0)


@pytest.fixture
async def seeded(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> SM:
    await collector(sm, mock_http(feed_handler()), tmp_path, Clock()).run("feodo")
    return sm


def service(sm: SM, http: SafeHttp, **settings: Any) -> EnrichmentService:
    return EnrichmentService(sm, http, MemoryQuotaStore(), Settings(**settings))


def by_name(res: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["enricher"]: r for r in res["enrichments"]}


IP = Observable(IOCType.IPV4, FEODO_IP)

# ── readers against recorded answers ─────────────────────────────────────────


async def test_rdap_domain_and_network(http: SafeHttp) -> None:
    d = await Rdap().query(http, IOCType.DOMAIN, "api.github.com")  # looked up by registrable domain
    assert d.status == "ok"
    assert d.query == "https://rdap.verisign.com/com/v1/domain/github.com"
    assert d.summary["registrar"] == "MarkMonitor Inc."
    assert d.summary["created"].startswith("2007-10-09")
    assert "dns1.p08.nsone.net" in d.summary["nameservers"]
    assert d.summary["age_days"] > 6000
    assert all(e.kind == "info" for e in d.evidence)  # an old domain is not suspicious
    n = await Rdap().query(http, IOCType.IPV4, FEODO_IP)
    assert n.query == f"https://rdap.arin.net/registry/ip/{FEODO_IP}"
    assert n.summary["name"] == "DIGITALOCEAN-162-243-0-0"
    assert n.summary["cidrs"] == ["162.243.0.0/16"]
    assert n.summary["organization"] == "DigitalOcean, LLC"
    miss = await Rdap().query(http, IOCType.DOMAIN, "nonexistent-threatlens-x9.com")
    assert (miss.status, miss.http_status) == ("not_found", 404)
    none = await Rdap().query(http, IOCType.DOMAIN, "example.zz")
    assert none.status == "not_found"
    assert none.calls == 0  # no registry serves that TLD: nothing asked


async def test_ripestat_asn_and_location(http: SafeHttp) -> None:
    o = await RipeStat().query(http, IOCType.IPV4, FEODO_IP)
    assert o.summary == {
        "asn": 14061,
        "as_holder": "DIGITALOCEAN-ASN - DigitalOcean, LLC",
        "prefix": "162.243.0.0/17",
        "announced": True,
        "country": "US",
        "city": "Secaucus",
        "latitude": 40.7908,
        "longitude": -74.056,
    }
    assert o.calls == 2


async def test_greynoise_scanner_and_miss(http: SafeHttp) -> None:
    o = await GreyNoise().query(http, IOCType.IPV4, "71.6.199.23")
    assert o.summary["name"] == "Shodan.io"
    assert [(e.kind, e.weight) for e in o.evidence] == [("benign", 50)]
    assert o.rate is not None
    assert o.rate.remaining == 20
    miss = await GreyNoise().query(http, IOCType.IPV4, "8.8.8.8")
    assert (miss.status, miss.http_status) == ("not_found", 404)


async def test_dns_records_and_nxdomain(http: SafeHttp) -> None:
    o = await Dns().query(http, IOCType.DOMAIN, "github.com")
    assert o.summary["a"] == ["20.207.73.82"]
    assert o.summary["mx"]
    assert o.summary["ns"]
    assert o.summary["txt"]
    assert o.calls == 5
    nx = await Dns().query(http, IOCType.DOMAIN, "nonexistent-threatlens-x9.com")
    assert nx.status == "not_found"


async def test_urlscan_search_and_miss(http: SafeHttp) -> None:
    o = await UrlScan().query(http, IOCType.DOMAIN, "github.com")
    assert o.summary["total"] == 10000
    assert o.summary["more"] is True
    assert o.summary["latest"]["link"].startswith("https://urlscan.io/result/")
    miss = await UrlScan().query(http, IOCType.DOMAIN, "nonexistent-threatlens-x9.com")
    assert miss.status == "not_found"


def test_urlscan_query_escapes_values() -> None:
    assert UrlScan.search_for(IOCType.IPV4, "1.2.3.4") == 'page.ip:"1.2.3.4"'
    q = UrlScan.search_for(IOCType.URL, 'https://x.example/a"b\\c')
    assert '\\"b\\\\c' in q  # a quote in the value can't end the phrase early


def test_virustotal_url_identifier() -> None:
    # Example from the VirusTotal "URL identifiers" documentation.
    assert (
        vt_url_id("http://www.somedomain.com/this/is/my/url")
        == "aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA"
    )


def test_enricher_catalogue_is_complete_and_consistent() -> None:
    assert set(REGISTRY) == {
        "rdap", "dns", "ripestat", "abuseipdb", "greynoise",
        "virustotal", "urlscan", "malwarebazaar", "crtsh",
    }  # fmt: skip
    for name, cls in REGISTRY.items():
        i = cls.info
        assert i.name == name
        assert i.applies_to, name
        assert i.verified.startswith("2026-"), name
        assert not (i.auto and (i.metered or i.mode == "active")), f"{name}: auto must be free and passive"
        assert not (i.metered and not i.quotas), f"{name}: metered without a quota"
        assert i.license_url.startswith("https://"), name
    assert [n for n, c in REGISTRY.items() if c.info.mode == "active"] == ["dns"]
    assert [n for n, c in REGISTRY.items() if c.info.discloses] == ["virustotal"]


# ── policy and storage ───────────────────────────────────────────────────────


async def test_lookup_known_c2_without_keys(seeded: SM, http: SafeHttp) -> None:
    # Feodo still lists this C2 but reports it offline since 2026-03-07: seven
    # months of decay (IP half-life 10 days) leave nothing to block on.
    res = await service(seeded, http).lookup(IP, actor="alice", clearance=RED)
    assert res["known"]["sources"] == ["feodo"]
    assert res["known"]["status"] == "expired"
    assert res["verdict"] == "unknown"
    assert res["score_model"] == "v1"
    assert any("offline since 2026-03-07" in ev["text"] for ev in res["evidence"])
    e = by_name(res)
    assert set(e) == {"rdap", "ripestat", "abuseipdb", "greynoise", "virustotal", "urlscan"}
    assert e["rdap"]["status"] == e["ripestat"]["status"] == "ok"
    assert (e["greynoise"]["status"], e["greynoise"]["found"]) == ("ok", False)
    assert e["abuseipdb"]["skipped_reason"] == e["virustotal"]["skipped_reason"] == "no_api_key"
    assert e["virustotal"]["detail"] == "set TL_VIRUSTOTAL_API_KEY"
    assert res["partial"] is True
    assert any(ev["source"] == "ripestat" and "AS14061" in ev["text"] for ev in res["evidence"])


async def test_lookup_fresh_c2_is_blocked_with_its_breakdown(seeded: SM, http: SafeHttp) -> None:
    res = await service(seeded, http).lookup(
        Observable(IOCType.IPV4, "50.16.16.211"), actor="a", only=["ripestat"], clearance=RED
    )
    assert (res["verdict"], res["recommended_action"]) == ("malicious", "block")
    bd = res["score_breakdown"]
    assert bd["base"]["source"] == "feodo"
    assert bd["config"].startswith("1.0/")
    assert res["score"] == round(res["priority"]) == round(bd["priority"])
    assert bd["formula"].endswith(f"= {bd['priority']:g}")


async def test_answers_are_stored_with_provenance(seeded: SM, http: SafeHttp) -> None:
    await service(seeded, http).lookup(IP, actor="alice", clearance=RED)
    async with seeded() as s:
        rows = {r.enricher: r for r in (await s.scalars(select(Enrichment))).all()}
        obs_id = await s.scalar(select(ObsRow.id).where(ObsRow.canonical_key == IP.key))
        src = {r.name: r for r in (await s.scalars(select(Source).where(Source.kind == "enricher"))).all()}
    assert set(rows) == {"rdap", "ripestat", "greynoise", "urlscan"}  # skips are not stored
    r = rows["rdap"]
    assert r.canonical_key == IP.key
    assert r.observable_id == obs_id
    assert r.query == f"https://rdap.arin.net/registry/ip/{FEODO_IP}"
    assert (r.requested_by, r.http_status, r.mode, r.source_id) == ("alice", 200, "passive", src["rdap"].id)
    assert r.raw["handle"] == "NET-162-243-0-0-1"  # the upstream answer is kept for reprocessing
    assert r.expires_at > r.fetched_at
    assert src["virustotal"].commercial_use is False
    assert src["virustotal"].redistribution is False


async def test_cache_hit_makes_no_calls_and_is_fast(seeded: SM, http: SafeHttp, upstream: Upstream) -> None:
    svc = service(seeded, http)
    await svc.lookup(IP, actor="alice", clearance=RED)
    upstream.calls.clear()
    res = await svc.lookup(IP, actor="bob", clearance=RED)
    assert upstream.calls == []
    assert {
        r["status"] for r in res["enrichments"] if r["enricher"] in ("rdap", "ripestat", "greynoise")
    } == {"cached"}
    assert res["took_ms"] < 2000  # Phase 3 acceptance: < 2 s on a cache hit
    upstream.calls.clear()
    again = await svc.lookup(IP, actor="bob", clearance=RED, refresh=True)
    assert "rdap.arin.net" in upstream.calls
    assert by_name(again)["rdap"]["status"] == "ok"


async def test_expired_answer_is_refetched(seeded: SM, http: SafeHttp, upstream: Upstream) -> None:
    clock = [Clock()()]
    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), Settings(), now=lambda: clock[0])
    await svc.lookup(IP, actor="a", clearance=RED, only=["ripestat"])
    clock[0] += timedelta(days=2)  # ripestat answers stay fresh for a day
    upstream.calls.clear()
    res = await svc.lookup(IP, actor="a", clearance=RED, only=["ripestat"])
    assert by_name(res)["ripestat"]["status"] == "ok"
    assert upstream.calls.count("stat.ripe.net") == 2


async def test_keys_enable_reputation(seeded: SM, http: SafeHttp) -> None:
    res = await service(seeded, http, **KEYS).lookup(IP, actor="alice", clearance=RED)
    e = by_name(res)
    assert e["abuseipdb"]["summary"]["abuse_confidence"] == 88
    assert e["virustotal"]["summary"]["malicious"] == 9
    kinds = {(ev["source"], ev["kind"]) for ev in res["evidence"]}
    assert {("abuseipdb", "malicious"), ("virustotal", "malicious"), ("threatlens", "malicious")} <= kinds
    bd = res["score_breakdown"]
    # VirusTotal (B, 0.85) x 95 = 80.75 is the base; AbuseIPDB (C, 0.70) x 88 = 61.6 is an
    # independent second upstream (+8); the Feodo listing has decayed to nothing.
    assert bd["base"]["source"] == "virustotal"
    assert bd["corroboration"] == {"value": 8.0, "upstreams": ["abuseipdb"]}
    assert (res["verdict"], res["priority"]) == ("malicious", 88.75)
    assert res["partial"] is False
    h = await service(seeded, http, **KEYS).lookup(
        Observable(IOCType.SHA256, EICAR), actor="a", clearance=RED
    )
    assert by_name(h)["malwarebazaar"]["summary"]["signature"] == "SYNTHETIC-TestFamily"
    assert h["verdict"] == "malicious"


@pytest.mark.parametrize(
    ("tlp", "blocked"),
    [
        ("TLP:CLEAR", set()),
        ("TLP:GREEN", {"virustotal"}),
        ("TLP:AMBER", {"rdap", "ripestat", "abuseipdb", "greynoise", "virustotal", "urlscan"}),
        ("TLP:RED", {"rdap", "ripestat", "abuseipdb", "greynoise", "virustotal", "urlscan"}),
    ],
)
async def test_tlp_keeps_values_on_the_platform(
    sm: SM, http: SafeHttp, upstream: Upstream, tlp: str, blocked: set[str]
) -> None:
    res = await service(sm, http, **KEYS).lookup(
        Observable(IOCType.IPV4, "71.6.199.23"), actor="a", clearance=RED, tlp=tlp
    )
    assert {n for n, r in by_name(res).items() if r.get("skipped_reason") == "tlp"} == blocked
    if blocked >= {"rdap"}:
        assert upstream.calls == []  # nothing left the platform


async def test_stored_tlp_wins_over_a_laxer_request(seeded: SM, http: SafeHttp, upstream: Upstream) -> None:
    async with seeded() as s, s.begin():
        ind = await s.scalar(
            select(Indicator)
            .join(ObsRow, Indicator.observable_id == ObsRow.id)
            .where(ObsRow.value == FEODO_IP)
        )
        assert ind is not None
        ind.tlp = "TLP:AMBER"
    res = await service(seeded, http).lookup(IP, actor="a", clearance=RED, tlp="TLP:CLEAR")
    assert res["tlp"] == "TLP:AMBER"
    assert upstream.calls == []


def test_tlp_rules() -> None:
    assert stricter_tlp("TLP:GREEN", None, "TLP:AMBER") == "TLP:AMBER"
    assert stricter_tlp(None) == "TLP:CLEAR"
    assert stricter_tlp(None, "bogus") == "TLP:RED"  # unknown markings fail closed
    assert tlp_blocks(False, True, "TLP:RED") is None  # nothing leaves the platform anyway
    assert tlp_blocks(True, False, "TLP:GREEN") is None
    assert tlp_blocks(True, True, "TLP:GREEN")
    assert tlp_blocks(True, False, "TLP:AMBER+STRICT")


async def test_active_enrichment_is_opt_in_and_audited(sm: SM, http: SafeHttp, upstream: Upstream) -> None:
    svc = service(sm, http)
    dom = Observable(IOCType.DOMAIN, "github.com")
    res = await svc.lookup(dom, actor="alice", clearance=RED, only=["dns", "rdap"])
    assert by_name(res)["dns"]["skipped_reason"] == "active_not_requested"
    assert "cloudflare-dns.com" not in upstream.calls
    assert res["partial"] is False  # not asking for active mode is not a gap
    res = await svc.lookup(dom, actor="alice", clearance=RED, active=True)
    assert by_name(res)["dns"]["summary"]["a"] == ["20.207.73.82"]
    async with sm() as s:
        audit = (await s.scalars(select(AuditLog).where(AuditLog.action == "enrich.active"))).all()
    assert [(a.actor, a.target) for a in audit] == [("alice", "dns:domain-name|github.com")]


async def test_quota_exhaustion_degrades_to_partial_results(
    sm: SM, http: SafeHttp, upstream: Upstream
) -> None:
    quota = MemoryQuotaStore()
    svc = EnrichmentService(sm, http, quota, Settings(**KEYS))
    for _ in range(4):
        assert await quota.take("virustotal", REGISTRY["virustotal"].info.quotas_for(True)) == 0
    res = await svc.lookup(IP, actor="a", clearance=RED)
    vt = by_name(res)["virustotal"]
    assert vt["skipped_reason"] == "quota_exhausted"
    assert 0 < vt["resets_in_s"] <= 61  # 4 per minute
    assert by_name(res)["abuseipdb"]["status"] == "ok"  # the rest still answer
    assert res["partial"] is True
    assert res["verdict"] in ("malicious", "suspicious", "unknown")


async def test_provider_429_blocks_until_reset(sm: SM, http: SafeHttp, upstream: Upstream) -> None:
    svc = service(sm, http, **KEYS)
    upstream.fail["api.abuseipdb.com"] = 429
    first = by_name(await svc.lookup(IP, actor="a", clearance=RED, only=["abuseipdb"]))["abuseipdb"]
    assert (first["skipped_reason"], first["resets_in_s"]) == ("quota_exhausted", 120)
    del upstream.fail["api.abuseipdb.com"]
    upstream.calls.clear()
    second = by_name(await svc.lookup(IP, actor="a", clearance=RED, only=["abuseipdb"]))["abuseipdb"]
    assert second["skipped_reason"] == "quota_exhausted"  # still blocked: the provider asked for 120 s
    assert upstream.calls == []


async def test_rate_headers_at_zero_block_the_provider(sm: SM, http: SafeHttp, upstream: Upstream) -> None:
    svc = service(sm, http)
    upstream.greynoise_headers = {"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": "4102444800"}
    await svc.lookup(Observable(IOCType.IPV4, "71.6.199.23"), actor="a", clearance=RED, only=["greynoise"])
    res = await svc.lookup(
        Observable(IOCType.IPV4, "71.6.199.24"), actor="a", clearance=RED, only=["greynoise"]
    )
    assert by_name(res)["greynoise"]["skipped_reason"] == "quota_exhausted"


async def test_bulk_budget_limits_metered_calls(sm: SM, http: SafeHttp) -> None:
    svc = service(sm, http, **KEYS)
    ips = [Observable(IOCType.IPV4, FEODO_IP), Observable(IOCType.IPV4, "71.6.199.23")]
    results, spent = await svc.lookup_many(ips, actor="a", clearance=RED, budget=3, concurrency=1)
    assert spent == 3
    skipped = [
        r for res in results for r in res["enrichments"] if r.get("skipped_reason") == "budget_exhausted"
    ]
    assert skipped
    assert all(REGISTRY[r["enricher"]].info.metered for r in skipped)
    unmetered = [r for res in results for r in res["enrichments"] if not REGISTRY[r["enricher"]].info.metered]
    assert all(r["status"] == "ok" for r in unmetered)  # free enrichers don't use the budget


async def test_timeout_and_errors_keep_the_previous_answer(
    sm: SM, http: SafeHttp, upstream: Upstream
) -> None:
    svc = EnrichmentService(sm, http, MemoryQuotaStore(), Settings(enrich_timeout_s=0.2))
    await svc.lookup(IP, actor="a", clearance=RED, only=["ripestat"])
    upstream.hang.add("stat.ripe.net")
    r = by_name(await svc.lookup(IP, actor="a", clearance=RED, only=["ripestat"], refresh=True))["ripestat"]
    assert (r["status"], r["error"]) == ("stale", "timed out after 0.2 s")
    assert r["summary"]["asn"] == 14061  # the older answer, clearly marked stale
    upstream.hang.clear()
    upstream.fail["rdap.arin.net"] = 500
    r = by_name(await svc.lookup(IP, actor="a", clearance=RED, only=["rdap"]))["rdap"]
    assert r["status"] == "error"
    assert "HTTP 500" in r["error"]


async def test_unreadable_answer_is_an_error_not_a_crash(sm: SM, mock_http: MakeHttp) -> None:
    http = mock_http(lambda req: httpx.Response(200, content=b"<html>maintenance</html>"))
    res = await service(sm, http).lookup(IP, actor="a", clearance=RED, only=["ripestat", "rdap"])
    assert {r["status"] for r in res["enrichments"]} == {"error"}
    assert res["verdict"] == "unknown"


async def test_allowlisted_values_are_benign(sm: SM, http: SafeHttp) -> None:
    async with sm() as s, s.begin():
        s.add(
            AllowlistEntry(
                kind="domain",
                value="github.com",
                effect="suppress",
                reason="our code host",
                origin="manual",
                created_by="t",
            )
        )
    res = await service(sm, http).lookup(Observable(IOCType.DOMAIN, "github.com"), actor="a", clearance=RED)
    assert res["verdict"] == "benign"
    assert res["allowlist"]["effect"] == "suppress"
    assert res["recommended_action"] == "no_action"


async def test_disabled_enricher_is_skipped(sm: SM, http: SafeHttp) -> None:
    svc = service(sm, http)
    await svc.sync_sources()
    async with sm() as s, s.begin():
        row = await s.scalar(select(Source).where(Source.name == "urlscan"))
        assert row is not None
        row.enabled = False
    svc = service(sm, http)
    res = await svc.lookup(IP, actor="a", clearance=RED, only=["urlscan"])
    assert by_name(res)["urlscan"]["skipped_reason"] == "disabled"


async def test_enrichers_are_not_scheduled_as_feeds(
    sm: SM, http: SafeHttp, mock_http: MakeHttp, tmp_path: Path
) -> None:
    await service(sm, http).sync_sources()
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    await c.sync_sources()
    due = await c.due()
    assert due
    assert not set(due) & set(REGISTRY)


async def test_backlog_enriches_new_ip_indicators(seeded: SM, http: SafeHttp, upstream: Upstream) -> None:
    svc = service(seeded, http, **KEYS)
    first = await svc.enrich_backlog(50)
    assert first["candidates"] == 1  # the other two Feodo C2s are offline for months: expired
    assert first["enriched"] == 1
    assert set(upstream.calls) <= {"stat.ripe.net"}
    assert (await svc.enrich_backlog(50))["candidates"] == 0
    assert await svc.enrich_backlog(0) == {"candidates": 0, "enriched": 0}


# ── quota store ──────────────────────────────────────────────────────────────


async def test_memory_quota_windows_and_blocks() -> None:
    now = [1_000_000.0]
    q = MemoryQuotaStore(clock=lambda: now[0])
    quotas = (Quota(2, 60), Quota(3, 86400))
    assert [await q.take("x", quotas) for _ in range(2)] == [0.0, 0.0]
    assert 0 < await q.take("x", quotas) <= 60  # minute window full; refusal costs nothing
    assert await q.usage("x", quotas) == {"2/minute": 2, "3/day": 2}
    now[0] += 60
    assert await q.take("x", quotas) == 0.0
    now[0] += 60
    assert await q.take("x", quotas) > 60  # day window full now
    await q.block("y", 30)
    assert 0 < await q.take("y", ()) <= 30
    now[0] += 31
    assert await q.take("y", ()) == 0.0


# ── API ──────────────────────────────────────────────────────────────────────


class Api:
    def __init__(self, client: httpx.AsyncClient, keys: dict[str, str]) -> None:
        self.client = client
        self.keys = keys

    def h(self, role: str) -> dict[str, str]:
        return {"X-API-Key": self.keys[role]}


@pytest.fixture
async def api(seeded: SM, http: SafeHttp) -> AsyncIterator[Api]:
    keys = {}
    async with seeded() as s, s.begin():
        for role in ("viewer", "analyst"):
            _, keys[role] = await create_key(s, role, role)
    settings = Settings(enrich_active_per_min=2, rate_limit_analyst=1000, **KEYS)  # type: ignore[arg-type]
    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), settings)
    app = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter(), enrich=svc)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        yield Api(c, keys)


async def test_lookup_route(api: Api) -> None:
    r = await api.client.get(f"/api/v1/lookup/ipv4-addr/{FEODO_IP}", headers=api.h("analyst"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "malicious"
    assert body["query"]["defanged"] == "162[.]243[.]103[.]246"
    assert body["known"]["sources"] == ["feodo"]
    assert {e["enricher"] for e in body["enrichments"]} >= {"rdap", "virustotal"}
    # Defanged input and slashes are fine in the path; a "?" must be sent as %3F.
    url = "/api/v1/lookup/url/hxxps[://]evil[.]example[.]com/a/b%3Fx=1"
    r = await api.client.get(url, headers=api.h("analyst"), params={"enrichers": "urlscan"})
    assert r.status_code == 200, r.text
    assert r.json()["query"]["value"] == "https://evil.example.com/a/b?x=1"


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/api/v1/lookup/ipv4-addr/10.0.0.1", 422),  # private: never sent anywhere
        ("/api/v1/lookup/ipv4-addr/not-an-ip", 422),
        ("/api/v1/lookup/vulnerability/CVE-2024-3400", 422),
        ("/api/v1/lookup/bogus-type/x", 422),
        ("/api/v1/lookup/domain-name/github.com?enrichers=rdap,nope", 422),
    ],
)
async def test_lookup_rejects_bad_input(api: Api, path: str, status: int) -> None:
    assert (await api.client.get(path, headers=api.h("analyst"))).status_code == status


async def test_lookup_needs_analyst(api: Api) -> None:
    assert (await api.client.get(f"/api/v1/lookup/ipv4-addr/{FEODO_IP}")).status_code == 401
    r = await api.client.get(f"/api/v1/lookup/ipv4-addr/{FEODO_IP}", headers=api.h("viewer"))
    assert r.status_code == 403
    r = await api.client.post("/api/v1/enrich", json={"indicators": [FEODO_IP]}, headers=api.h("viewer"))
    assert r.status_code == 403
    assert (await api.client.get("/api/v1/enrichers", headers=api.h("viewer"))).status_code == 200


async def test_bulk_enrich_from_an_alert(api: Api) -> None:
    alert = f"Beacon from host-17 to {FEODO_IP.replace('.', '[.]')}:443, then 71.6.199.23 scanned us."
    body = {
        "indicators": ["github.com", {"type": "file-sha256", "value": EICAR}, "192.168.1.5", FEODO_IP],
        "text": alert,
        "tlp": "TLP:CLEAR",
    }
    r = await api.client.post("/api/v1/enrich", json=body, headers=api.h("analyst"))
    assert r.status_code == 200, r.text
    out = r.json()
    values = [x["query"]["value"] for x in out["results"]]
    assert len(values) == len(set(values)) == 4  # the IP in the text and the list is enriched once
    assert out["results"][0]["verdict"] == "malicious"  # worst first
    assert out["rejected"] == [{"value": "192.168.1.5", "reason": out["rejected"][0]["reason"]}]
    assert sum(out["counts"].values()) == 4
    assert out["budget_spent"] > 0


async def test_bulk_limits(api: Api) -> None:
    many = [f"1.1.{i}.1" for i in range(101)]  # one more than TL_ENRICH_BULK_MAX
    r = await api.client.post("/api/v1/enrich", json={"indicators": many}, headers=api.h("analyst"))
    assert r.status_code == 422


async def test_active_lookups_are_rate_limited(api: Api) -> None:
    url = "/api/v1/lookup/domain-name/github.com?active=true&enrichers=dns"
    codes = [(await api.client.get(url, headers=api.h("analyst"))).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


async def test_enrichers_catalogue_route(api: Api) -> None:
    rows = {r["name"]: r for r in (await api.client.get("/api/v1/enrichers", headers=api.h("viewer"))).json()}
    assert set(rows) == set(REGISTRY)
    assert rows["virustotal"]["key_configured"] is True
    assert rows["virustotal"]["discloses"] is True
    assert rows["greynoise"]["key_configured"] is False
    assert rows["greynoise"]["quotas"] == ["25/week"]
    assert rows["dns"]["mode"] == "active"
    sources = (await api.client.get("/api/v1/sources", headers=api.h("viewer"))).json()
    vt = next(s for s in sources if s["name"] == "virustotal")
    assert (vt["kind"], vt["key_configured"], vt["commercial_use"]) == ("enricher", True, False)


async def test_lookup_output_never_contains_api_keys(api: Api) -> None:
    r = await api.client.post(
        "/api/v1/enrich", json={"indicators": [FEODO_IP, EICAR]}, headers=api.h("analyst")
    )
    text = json.dumps(r.json())
    assert all(k not in text for k in KEYS.values() if len(k) > 1)


# ── a fake enricher, to test the service contract in isolation ───────────────


class Slow(Enricher):
    info = EnricherInfo(
        name="slow", title="Slow", homepage="https://x.example", applies_to=frozenset({IOCType.DOMAIN}),
        mode="passive", third_party=False, discloses=False, reliability="F", reliability_note="",
        license="", license_url="https://x.example", commercial_use=True, redistribution=True,
        upstream="x", ttl=timedelta(hours=1), negative_ttl=timedelta(hours=1), verified="2026-10-10",
        concurrency=1,
    )  # fmt: skip
    running = 0
    peak = 0

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        Slow.running += 1
        Slow.peak = max(Slow.peak, Slow.running)
        await asyncio.sleep(0.01)
        Slow.running -= 1
        return Outcome("ok", {"v": value})


async def test_per_enricher_concurrency_limit(sm: SM, http: SafeHttp) -> None:
    svc = EnrichmentService(sm, http, MemoryQuotaStore(), Settings(), registry={"slow": Slow})
    obs = [Observable(IOCType.DOMAIN, f"d{i}.example.com") for i in range(6)]
    results, _ = await svc.lookup_many(obs, actor="a", clearance=RED, concurrency=6)
    assert all(r["enrichments"][0]["status"] == "ok" for r in results)
    assert Slow.peak == 1
