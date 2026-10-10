"""Own assets from ReconX (Phase 3b): import, observed tech stack, the
asset/indicator join, lookups of own assets, API, UI and CLI."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.conftest import FIXTURES
from tests.test_collect import Clock, collector, feed_handler
from tests.test_enrich import Upstream
from threatlens.api.app import create_app
from threatlens.assets import (
    ImportFormatError,
    import_reconx,
    observed_stack,
    org_stack,
    parse_cpe,
    read_reconx,
)
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.ioc.types import IOCType, Observable
from threatlens.kb.base import KbContext
from threatlens.kb.nvd import Nvd
from threatlens.models import Asset, AssetProduct, AuditLog, Vulnerability, VulnerabilityProduct
from threatlens.net.http import SafeHttp
from threatlens.rawstore import RawStore
from threatlens.settings import Settings

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
SCAN = FIXTURES / "reconx_scan.json"


def scan(**changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(SCAN.read_text(encoding="utf-8"))
    doc.update(changes)
    return doc


async def do_import(sm: SM, doc: dict[str, Any], actor: str = "alice") -> Any:
    body = json.dumps(doc).encode()
    return await import_reconx(sm, doc, hashlib.sha256(body).hexdigest(), actor)


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        (
            "cpe:/a:apache:http_server:2.4.49",
            ("a", "apache", "http_server", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49"),
        ),
        ("cpe:/o:linux:linux_kernel", ("o", "linux", "linux_kernel", None, "cpe:2.3:o:linux:linux_kernel:*")),
        (
            "CPE:2.3:a:NGINX:nginx:1.18.0:*:*:*:*:*:*:*",
            ("a", "nginx", "nginx", "1.18.0", "cpe:2.3:a:nginx:nginx:1.18.0"),
        ),
        (
            "cpe:/a:microsoft:internet_information_services:10.0",
            (
                "a",
                "microsoft",
                "internet_information_services",
                "10.0",
                "cpe:2.3:a:microsoft:internet_information_services:10.0",
            ),
        ),
        ("cpe:/a:*:nginx", None),
        ("cpe:/x:vendor:product", None),
        ("cpe:/a:vendor", None),
        ("not-a-cpe", None),
        ("cpe:/a:ven dor:product", None),
    ],
)
def test_parse_cpe(raw: str, want: tuple[str, ...] | None) -> None:
    assert parse_cpe(raw) == want


def test_read_reconx_picks_live_public_assets() -> None:
    target, ttype, when, found, rejected = read_reconx(scan())
    assert (target, ttype, when) == ("example.com", "domain", datetime(2026, 10, 10, 12, tzinfo=UTC))
    kinds = {f.obs.key: f.kind for f in found}
    assert kinds == {
        "domain-name|example.com": "domain",  # the apex, merged with its host entry
        "domain-name|www.example.com": "host",
        "domain-name|c2-lookalike.example.com": "host",
        "domain-name|intranet.example.com": "host",  # a public name, even if its address is private
        "ipv4-addr|93.184.216.34": "ip",
        "ipv4-addr|162.243.103.246": "ip",
    }
    assert "domain-name|old.example.com" not in kinds  # no longer resolves
    assert [(r["value"], r["reason"][:20]) for r in rejected] == [
        ("10.0.0.5", "non-public (bogon/pr"),  # the private IP itself is never an asset
        ("199.43.135.53", "not an address of a "),  # a name server, not ours
        ("192.0.32.10", "shared CDN edge (Exa"),  # serves thousands of sites
    ]
    apex = next(f for f in found if f.kind == "domain")
    assert apex.details["role"] == "scan target"
    assert apex.details["asn"] == "AS15133"  # host details merged into the apex entry
    edge = next(f for f in found if f.obs.value == "93.184.216.34")
    assert [p[4] for p in edge.products] == [
        "cpe:2.3:a:apache:http_server:2.4.49",
        "cpe:2.3:a:nginx:nginx:1.18.0",
        "cpe:2.3:o:linux:linux_kernel:*",
    ]
    assert edge.details["ports"] == [80, 443]


@pytest.mark.parametrize(
    ("doc", "msg"),
    [
        ([], "no 'target'"),
        ({"target": {"value": "Acme", "type": "org"}}, "domain or an IP"),
        ({"target": {"value": "example.com", "type": "domain"}, "passive_intel": []}, "must be an object"),
        (
            {"target": {"value": "example.com", "type": "domain"}, "passive_intel": {"hosts": {}}},
            "must be lists",
        ),
    ],
)
def test_read_reconx_rejects_other_documents(doc: Any, msg: str) -> None:
    with pytest.raises(ImportFormatError, match=msg):
        read_reconx(doc)


async def test_import_is_idempotent_and_newest_wins(sm: SM) -> None:
    first = await do_import(sm, scan())
    assert (first.new_assets, first.updated_assets, first.hosts, first.ips, first.products) == (6, 0, 4, 2, 4)
    assert not first.duplicate
    again = await do_import(sm, scan())
    assert again.duplicate
    assert again.import_id == first.import_id
    newer = scan(timestamp="2026-10-12T00:00:00Z")
    newer["passive_intel"]["hosts"][1]["role"] = "Likely API"
    later = await do_import(sm, newer)
    assert (later.new_assets, later.updated_assets) == (0, 6)
    older = scan(timestamp="2026-09-01T00:00:00Z")
    older["passive_intel"]["hosts"][1]["role"] = "stale"
    await do_import(sm, older)
    async with sm() as s:
        www = await s.scalar(select(Asset).where(Asset.value == "www.example.com"))
        products = (await s.scalars(select(AssetProduct))).all()
        audits = (await s.scalars(select(AuditLog).where(AuditLog.action == "assets.import"))).all()
    assert www is not None
    assert www.details["role"] == "Likely API"  # the older scan did not overwrite it
    assert www.first_seen.replace(tzinfo=UTC) == datetime(2026, 10, 10, 12, tzinfo=UTC)
    assert len(products) == 4  # nginx on both IPs counts per asset
    assert len(audits) == 3  # the duplicate import was not recorded


async def test_observed_stack_extends_the_profile(sm: SM) -> None:
    await do_import(sm, scan())
    async with sm() as s:
        observed = await observed_stack(s)
        stack = await org_stack(s, Settings())
    assert observed == [
        ("cpe:2.3:a:apache:http_server", "apache", "http_server"),
        ("cpe:2.3:a:nginx:nginx", "nginx", "nginx"),
        ("cpe:2.3:o:linux:linux_kernel", "linux", "linux_kernel"),
    ]
    pairs = {(v, p) for _, v, p in stack}
    assert {("apache", "http_server"), ("fortinet", "fortios")} <= pairs  # observed + config/org_profile.yaml


async def no_sleep(_: float) -> None:
    return None


async def test_nvd_mirrors_observed_applications_only(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    await do_import(sm, scan())
    ctx = KbContext(
        sm=sm, http=mock_http(lambda r: httpx.Response(404)), store=RawStore(tmp_path), settings=Settings(),
        now=datetime.now(UTC), source_id=1, source_name="nvd", checkpoint={}, sleep=no_sleep,
    )  # fmt: skip
    prefixes = {p for p, _, _ in await Nvd._stack(ctx)}
    assert "cpe:2.3:a:apache:http_server" in prefixes
    assert "cpe:2.3:o:linux:linux_kernel" not in prefixes  # a kernel CPE alone pulls thousands of CVEs


# ── lookups, API, UI ─────────────────────────────────────────────────────────


class Api:
    def __init__(self, client: httpx.AsyncClient, keys: dict[str, str], sm: SM) -> None:
        self.client = client
        self.keys = keys
        self.sm = sm

    def h(self, role: str) -> dict[str, str]:
        return {"X-API-Key": self.keys[role]}


@pytest.fixture
async def api(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> AsyncIterator[Api]:
    await collector(sm, mock_http(feed_handler()), tmp_path, Clock()).run("feodo")
    keys = {}
    async with sm() as s, s.begin():
        for role in ("viewer", "analyst"):
            _, keys[role] = await create_key(s, role, role)
        vuln = Vulnerability(cve_id="CVE-2021-41773", stix_id="vulnerability--test-41773", kev=True)
        s.add(vuln)
        await s.flush()
        s.add(
            VulnerabilityProduct(vulnerability_id=vuln.id, part="a", vendor="apache", product="http_server")
        )
    settings = Settings(rate_limit_analyst=1000, rate_limit_viewer=1000)
    svc = EnrichmentService(sm, mock_http(Upstream()), MemoryQuotaStore(), settings)  # type: ignore[arg-type]
    app = create_app(settings, checks={}, sessionmaker=sm, limiter=MemoryRateLimiter(), enrich=svc)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        yield Api(c, keys, sm)


async def test_import_route(api: Api) -> None:
    body = SCAN.read_bytes()
    r = await api.client.post("/api/v1/assets/import/reconx", content=body, headers=api.h("viewer"))
    assert r.status_code == 403  # importing changes what counts as "ours": analyst
    r = await api.client.post("/api/v1/assets/import/reconx", content=body, headers=api.h("analyst"))
    assert r.status_code == 200, r.text
    assert (r.json()["new_assets"], r.json()["duplicate"]) == (6, False)
    again = await api.client.post("/api/v1/assets/import/reconx", content=body, headers=api.h("analyst"))
    assert again.json()["duplicate"] is True
    bad = await api.client.post("/api/v1/assets/import/reconx", content=b"{nope", headers=api.h("analyst"))
    assert bad.status_code == 422
    org = await api.client.post(
        "/api/v1/assets/import/reconx",
        json={"target": {"value": "Acme", "type": "org"}},
        headers=api.h("analyst"),
    )
    assert org.status_code == 422


async def test_assets_listed_by_feeds_come_first(api: Api) -> None:
    await do_import(api.sm, scan())
    page = (await api.client.get("/api/v1/assets", headers=api.h("viewer"))).json()
    assert page["total"] == 6
    first = page["items"][0]
    assert first["value"] == "162.243.103.246"  # an own IP that Feodo Tracker lists
    assert first["indicator"]["sources"] == ["feodo"]
    assert first["products"] == ["cpe:2.3:a:nginx:nginx:1.18.0"]
    flagged = (await api.client.get("/api/v1/assets?flagged=true", headers=api.h("viewer"))).json()
    assert [a["value"] for a in flagged["items"]] == ["162.243.103.246"]
    hosts = (await api.client.get("/api/v1/assets?kind=host&q=www", headers=api.h("viewer"))).json()
    assert [a["value"] for a in hosts["items"]] == ["www.example.com"]
    prods = {
        p["product"]: p
        for p in (await api.client.get("/api/v1/assets/products", headers=api.h("viewer"))).json()
    }
    apache = prods["http_server"]
    assert (apache["cves"], apache["kev_cves"], apache["versions"]) == (1, 1, ["2.4.49"])
    assert prods["nginx"]["assets"] == 2
    imports = (await api.client.get("/api/v1/assets/imports", headers=api.h("viewer"))).json()
    assert imports[0]["target"] == "example.com"
    assert imports[0]["counts"]["rejected"] == 3


async def test_lookup_of_an_own_asset_says_investigate(api: Api) -> None:
    await do_import(api.sm, scan())
    r = await api.client.get(
        "/api/v1/lookup/ipv4-addr/162.243.103.246?enrichers=ripestat", headers=api.h("analyst")
    )
    body = r.json()
    assert body["verdict"] == "malicious"
    assert body["recommended_action"] == "investigate"  # never "block" your own host
    assert body["asset"]["target"] == "example.com"
    assert any(e["source"] == "assets" and "Own asset" in e["text"] for e in body["evidence"])
    other = await api.client.get(
        "/api/v1/lookup/ipv4-addr/50.16.16.211?enrichers=ripestat", headers=api.h("analyst")
    )
    assert other.json()["recommended_action"] == "block"  # not ours: unchanged
    assert other.json()["asset"] is None


async def test_assets_page(api: Api) -> None:
    async with api.sm() as s, s.begin():
        _, key = await create_key(s, "ui", "analyst")
    r = await api.client.post(
        "/ui/login", data={"key": key, "next": "/ui/assets"}, headers={"Sec-Fetch-Site": "same-origin"}
    )
    assert r.status_code == 303
    empty = await api.client.get("/ui/assets")
    assert "No assets yet" in empty.text
    await do_import(api.sm, scan())
    html = (await api.client.get("/ui/assets")).text
    assert "162.243.103.246" in html
    assert "listed" in html
    assert "http server" in html  # observed stack panel
    assert "<script" not in html


def test_cli_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sm: SM, capsys: pytest.CaptureFixture[str]
) -> None:
    from threatlens.cli import main
    from threatlens.settings import get_settings

    monkeypatch.setenv("TL_DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'tl.db').as_posix()}")
    get_settings.cache_clear()
    try:
        bad = tmp_path / "bad.json"
        bad.write_text('{"target": {"value": "Acme", "type": "org"}}', encoding="utf-8")
        assert main(["import-reconx", str(SCAN), str(bad)]) == 1
        out = capsys.readouterr()
        assert "example.com: 4 hosts, 2 IPs, 4 products; 6 new, 0 updated, 3 not imported" in out.out
        assert "not imported" in out.err
        assert main(["import-reconx", str(SCAN)]) == 0
        assert "already imported" in capsys.readouterr().out
    finally:
        get_settings.cache_clear()


def test_observable_keys_match(tmp_path: Path) -> None:
    """Assets join indicators on the observables' canonical key."""
    _, _, _, found, _ = read_reconx(scan())
    assert Observable(IOCType.IPV4, "162.243.103.246").key in {f.obs.key for f in found}
