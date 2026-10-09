"""API v1 knowledge-base routes, against a graph built from recorded fixtures."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import threatlens.models  # noqa: F401 - register tables
from tests.test_kb import build_graph
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.db import Base
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def client(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s, s.begin():
        _, key = await create_key(s, "reader", "viewer")
    app = create_app(Settings(), checks={}, sessionmaker=sm, limiter=MemoryRateLimiter())
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", headers={"X-API-Key": key}
        ) as c,
    ):
        yield c


async def test_routes_need_a_key(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/entities", "/api/v1/vulnerabilities", "/api/v1/graph/node?node=S0367"):
        r = await client.get(path, headers={"X-API-Key": ""})
        assert r.status_code == 401, path


async def test_releases_and_changes(client: httpx.AsyncClient) -> None:
    rel = (await client.get("/api/v1/attack/releases")).json()
    assert [(r["domain"], r["version"], r["baseline"]) for r in rel] == [("enterprise-attack", "19.2", True)]
    ch = await client.get("/api/v1/attack/releases/enterprise-attack/19.2/changes")
    assert ch.status_code == 200
    assert ch.json()["total"] == 0  # baseline
    assert (await client.get("/api/v1/attack/releases/enterprise-attack/1.0/changes")).status_code == 404
    bad = await client.get("/api/v1/attack/releases/enterprise-attack/19.2/changes?change=exploded")
    assert bad.status_code == 422


async def test_techniques_linked_to_malware(client: httpx.AsyncClient) -> None:
    """Phase 2 acceptance: "show all techniques linked to malware X"."""
    for ident in ("Emotet", "S0367", "geodo"):
        r = await client.get(f"/api/v1/entities/{ident}/techniques")
        assert r.status_code == 200, ident
        body = r.json()
        assert body["entity"]["label"] == "Emotet"
        ids = [t["technique"]["external_id"] for t in body["techniques"]]
        assert ids == sorted(ids)
        assert {"T1047", "T1033", "T1110.001", "T1552.001", "T1570", "T1573.001"} == set(ids)
        ev = body["techniques"][0]["evidence"]
        assert ev["source"] == "mitre_attack"
        assert ev["origin"] == "attack"
        assert ev["provenance"]["attack_relationship"].startswith("relationship--")
        assert body["techniques"][0]["technique"]["url"].startswith("https://attack.mitre.org/techniques/")
    top = (await client.get("/api/v1/entities/Emotet/techniques?include_subtechniques=false")).json()
    assert {t["technique"]["external_id"] for t in top["techniques"]} == {"T1047", "T1033", "T1570"}
    assert (await client.get("/api/v1/entities/NoSuchMalware/techniques")).status_code == 404


async def test_entities(client: httpx.AsyncClient) -> None:
    groups = (await client.get("/api/v1/entities?type=intrusion-set")).json()
    assert {g["name"] for g in groups["items"]} == {"Lazarus Group", "Wizard Spider", "TeamPCP"}
    cred = (await client.get("/api/v1/entities?type=attack-pattern&tactic=credential-access")).json()
    assert cred["total"] >= 2
    assert all("credential-access" in t["tactics"] for t in cred["items"])
    # "Indicator Removal from Tools" exists twice: a revoked technique and T1027.005, which replaced it.
    live = (await client.get("/api/v1/entities?type=attack-pattern&q=indicator removal")).json()
    assert [(t["external_id"], t["revoked"]) for t in live["items"]] == [("T1027.005", False)]
    every = (
        await client.get("/api/v1/entities?type=attack-pattern&q=indicator removal&include_revoked=true")
    ).json()
    assert every["total"] == 2
    assert any(t["revoked"] for t in every["items"])
    d = (await client.get("/api/v1/entities/S0367")).json()
    assert d["name"] == "Emotet"
    assert d["relationship_counts"]["uses:out"] == 6
    assert d["relationship_counts"]["uses:in"] == 1
    assert d["relationship_counts"]["indicates:in"] >= 1  # Feodo C2 indicators
    assert (await client.get("/api/v1/entities/CVE-2024-3400")).status_code == 404  # a vulnerability


async def test_vulnerabilities(client: httpx.AsyncClient) -> None:
    kev = (await client.get("/api/v1/vulnerabilities?kev=true&sort=cve")).json()
    ids = [v["cve_id"] for v in kev["items"]]
    assert "CVE-2024-3400" in ids
    assert all(v["kev"] for v in kev["items"])
    forti = (await client.get("/api/v1/vulnerabilities?vendor=fortinet&product=fortios")).json()
    assert {v["cve_id"] for v in forti["items"]} == {"CVE-2025-43892", "CVE-2025-62675"}
    hi = (await client.get("/api/v1/vulnerabilities?cvss_min=9.5")).json()
    assert all(v["cvss_score"] >= 9.5 for v in hi["items"])
    q = (await client.get("/api/v1/vulnerabilities?q=globalprotect")).json()
    assert [v["cve_id"] for v in q["items"]] == ["CVE-2024-3400"]

    d = (await client.get("/api/v1/vulnerabilities/cve-2024-3400")).json()
    assert d["kev"] is True
    assert d["kev_due_date"] == "2024-04-19"
    assert {"exploited-in-the-wild", "public-exploit-reference"} <= {
        x["signal"] for x in d["exploit_signals"]
    }
    assert {"part": "o", "vendor": "paloaltonetworks", "product": "pan-os"} in d["products"]
    assert set(d["sources"]) >= {"nvd", "cisa_kev"}
    assert (await client.get("/api/v1/vulnerabilities/CVE-1999-0000")).status_code == 404
    assert (await client.get("/api/v1/vulnerabilities?epss_min=2")).status_code == 422


async def test_graph_routes(client: httpx.AsyncClient) -> None:
    feodo = json.loads((ROOT / "tests" / "fixtures" / "feodo.json").read_text())
    ip = next(d["ip_address"] for d in feodo if d.get("malware") == "Emotet")
    node = (await client.get(f"/api/v1/graph/node?node={ip}")).json()
    assert node["kind"] == "indicator"

    nb = (await client.get("/api/v1/graph/neighbors?node=Emotet&rel=uses&direction=in")).json()
    assert [i["node"]["label"] for i in nb["items"]] == ["Wizard Spider"]

    p = (await client.get("/api/v1/graph/paths", params={"from": ip, "to": "CVE-2020-1472"})).json()
    assert p["length"] == 3
    assert [e["rel_type"] for e in p["paths"][0]] == ["indicates", "uses", "related-to"]
    assert all(e["source"] and e["provenance"] for e in p["paths"][0])
    assert set(p["nodes"]) >= {p["from"]["ref"], p["to"]["ref"]}

    assert (
        await client.get("/api/v1/graph/paths", params={"from": ip, "to": "nothing-known"})
    ).status_code == 404
    assert (
        await client.get("/api/v1/graph/paths", params={"from": ip, "to": "T1047", "max_depth": 9})
    ).status_code == 422


def test_migrations_cover_every_model_column() -> None:
    """Guard against model/migration drift without a database: every table and
    column in the models must appear in the offline SQL of the migrations."""
    sql = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for table in Base.metadata.sorted_tables:
        assert f"CREATE TABLE {table.name} (" in sql, table.name
        block = sql.split(f"CREATE TABLE {table.name} (", 1)[1].split(";", 1)[0]
        added = [
            line for line in sql.splitlines() if line.startswith(f"ALTER TABLE {table.name} ADD COLUMN ")
        ]
        for col in table.columns:
            name = f'"{col.name}"' if col.name in ("references",) else col.name
            in_create = f"\n    {name} " in block or f"\n    {col.name} " in block
            in_alter = any(f"ADD COLUMN {col.name} " in a or f'ADD COLUMN "{col.name}" ' in a for a in added)
            assert in_create or in_alter, f"{table.name}.{col.name} missing from migrations"
