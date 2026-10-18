"""Phase 6 dissemination (ADR 0019): STIX 2.1 + TLP 2.0, the TAXII 2.1 server
(and a second ThreatLens consuming it), licence/TLP-aware exports, SIEM/TIP
integrations, alerting, sightings from our SIEM, and the network guard."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from stix2validator import ValidationOptions, validate_instance

from tests.test_cases import LIVE, SAME, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import FEODO_IP, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import blocking
from threatlens.collect import stix_pattern
from threatlens.connectors import custom
from threatlens.ioc.types import IOCType
from threatlens.ioc.types import Observable as Obs
from threatlens.kb.ids import indicator_stix_id
from threatlens.models import (
    AlertEvent,
    AuditLog,
    Indicator,
    IntegrationRun,
    Sighting,
    Source,
)
from threatlens.models import Observable as ObsRow
from threatlens.net import guard
from threatlens.net.http import SafeHttp
from threatlens.share import select as sel
from threatlens.share import sinks, stix
from threatlens.share.taxii import COLLECTIONS, MEDIA

H = {"Accept": MEDIA}
NOW = datetime.now(UTC)


async def _add(
    app: App,
    value: str,
    t: IOCType,
    *,
    score: float,
    tlp: str = "TLP:CLEAR",
    source: str | None = "licensed",
    redistribution: bool = True,
    status: str = "active",
) -> int:
    """An indicator reported by ``source`` (None: an analyst's own)."""
    o = Obs(t, value)
    async with app.sm() as s, s.begin():
        row = ObsRow(
            type=t.value,
            value=value,
            canonical_key=o.key,
            defanged=value.replace(".", "[.]"),
            first_seen=NOW,
            last_seen=NOW,
            sightings_count=1,
        )
        s.add(row)
        await s.flush()
        ind = Indicator(
            observable_id=row.id,
            stix_id=indicator_stix_id(o.key),
            pattern=stix_pattern(o),
            valid_from=NOW,
            valid_until=NOW + timedelta(days=30),
            confidence=80,
            priority_score=score,
            tlp=tlp,
            status=status,
            labels=["test"],
            created_at=NOW,
            updated_at=NOW,
        )
        s.add(ind)
        await s.flush()
        if source:
            src = await s.scalar(select(Source).where(Source.name == source))
            if src is None:
                src = Source(
                    name=source,
                    title=source.title(),
                    kind="ioc",
                    homepage="https://example.org",
                    reliability="B",
                    license="test",
                    license_url="",
                    commercial_use=True,
                    redistribution=redistribution,
                    upstream=source,
                    interval_minutes=60,
                )
                s.add(src)
                await s.flush()
            s.add(Sighting(indicator_id=ind.id, source_id=src.id, first_seen=NOW, last_seen=NOW))
        return ind.id


async def _rows(app: App, rules: sel.Rules) -> list[sel.Row]:
    async with app.sm() as s:
        return await sel.page(s, rules, limit=1000)


# ── what may leave ───────────────────────────────────────────────────────────


async def test_sharing_rules_tlp_licence_score_and_revocations(app: App) -> None:
    await _add(app, "198.51.100.10", IOCType.IPV4, score=90)
    await _add(app, "198.51.100.11", IOCType.IPV4, score=90, source="nolicence", redistribution=False)
    await _add(app, "198.51.100.12", IOCType.IPV4, score=90, tlp="TLP:AMBER")
    await _add(app, "198.51.100.13", IOCType.IPV4, score=90, tlp="TLP:RED")
    await _add(app, "198.51.100.14", IOCType.IPV4, score=20)
    await _add(app, "own-intel.example", IOCType.DOMAIN, score=75, source=None)
    await _add(app, "198.51.100.15", IOCType.IPV4, score=0, status="false_positive")
    vals = {r.obs.value for r in await _rows(app, sel.Rules("TLP:GREEN", 60))}
    assert {"198.51.100.10", "own-intel.example", "198.51.100.15", LIVE} <= vals
    assert not vals & {"198.51.100.11", "198.51.100.12", "198.51.100.13", "198.51.100.14"}
    amber = {r.obs.value for r in await _rows(app, sel.Rules("TLP:AMBER+STRICT", 60))}
    assert "198.51.100.12" in amber
    assert "198.51.100.13" not in amber  # RED never leaves, whatever the cap
    assert sel.levels("TLP:RED") == ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"]
    no_revocations = {r.obs.value for r in await _rows(app, sel.Rules("TLP:GREEN", 60, revocations=False))}
    assert "198.51.100.15" not in no_revocations


async def test_stix_bundle_validates_and_uses_tlp_2_markings(app: App) -> None:
    await _add(app, "198.51.100.20", IOCType.IPV4, score=88, tlp="TLP:GREEN")
    await _add(app, "198.51.100.21", IOCType.IPV4, score=0, status="false_positive")
    rows = await _rows(app, sel.Rules("TLP:GREEN", 60))
    async with app.sm() as s:
        bundle = await stix.build(s, rows, "Argus test")
    result = validate_instance(bundle, ValidationOptions(version="2.1"))
    assert result.is_valid, [str(e) for e in result.errors]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for o in bundle["objects"]:
        by_type.setdefault(o["type"], []).append(o)
    assert {m["id"] for m in by_type["marking-definition"]} == {
        stix.TLP2["TLP:CLEAR"][0],
        stix.TLP2["TLP:GREEN"][0],
    }
    assert all("extensions" in m for m in by_type["marking-definition"])
    inds = {o["pattern"]: o for o in by_type["indicator"]}
    live = inds[f"[ipv4-addr:value = '{LIVE}']"]
    assert live["id"] == indicator_stix_id(f"ipv4-addr|{LIVE}")  # stable id: re-sends update
    assert live["created_by_ref"] == by_type["identity"][0]["id"]
    assert inds["[ipv4-addr:value = '198.51.100.21']"]["revoked"] is True
    # Feodo links its C2s to malware: the family and the relationship travel with them
    assert by_type.get("malware")
    assert by_type.get("relationship")
    rel = by_type["relationship"][0]
    assert rel["relationship_type"] == "indicates"
    assert rel["source_ref"] in {o["id"] for o in by_type["indicator"]}


# ── TAXII 2.1 ────────────────────────────────────────────────────────────────


def _basic(key: str) -> dict[str, str]:
    return {**H, "Authorization": "Basic " + base64.b64encode(f"taxii:{key}".encode()).decode()}


async def test_taxii_discovery_auth_and_media_types(app: App) -> None:
    r = await app.c.get("/taxii2/", headers=H)
    assert r.status_code == 401
    assert r.headers["content-type"] == MEDIA
    assert r.headers["www-authenticate"].startswith("Basic")
    assert r.json()["http_status"] == "401"
    assert (
        await app.c.get("/taxii2/", headers={**_basic(app.keys["viewer"]), "Accept": "text/html"})
    ).status_code == 406
    d = (await app.c.get("/taxii2/", headers=_basic(app.keys["viewer"]))).json()
    assert d["api_roots"] == [d["default"]]
    root = (await app.c.get("/taxii2/api/", headers={**H, "X-API-Key": app.keys["viewer"]})).json()
    assert root["versions"] == [MEDIA]


async def test_taxii_collections_follow_clearance(app: App) -> None:
    green = (await app.c.get("/taxii2/api/collections/", headers=_basic(app.keys["green"]))).json()
    titles = {c["title"] for c in green["collections"]}
    assert all(c["can_read"] for c in green["collections"])
    assert not any(c["can_write"] for c in green["collections"])
    assert not any("AMBER" in t for t in titles)
    amber = next(c for c in COLLECTIONS if c.key == "amber-high")
    r = await app.c.get(f"/taxii2/api/collections/{amber.id}/objects/", headers=_basic(app.keys["green"]))
    assert r.status_code == 404  # above clearance: as if it didn't exist
    viewer = (await app.c.get("/taxii2/api/collections/", headers=_basic(app.keys["analyst"]))).json()
    assert any("AMBER" in c["title"] for c in viewer["collections"])


async def test_taxii_objects_paging_filters_and_manifest(app: App) -> None:
    for n in range(5):
        await _add(app, f"198.51.100.{30 + n}", IOCType.IPV4, score=70 + n)
    c = next(c for c in COLLECTIONS if c.key == "clear-high")
    base = f"/taxii2/api/collections/{c.id}"
    h = _basic(app.keys["viewer"])
    seen: list[str] = []
    r = await app.c.get(f"{base}/objects/", params={"limit": "2", "match[type]": "indicator"}, headers=h)
    while True:
        assert r.status_code == 200
        assert r.headers["content-type"] == MEDIA
        body = r.json()
        seen += [o["id"] for o in body.get("objects", [])]
        assert r.headers.get("x-taxii-date-added-first") or not body.get("objects")
        if not body["more"]:
            break
        r = await app.c.get(
            f"{base}/objects/",
            params={"limit": "2", "next": body["next"], "match[type]": "indicator"},
            headers=h,
        )
    assert len(seen) == len(set(seen)) >= 6  # five new + the live Feodo C2, no repeats across pages
    one = seen[0]
    got = (await app.c.get(f"{base}/objects/{one}/", headers=h)).json()
    assert [o["id"] for o in got["objects"]] == [one]
    assert (await app.c.get(f"{base}/objects/{one}/versions/", headers=h)).json()["versions"]
    later = (NOW + timedelta(days=1)).isoformat()
    assert (
        "objects"
        not in (await app.c.get(f"{base}/objects/", params={"added_after": later}, headers=h)).json()
    )
    man = (await app.c.get(f"{base}/manifest/", params={"match[type]": "indicator"}, headers=h)).json()
    assert {m["media_type"] for m in man["objects"]} == {"application/stix+json;version=2.1"}
    assert (await app.c.post(f"{base}/objects/", headers=h, json={"objects": []})).status_code == 403
    assert (await app.c.get(f"{base}/objects/", params={"next": "!!"}, headers=h)).status_code == 400


async def test_a_second_threatlens_consumes_the_taxii_feed(app: App) -> None:
    """The TAXII reader of a custom feed (what another ThreatLens or Argus
    uses) pulls our collection, follows ``next`` and resumes from the
    checkpoint: the same code path the worker runs."""
    await _add(app, "203.0.113.50", IOCType.IPV4, score=91, tlp="TLP:GREEN")
    c = next(c for c in COLLECTIONS if c.key == "green-high")
    transport = httpx.ASGITransport(app=app.c._transport.app)  # type: ignore[attr-defined]
    async with SafeHttp(transport=transport, allow_http=True, retries=0) as client:
        res = await custom.fetch_taxii(
            client, f"http://test/taxii2/api/collections/{c.id}/", {"X-API-Key": app.keys["green"]}, {}
        )
        spec = custom.FeedSpec(name="custom_peer", title="Peer", url="x", format="taxii", tlp="TLP:CLEAR")
        items = list(custom.parse_spec(spec, res.body))
        vals = {i.value for i in items}
        assert {LIVE, "203.0.113.50"} <= vals
        green = next(i for i in items if i.value == "203.0.113.50")
        assert green.tlp == "TLP:GREEN"  # the producer's marking is kept
        assert green.type is IOCType.IPV4
        mark = res.headers["taxii_added_last"]
        again = await custom.fetch_taxii(
            client,
            f"http://test/taxii2/api/collections/{c.id}/",
            {"X-API-Key": app.keys["green"]},
            {"taxii_added_last": mark},
        )
        assert json.loads(again.body)["objects"] == []  # nothing new since the checkpoint


def test_stix_pattern_reader() -> None:
    pv = custom.pattern_values(
        "[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'ev\\'il.example'] OR "
        "[file:hashes.'SHA-256' = 'aa'] OR [process:name = 'x'] OR [ipv4-addr:value = '10.0.0.0/8']"
    )
    assert pv == [
        (IOCType.IPV4, "1.2.3.4"),
        (IOCType.DOMAIN, "ev'il.example"),
        (IOCType.SHA256, "aa"),
        (IOCType.IPV4_NET, "10.0.0.0/8"),
    ]


def test_misp_attributes_map_to_items() -> None:
    doc = {
        "response": {
            "Attribute": [
                {
                    "type": "ip-dst|port",
                    "value": "203.0.113.9|443",
                    "timestamp": "1760000000",
                    "event_id": "7",
                    "Tag": [{"name": "tlp:amber"}, {"name": "botnet"}],
                    "Event": {"info": "C2 wave", "Tag": [{"name": "tlp:green"}]},
                },
                {"type": "filename|sha256", "value": "a.exe|" + "b" * 64, "timestamp": "1760000001"},
                {"type": "comment", "value": "not an indicator"},
                {"type": "domain", "value": "evil.example", "deleted": True},
            ]
        }
    }
    spec = custom.FeedSpec(name="custom_misp", title="MISP", url="x", format="misp", tlp="TLP:CLEAR")
    items = list(custom.parse_spec(spec, json.dumps(doc).encode()))
    assert [(i.value, i.type) for i in items] == [("203.0.113.9", None), ("b" * 64, IOCType.SHA256)]
    assert items[0].tlp == "TLP:AMBER"  # the strictest tag wins
    assert "botnet" in items[0].labels
    assert items[0].context["misp_event"] == "C2 wave"
    with pytest.raises(custom.SchemaDriftError):
        list(custom.parse_spec(spec, b'{"Event": []}'))


# ── exports ──────────────────────────────────────────────────────────────────


async def _token(app: App) -> str:
    async with app.sm() as s, s.begin():
        _, tok = await blocking.create_token(s, "fw", actor="test")
    return tok


async def test_indicator_exports_in_every_format(app: App) -> None:
    await _add(app, "198.51.100.40", IOCType.IPV4, score=80)
    await _add(app, "10.20.30.0/24", IOCType.IPV4_NET, score=80)
    await _add(app, "evil-export.example", IOCType.DOMAIN, score=80)
    await _add(app, "http://evil-export.example/a:b", IOCType.URL, score=80)
    await _add(app, "198.51.100.41", IOCType.IPV4, score=80, source="nolicence", redistribution=False)
    await _add(app, "=cmd|' /C calc'!A0.example", IOCType.DOMAIN, score=80)
    tok = await _token(app)
    ips = (await app.c.get(f"/feeds/{tok}/indicators/ip.txt")).text.split()
    assert "198.51.100.40" in ips
    assert LIVE in ips
    assert "198.51.100.41" not in ips  # its only source forbids redistribution
    urls = (await app.c.get(f"/feeds/{tok}/indicators/url.txt")).text.split()
    assert "evil-export.example/a:b" in urls  # EDL: no scheme
    cdb = (await app.c.get(f"/feeds/{tok}/indicators/wazuh-ip.cdb")).text.splitlines()
    assert "10.20.30.:malicious score=80 tlp=clear" in cdb  # a /24 as Wazuh's dotted prefix
    assert f"{LIVE}:malicious score=" in "\n".join(cdb)
    ucdb = (await app.c.get(f"/feeds/{tok}/indicators/wazuh-url.cdb")).text
    assert '"http://evil-export.example/a:b":malicious' in ucdb  # keys with a colon are quoted
    csv_text = (await app.c.get(f"/feeds/{tok}/indicators/indicators.csv")).text
    assert "\n'=cmd" in csv_text  # a formula is neutralised
    doc = (await app.c.get(f"/feeds/{tok}/indicators/indicators.json")).json()
    assert doc["count"] == len(doc["indicators"])
    bundle = (await app.c.get(f"/feeds/{tok}/indicators/stix.json")).json()
    assert validate_instance(bundle, ValidationOptions(version="2.1")).is_valid
    assert (await app.c.get("/feeds/tlf_wrong/indicators/ip.txt")).status_code == 404
    assert (await app.c.get(f"/feeds/{tok}/indicators/nope.txt")).status_code == 404
    high = (await app.c.get(f"/feeds/{tok}/indicators/ip.txt", params={"min_score": 99})).text
    assert "198.51.100.40" not in high


# ── integrations ─────────────────────────────────────────────────────────────


class Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        host, path = req.url.host, req.url.path
        if host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok-123", "token_type": "Bearer"})
        if path.endswith("/_bulk"):
            n = len(req.content.splitlines()) // 2
            return httpx.Response(200, json={"errors": False, "items": [{"index": {"status": 201}}] * n})
        if path.endswith("/events/add"):
            return httpx.Response(200, json={"Event": {"id": str(len(self.requests))}})
        if path.endswith("/servers/getVersion"):
            return httpx.Response(200, json={"version": "2.5.3"})
        return httpx.Response(200, json={"text": "Success", "code": 0, "ok": True})


@pytest.fixture
def rec(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    r = Recorder()

    async def _nosleep(_: float) -> None:
        return None

    def http_for(allow_internal: bool, settings: Any, *, retries: int = 1) -> SafeHttp:
        return SafeHttp(transport=httpx.MockTransport(r), allow_http=True, retries=0, sleep=_nosleep)

    monkeypatch.setattr(sinks, "http_for", http_for)
    return r


async def _admin(app: App) -> None:
    from threatlens.users import create_user

    async with app.sm() as s, s.begin():
        await create_user(s, "ada", "ada-password", "admin")
    await app.login("ada")


async def _integration(app: App, **body: Any) -> dict[str, Any]:
    r = await app.c.post("/api/v1/integrations", json=body, headers=SAME)
    assert r.status_code == 201, r.text
    return r.json()


async def test_integration_validation_and_secrets_stay_secret(app: App) -> None:
    await _admin(app)
    bad = [
        {"name": "x", "kind": "splunk_hec", "config": {"url": "https://s"}, "secret": {"token": "t"}},
        {"name": "hec", "kind": "splunk_hec", "config": {}, "secret": {"token": "t"}},
        {"name": "hec", "kind": "splunk_hec", "config": {"url": "https://u:p@s"}, "secret": {"token": "t"}},
        {"name": "hec", "kind": "splunk_hec", "config": {"url": "https://s"}, "secret": {}},
        {
            "name": "hec",
            "kind": "splunk_hec",
            "config": {"url": "https://s"},
            "secret": {"token": "t"},
            "max_tlp": "TLP:RED",
        },
    ]
    for b in bad:
        assert (await app.c.post("/api/v1/integrations", json=b, headers=SAME)).status_code == 422, b
    i = await _integration(
        app,
        name="hec",
        kind="splunk_hec",
        config={"url": "https://splunk.example:8088"},
        secret={"token": "SUPER-SECRET-TOKEN"},
    )
    assert i["hasSecret"] is True
    listed = (await app.c.get("/api/v1/integrations")).text
    assert "SUPER-SECRET-TOKEN" not in listed
    async with app.sm() as s:
        audit = json.dumps([a.details for a in (await s.scalars(select(AuditLog))).all()])
    assert "SUPER-SECRET-TOKEN" not in audit
    # an edit without the secret keeps the stored one
    r = await app.c.put(
        f"/api/v1/integrations/{i['id']}",
        headers=SAME,
        json={
            "name": "hec",
            "kind": "splunk_hec",
            "config": {"url": "https://splunk.example:8088"},
            "min_score": 70,
        },
    )
    assert r.status_code == 200
    assert r.json()["hasSecret"]
    await app.login("anna")
    assert (await app.c.get("/api/v1/integrations")).status_code == 403  # admin only


async def test_push_to_splunk_elastic_sentinel_misp_and_webhook(app: App, rec: Recorder) -> None:
    await _admin(app)
    await _add(app, "198.51.100.60", IOCType.IPV4, score=85, tlp="TLP:GREEN")
    await _add(app, "evil-push.example", IOCType.DOMAIN, score=85)
    made = [
        await _integration(
            app,
            name="hec",
            kind="splunk_hec",
            config={"url": "https://splunk.example:8088", "index": "ti"},
            secret={"token": "hec-token"},
        ),
        await _integration(
            app,
            name="es",
            kind="elastic",
            config={"url": "https://es.example:9200"},
            secret={"api_key": "es-key"},
        ),
        await _integration(
            app,
            name="sentinel",
            kind="sentinel",
            config={"tenant_id": "t1", "client_id": "c1", "workspace_id": "w1"},
            secret={"client_secret": "cs"},
        ),
        await _integration(
            app, name="misp", kind="misp", config={"url": "https://misp.example"}, secret={"key": "mk"}
        ),
        await _integration(app, name="hook", kind="webhook", config={"url": "https://hooks.example/argus"}),
    ]
    for i in made:
        r = await app.c.post(f"/api/v1/integrations/{i['id']}/push", headers=SAME)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "success", r.json()
        assert r.json()["sent"] >= 3
    by_path = {(q.url.host, q.url.path): q for q in rec.requests}
    hec = by_path[("splunk.example", "/services/collector/event")]
    assert hec.headers["authorization"] == "Splunk hec-token"
    events = [json.loads(line) for line in hec.content.splitlines()]
    assert {e["event"]["value"] for e in events} >= {
        "198.51.100.60",
        "evil-push.example",
        LIVE,
    }  # real values
    assert all(e["index"] == "ti" for e in events)
    assert all(e["sourcetype"] == "argus:indicator" for e in events)
    es = by_path[("es.example", "/_bulk")]
    assert es.headers["authorization"] == "ApiKey es-key"
    lines = [json.loads(x) for x in es.content.splitlines()]
    doc = lines[1]
    assert lines[0]["index"]["_id"].startswith("indicator--")
    assert doc["threat"]["indicator"]["marking"]["tlp"] in ("CLEAR", "GREEN")
    assert doc["event"]["kind"] == "enrichment"
    token = by_path[("login.microsoftonline.com", "/t1/oauth2/v2.0/token")]
    assert b"scope=https%3A%2F%2Fmanagement.azure.com%2F.default" in token.content
    up = by_path[("api.ti.sentinel.azure.com", "/workspaces/w1/threat-intelligence-stix-objects:upload")]
    assert up.url.params["api-version"] == "2024-02-01-preview"
    assert up.headers["authorization"] == "Bearer tok-123"
    body = json.loads(up.content)
    assert 1 < len(body["stixobjects"]) <= 100
    assert body["stixobjects"][0]["type"] == "identity"
    misp = [q for q in rec.requests if q.url.path == "/events/add"]
    events_by_tlp = {
        json.loads(q.content)["Event"]["Tag"][0]["name"]: json.loads(q.content)["Event"] for q in misp
    }
    assert set(events_by_tlp) == {"tlp:clear", "tlp:green"}  # one event per marking
    assert all(a["to_ids"] for e in events_by_tlp.values() for a in e["Attribute"])
    assert misp[0].headers["authorization"] == "mk"
    # a second push sends nothing new: the cursor moved
    again = (await app.c.post(f"/api/v1/integrations/{made[0]['id']}/push", headers=SAME)).json()
    assert again["sent"] == 0
    runs = (await app.c.get(f"/api/v1/integrations/{made[0]['id']}/runs")).json()
    assert [r["trigger"] for r in runs] == ["manual", "manual"]


async def test_push_failure_is_recorded_and_redacted(app: App, monkeypatch: pytest.MonkeyPatch) -> None:
    await _admin(app)

    def http_for(allow_internal: bool, settings: Any, *, retries: int = 1) -> SafeHttp:
        return SafeHttp(transport=httpx.MockTransport(lambda r: httpx.Response(403, json={})), retries=0)

    monkeypatch.setattr(sinks, "http_for", http_for)
    i = await _integration(
        app,
        name="hec",
        kind="splunk_hec",
        config={"url": "https://splunk.example:8088"},
        secret={"token": "hec-token"},
    )
    res = (await app.c.post(f"/api/v1/integrations/{i['id']}/push", headers=SAME)).json()
    assert res["status"] == "failed"
    assert "403" in res["error"]
    assert "hec-token" not in res["error"]
    listed = next(x for x in (await app.c.get("/api/v1/integrations")).json()["items"] if x["id"] == i["id"])
    assert listed["lastStatus"] == "failed"
    assert listed["cursor"] is None  # nothing delivered: the next run starts over


async def test_integration_test_button(app: App, rec: Recorder) -> None:
    await _admin(app)
    i = await _integration(
        app, name="misp", kind="misp", config={"url": "https://misp.example"}, secret={"key": "k"}
    )
    r = await app.c.post(f"/api/v1/integrations/{i['id']}/test", headers=SAME)
    assert r.json() == {"ok": True, "result": "MISP answered (version 2.5.3)"}
    s = await _integration(
        app, name="slack", kind="slack", secret={"webhook_url": "https://hooks.slack.com/services/T/B/x"}
    )
    assert (await app.c.post(f"/api/v1/integrations/{s['id']}/test", headers=SAME)).json()["ok"]
    slack = next(q for q in rec.requests if q.url.host == "hooks.slack.com")
    assert "Argus test message" in json.loads(slack.content)["text"]


# ── alerts ───────────────────────────────────────────────────────────────────


async def test_alerts_once_within_tlp_and_rate_limited(app: App, rec: Recorder) -> None:
    await _admin(app)
    slack = await _integration(
        app,
        name="slack",
        kind="slack",
        max_tlp="TLP:GREEN",
        secret={"webhook_url": "https://hooks.slack.com/services/T/B/x"},
    )
    hec = await _integration(
        app, name="hec", kind="splunk_hec", config={"url": "https://s.example"}, secret={"token": "t"}
    )
    bad = {
        "name": "high",
        "kind": "score",
        "params": {"min_score": 80},
        "channels": [hec["id"]],
        "max_tlp": "TLP:AMBER",
    }
    assert (
        await app.c.post("/api/v1/alerts/rules", json=bad, headers=SAME)
    ).status_code == 422  # not a channel
    rule = (
        await app.c.post(
            "/api/v1/alerts/rules",
            headers=SAME,
            json={
                "name": "high",
                "kind": "score",
                "params": {"min_score": 80},
                "channels": [slack["id"]],
                "max_tlp": "TLP:AMBER",
            },
        )
    ).json()
    # existing intelligence does not alert: the rule starts from now
    first = (await app.c.post("/api/v1/alerts/evaluate", headers=SAME)).json()
    assert first["raised"] == 0
    a = await _add(app, "198.51.100.70", IOCType.IPV4, score=95)
    amber = await _add(app, "198.51.100.71", IOCType.IPV4, score=95, tlp="TLP:AMBER")
    await _add(app, "198.51.100.72", IOCType.IPV4, score=95, tlp="TLP:RED")
    await _add(app, "198.51.100.73", IOCType.IPV4, score=50)
    async with app.sm() as s, s.begin():
        for ind in (await s.scalars(select(Indicator).where(Indicator.id.in_([a, amber])))).all():
            ind.updated_at = datetime.now(UTC) + timedelta(seconds=5)
    res = (await app.c.post("/api/v1/alerts/evaluate", headers=SAME)).json()
    assert res["raised"] == 2  # RED never alerts, 50 is below the rule
    assert res["delivered"] == 1
    assert res["held"] == 1  # AMBER is above the Slack channel's cap
    texts = [json.loads(q.content)["text"] for q in rec.requests if q.url.host == "hooks.slack.com"]
    assert len(texts) == 1
    assert "198[.]51[.]100[.]70" in texts[0]  # people get defanged values
    again = (await app.c.post("/api/v1/alerts/evaluate", headers=SAME)).json()
    assert again["raised"] == 0  # never twice
    shown = (await app.c.get("/api/v1/alerts")).json()
    assert {e["rule"] for e in shown} == {"high"}
    held = next(e for e in shown if "71" in e["title"])
    assert held["delivered"][str(slack["id"])].startswith("held")
    await app.login("vera")  # a viewer reads alerts within their clearance
    assert all(e["tlp"] in ("TLP:CLEAR", "TLP:GREEN") for e in (await app.c.get("/api/v1/alerts")).json())
    del rule


async def test_alert_rate_limit_sends_a_digest(
    app: App, rec: Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _admin(app)
    tele = await _integration(
        app, name="tele", kind="telegram", config={"chat_id": "-100"}, secret={"bot_token": "123:ABC"}
    )
    await app.c.post(
        "/api/v1/alerts/rules",
        headers=SAME,
        json={
            "name": "all",
            "kind": "score",
            "params": {"min_score": 60},
            "channels": [tele["id"]],
            "max_tlp": "TLP:CLEAR",
        },
    )
    from threatlens.share import alerts

    real = alerts.evaluate

    async def limited(sm: Any, settings: Any) -> dict[str, int]:
        return await real(sm, settings.model_copy(update={"alert_max_per_hour": 2}))

    monkeypatch.setattr(alerts, "evaluate", limited)
    ids = [await _add(app, f"198.51.100.{80 + n}", IOCType.IPV4, score=90) for n in range(5)]
    async with app.sm() as s, s.begin():
        for ind in (await s.scalars(select(Indicator).where(Indicator.id.in_(ids)))).all():
            ind.updated_at = datetime.now(UTC) + timedelta(seconds=5)
    import threatlens.api.share as share_api

    monkeypatch.setattr(share_api.alerts, "evaluate", limited)
    res = (await app.c.post("/api/v1/alerts/evaluate", headers=SAME)).json()
    assert res["raised"] == 5
    assert res["delivered"] == 2
    assert res["held"] == 3
    msgs = [json.loads(q.content)["text"] for q in rec.requests if q.url.host == "api.telegram.org"]
    assert len(msgs) == 3
    assert "3 more alerts" in msgs[-1]
    assert all(
        "/bot123:ABC/sendMessage" in str(q.url) for q in rec.requests if q.url.host == "api.telegram.org"
    )
    async with app.sm() as s:
        assert int(await s.scalar(select(func.count()).select_from(AlertEvent)) or 0) == 5
        runs = (await s.scalars(select(IntegrationRun).where(IntegrationRun.trigger == "alert"))).all()
    assert all("123:ABC" not in (r.error or "") for r in runs)


# ── sightings from our SIEM ──────────────────────────────────────────────────


async def test_siem_sightings_record_known_values_only(app: App) -> None:
    await app.login("anna")
    before = (await app.c.get(f"/api/v1/indicators?q={LIVE}")).json()["items"][0]["priority_score"]
    r = await app.c.post(
        "/api/v1/sightings",
        headers=SAME,
        json={
            "system": "Splunk",
            "values": [LIVE, "203.0.113.99", "beacon to 162.243.103[.]246 seen"],
            "context": {"host": "fin-ws-12"},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["checked"] >= 2
    assert body["known"] == 2
    live = next(m for m in body["matches"] if m["value"] == "50[.]16[.]16[.]211")
    assert (live["verdict"], live["action"]) == ("malicious", "block")
    async with app.sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "siem_splunk"))
        assert src is not None
        assert src.kind == "environment"
        assert (
            await s.scalar(select(ObsRow).where(ObsRow.value == "45.33.32.156")) is None
        )  # logs aren't intel
    from threatlens.scoring.store import rescore
    from threatlens.settings import Settings

    await rescore(app.sm, Settings())
    after = (await app.c.get(f"/api/v1/indicators?q={LIVE}")).json()["items"][0]["priority_score"]
    assert after == before  # seeing it ourselves is not a report that it is malicious
    ind = await app.ind(LIVE)
    seen = {
        s["key"]: s for s in (await app.c.get(f"/app/api/indicators/{ind.id}/related")).json()["journey"]
    }["seen"]
    assert seen["state"] == "warn"
    assert "Splunk" in seen["lines"][0]
    await app.login("vera")
    assert (
        await app.c.post("/api/v1/sightings", headers=SAME, json={"system": "x", "values": [LIVE]})
    ).status_code == 403


async def test_wazuh_alert_webhook(app: App) -> None:
    alert = {
        "rule": {"id": "100200", "description": "Outbound to rare IP"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "10.0.0.5", "dstip": LIVE, "url": "http://docs.example/readme"},
    }
    r = await app.c.post("/api/v1/integrations/wazuh/alert", json=alert, headers=app.h("analyst"))
    assert r.status_code == 200
    assert [m["value"] for m in r.json()["matches"]] == ["50[.]16[.]16[.]211"]
    async with app.sm() as s:
        sg = (
            (await s.execute(select(Sighting).join(Source).where(Source.name == "siem_wazuh")))
            .scalars()
            .one()
        )
    assert sg.context["agent"] == "web-01"


# ── network guard for internal destinations ──────────────────────────────────


@pytest.mark.parametrize(
    ("addr", "internal", "loopback", "ok"),
    [
        ("10.1.2.3", False, False, False),
        ("10.1.2.3", True, False, True),
        ("192.168.1.10", True, False, True),
        ("fd00::1", True, False, True),
        ("127.0.0.1", True, False, False),
        ("127.0.0.1", True, True, True),
        ("169.254.169.254", True, True, False),  # cloud metadata: never
        ("fe80::1", True, True, False),
        ("0.0.0.0", True, True, False),  # noqa: S104 - an address under test, not a bind
        ("8.8.8.8", False, False, True),
    ],
)
def test_internal_networks_never_include_metadata(
    addr: str, internal: bool, loopback: bool, ok: bool
) -> None:
    def check() -> str:
        return guard.check_addresses("h", [addr], internal=internal, loopback=loopback)

    if ok:
        assert check() == addr
    else:
        with pytest.raises(guard.BlockedAddressError):
            check()


async def test_basic_auth_carries_the_api_key(app: App) -> None:
    h = {"Authorization": "Basic " + base64.b64encode(f"ignored:{app.keys['viewer']}".encode()).decode()}
    assert (await app.c.get("/api/v1/indicators", headers=h)).status_code == 200
    bad = {"Authorization": "Basic " + base64.b64encode(b"ignored:tl_wrong").decode()}
    assert (await app.c.get("/api/v1/indicators", headers=bad)).status_code == 401
    assert (await app.c.get("/api/v1/indicators", headers={"Authorization": "Basic !!"})).status_code == 401
