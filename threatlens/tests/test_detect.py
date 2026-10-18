"""Phase 7 detection engineering (ADR 0020): rules from indicators, the hunt
library, Navigator layers, coverage gaps and retro-hunt packs. Every
generated rule must pass its syntax check and carry its metadata."""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
import yaml
import yara
from sigma.collection import SigmaCollection
from sqlalchemy import select

from tests.test_cases import LIVE, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from tests.test_share import _add
from threatlens.detect import attack, hunts, retro
from threatlens.detect import rules as gen
from threatlens.ioc.types import IOCType
from threatlens.models import Entity, Indicator, Relationship
from threatlens.settings import Settings

AUTHOR = "Argus test"
NASTY_URL = 'http://bad.example:8080/a;b"c|d\\e.sh'
IOCS = [
    gen.Ioc(1, "ipv4-addr", "203.0.113.7", 76, "TLP:CLEAR", ("botnet-c2", "qakbot"), ("feodo",)),
    gen.Ioc(2, "ipv4-net", "198.51.100.0/24", 70, "TLP:GREEN", ("drop",), ("spamhaus_drop",)),
    gen.Ioc(3, "domain-name", "evil-c2.example", 80, "TLP:CLEAR", ("botnet-c2",), ("threatfox",)),
    gen.Ioc(4, "url", NASTY_URL, 72, "TLP:CLEAR", ("malware-distribution",), ("urlhaus",)),
    gen.Ioc(5, "domain-name", "login-bank.example", 66, "TLP:CLEAR", ("phishing",), ("openphish",)),
    gen.Ioc(
        6,
        "file-sha256",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        90,
        "TLP:AMBER",
        ("qakbot",),
        ("malwarebazaar",),
    ),
    gen.Ioc(7, "file-md5", "098f6bcd4621d373cade4e832627b4f6", 85, "TLP:CLEAR", (), ()),
]


def test_sigma_rules_parse_compile_and_carry_metadata() -> None:
    rules = gen.sigma_rules(IOCS, author=AUTHOR, base_url="https://argus.example")
    assert {r.name.split("_")[1] for r in rules} >= {"ip", "net", "domain", "url", "sha256", "md5"}
    for r in rules:
        doc = yaml.safe_load(r.body)
        assert SigmaCollection.from_yaml(r.body).rules  # parses
        assert uuid.UUID(doc["id"])
        assert doc["author"] == AUTHOR
        assert doc["date"] == datetime.now(UTC).strftime("%Y-%m-%d")
        assert doc["references"]
        assert doc["falsepositives"]
        assert any(t.startswith("attack.t") for t in doc["tags"])
        assert any(t.startswith("tlp.") for t in doc["tags"])
        assert 0 < doc["x_argus_confidence"] <= 100
        assert r.problems == [], r.problems
        assert all(r.queries[b] for b in gen.SIGMA_BACKENDS), r.queries
    sha = next(r for r in rules if "sha256" in r.name)
    assert "tlp.amber" in yaml.safe_load(sha.body)["tags"]  # the strictest marking of its indicators
    assert "SHA256=9F86D081" in sha.queries["splunk"]  # Sysmon's Hashes field format
    dns = next(r for r in rules if r.name.startswith("argus_domain_c2_dns"))
    assert '".evil-c2.example"' in dns.queries["kql"]  # subdomains match too


def test_suricata_rules_are_valid_and_escaped() -> None:
    rules = gen.suricata_rules(IOCS, author=AUTHOR)
    body = "\n".join(r.body for r in rules)
    gen.check_suricata(body)  # suricataparser + required options + unique sids
    url = next(r for r in rules if "url" in r.name).body
    assert 'content:"/a|3B|b|22|c|7C|d|5C|e.sh"' in url  # ; " | \ hex-encoded
    assert 'tls.sni; content:"evil-c2.example"; nocase; endswith;' in body
    assert "alert ip $HOME_NET any -> 198.51.100.0/24 any" in body
    sids = [int(x.split("sid:")[1].split(";")[0]) for x in body.splitlines() if "sid:" in x]
    assert len(sids) == len(set(sids))
    assert all(gen.SID_BASE <= s < gen.SID_BASE + 1_000_000 for s in sids)
    with pytest.raises(gen.RuleError):
        gen.check_suricata(
            'alert ip any any -> 1.2.3.4 any (msg:"x"; sid:1; rev:1;)'
        )  # no classtype/metadata


def test_yara_rules_compile_and_match_the_right_file() -> None:
    (rule,) = [r for r in gen.yara_rules(IOCS, author=AUTHOR) if "sha256" in r.name]
    compiled = yara.compile(source=rule.body)
    assert compiled.match(data=b"test")  # sha256("test") is the indicator above
    assert not compiled.match(data=b"other")
    assert 'tlp = "TLP:AMBER"' in rule.body
    assert "mitre_att" in rule.body
    with pytest.raises(gen.RuleError):
        gen.check_yara("rule broken { condition: }")


def test_wazuh_rules_are_well_formed() -> None:
    w = gen.wazuh_rules(AUTHOR)
    gen.check_wazuh(w.body)
    assert w.body.count('<rule id="1009') == 4
    assert 'lookup="address_match_key">etc/lists/argus-ip' in w.body
    with pytest.raises(gen.RuleError):
        gen.check_wazuh('<group name="x"><rule id="5"><description>d</description></rule></group>')


def test_hunt_library_compiles_with_data_sources_and_fp_notes() -> None:
    lib = hunts.library()
    assert len(lib) >= 14
    assert len({h["technique"] for h in lib}) == len(lib)
    for h in lib:
        assert h["problems"] == [], (h["technique"], h["problems"])
        assert all(h["queries"][b] for b in gen.SIGMA_BACKENDS), h["technique"]
        assert h["dataSources"]
        assert h["falsepositives"]
        assert gen.check_attack_tags(h["tags"]) == []
        assert f"attack.{h['technique'].lower()}" in h["tags"]
    assert [h["technique"] for h in hunts.for_techniques({"T1218"})] == ["T1218.011", "T1218.005"]


def test_attack_tags_are_checked_offline() -> None:
    assert gen.check_attack_tags(["attack.stealth", "attack.t1218.011", "tlp.clear", "cve.2024-1"]) == []
    assert gen.check_attack_tags(["attack.defense-evasion", "attack.t12"]) == [
        "attack.defense-evasion",
        "attack.t12",
    ]


# ── API ──────────────────────────────────────────────────────────────────────


async def test_generate_api_respects_clearance(app: App) -> None:
    await _add(app, "198.51.100.90", IOCType.IPV4, score=88, tlp="TLP:AMBER")
    r = await app.c.post(
        "/api/v1/detections/generate",
        headers=app.h("green"),
        json={"min_score": 60, "max_tlp": "TLP:AMBER", "formats": ["sigma", "suricata"]},
    )
    assert r.status_code == 200
    text = json.dumps(r.json())
    assert LIVE in text
    assert "198.51.100.90" not in text  # AMBER, above the key's GREEN clearance
    r = await app.c.post(
        "/api/v1/detections/generate",
        headers=app.h("analyst"),
        json={"min_score": 60, "max_tlp": "TLP:AMBER", "formats": ["suricata"]},
    )
    assert "198.51.100.90" in json.dumps(r.json())
    viewer = await app.c.post("/api/v1/detections/generate", headers=app.h("viewer"), json={})
    assert viewer.status_code == 403


async def test_detection_pack_zip(app: App) -> None:
    r = await app.c.get("/api/v1/detections/pack.zip", headers=app.h("analyst"), params={"min_score": 60})
    assert r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert "README.txt" in names
    assert z.read("README.txt").decode().startswith("TLP:")
    assert any(n.startswith("sigma/splunk/") for n in names)
    assert any(n.startswith("suricata/") for n in names)
    assert "wazuh/argus_rules.xml" in names


async def _malware_with_techniques(app: App) -> str:
    async with app.sm() as s, s.begin():
        mal = Entity(
            stix_id=f"malware--{uuid.uuid4()}",
            type="malware",
            name="TestBot",
            external_id="S9999",
            origin="attack",
        )
        s.add(mal)
        for tid, name in (("T1071.001", "Web Protocols"), ("T1105", "Ingress Tool Transfer")):
            t = Entity(
                stix_id=f"attack-pattern--{uuid.uuid4()}",
                type="attack-pattern",
                name=name,
                external_id=tid,
                origin="attack",
                domains=["enterprise-attack"],
            )
            s.add(t)
            s.add(
                Relationship(
                    stix_id=f"relationship--{uuid.uuid4()}",
                    src_ref=mal.stix_id,
                    rel_type="uses",
                    dst_ref=t.stix_id,
                    origin="attack",
                    description=f"TestBot uses {name}",
                )
            )
    return "S9999"


async def test_navigator_layer_for_an_entity(app: App) -> None:
    ref = await _malware_with_techniques(app)
    r = await app.c.get(f"/api/v1/detections/navigator/{ref}", headers=app.h("viewer"))
    assert r.status_code == 200
    layer = r.json()
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1071.001", "T1105"}
    assert "attachment" in r.headers["content-disposition"]
    assert (
        await app.c.get("/api/v1/detections/navigator/nothing-like-this", headers=app.h("viewer"))
    ).status_code == 404


async def test_coverage_against_imported_sigma(app: App) -> None:
    await _malware_with_techniques(app)
    rule = yaml.safe_dump(
        {
            "title": "Phish attachment",
            "id": str(uuid.uuid4()),
            "status": "stable",
            "logsource": {"category": "process_creation"},
            "tags": ["attack.initial-access", "attack.t1566.001"],
            "detection": {"sel": {"Image|endswith": "\\winword.exe"}, "condition": "sel"},
        }
    )
    files = [
        ("files", ("phish.yml", rule.encode(), "application/x-yaml")),
        ("files", ("bad.yml", b"title: [unclosed", "application/x-yaml")),
    ]
    r = await app.c.post("/api/v1/detections/inventory", headers=app.h("analyst"), files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == 1
    assert body["errors"]
    again = (
        await app.c.post("/api/v1/detections/inventory", headers=app.h("analyst"), files=files[:1])
    ).json()
    assert (again["added"], again["updated"]) == (0, 1)  # the same rule id updates, never duplicates
    cov = (await app.c.get("/api/v1/detections/coverage", headers=app.h("viewer"))).json()
    by = {i["technique"]: i for i in cov["items"]}
    assert by["T1566"]["covered"]  # a sub-technique rule covers the PIR's T1566
    assert not by["T1190"]["covered"]
    assert "PIR-1 watches it" in by["T1190"]["why"]
    assert cov["gaps"][0]["weight"] >= cov["gaps"][-1]["weight"]
    assert {t["techniqueID"] for t in cov["gapLayer"]["techniques"]} == {g["technique"] for g in cov["gaps"]}


def test_inventory_parser_reads_techniques() -> None:
    recs, errors = attack.parse_inventory(
        [
            (
                "a.yml",
                "title: A\ndetection: {condition: x}\n"
                "tags: [attack.T1059.001, attack.execution, tlp.clear]\n",
            ),
            ("b.yml", "action: global\n"),
        ]
    )
    assert [r["techniques"] for r in recs] == [["T1059.001"]]
    assert errors == []


async def test_retro_hunt_pack_for_new_high_priority_indicators(app: App) -> None:
    settings = Settings()
    await retro.build(app.sm, settings)  # the first run sets the cursor
    hot = await _add(app, "198.51.100.95", IOCType.IPV4, score=92)
    cool = await _add(app, "198.51.100.96", IOCType.IPV4, score=50)
    async with app.sm() as s, s.begin():
        for ind in (await s.scalars(select(Indicator).where(Indicator.id.in_([hot, cool])))).all():
            ind.created_at = datetime.now(UTC) + timedelta(seconds=1)  # arrived after the cursor
    pack_id = await retro.build(app.sm, settings)
    assert pack_id is not None
    packs = (await app.c.get("/api/v1/detections/retro", headers=app.h("viewer"))).json()
    p = next(x for x in packs if x["id"] == pack_id)
    assert p["indicators"] == 1
    assert p["lookbackDays"] == retro.LOOKBACK_DAYS
    assert any("198.51.100.95" in q["query"] for q in p["queries"]["splunk"])
    assert not any("198.51.100.96" in q["query"] for q in p["queries"]["splunk"])
    assert await retro.build(app.sm, settings) is None  # nothing new since


def test_suricata_sids_never_collide_across_many_indicators() -> None:
    many = [
        gen.Ioc(n, "ipv4-addr", f"10.{n // 65536}.{n // 256 % 256}.{n % 256}", 50, "TLP:CLEAR", ("tor",), ())
        for n in range(5000)
    ]
    body = "\n".join(r.body for r in gen.suricata_rules(many, author=AUTHOR))
    gen.check_suricata(body)  # raises on a duplicate sid
    again = "\n".join(r.body for r in gen.suricata_rules(many, author=AUTHOR))
    assert again == body  # still deterministic


def test_suricata_check_rejects_a_broken_msg() -> None:
    # suricataparser accepts this; Suricata 7 rejects it ("bad option value formatting")
    bad = (
        'alert http $HOME_NET any -> any any (msg:"x a;b"; classtype:trojan-activity; '
        "sid:9100001; rev:1; metadata: a b;)"
    )
    with pytest.raises(gen.RuleError):
        gen.check_suricata(bad)
