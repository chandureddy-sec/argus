"""Contract tests: each parser against its recorded fixture, plus schema-drift
cases that must fail loudly instead of silently ingesting nothing."""

from __future__ import annotations

import json
import re

import pytest

from tests.conftest import fixture_bytes
from threatlens.connectors import REGISTRY
from threatlens.connectors.base import Connector, MissingKeyError, SchemaDriftError, parse_time
from threatlens.connectors.feeds import (
    CisaKev,
    FeodoTracker,
    OpenPhish,
    Otx,
    SpamhausDrop,
    ThreatFox,
    TorExits,
    UrlHaus,
)
from threatlens.ioc.types import IOCType


def items(c: Connector, name: str) -> list:  # type: ignore[type-arg]
    return list(c.parse(fixture_bytes(name)))


def test_registry_metadata_is_complete() -> None:
    assert set(REGISTRY) == {
        "cisa_kev",
        "urlhaus",
        "threatfox",
        "feodo",
        "otx",
        "spamhaus_drop",
        "tor_exits",
        "openphish",
    }
    for cls in REGISTRY.values():
        i = cls.info
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", i.verified), i.name
        assert i.min_interval <= i.interval, i.name
        assert i.url.startswith("https://") and i.license_url.startswith("https://"), i.name
        assert 0 <= i.default_confidence <= 100
        assert i.key_required <= bool(i.key_setting), i.name  # required keys must name their setting


def test_kev() -> None:
    got = items(CisaKev(), "cisa_kev.json")
    assert len(got) == 3
    assert all(i.type == IOCType.CVE and i.value.startswith("CVE-") for i in got)
    assert all("kev" in i.labels for i in got)
    assert any("ransomware" in i.labels for i in got)
    assert got[0].context["vendor"] and got[0].seen_at is not None


def test_urlhaus() -> None:
    got = items(UrlHaus(), "urlhaus.csv")
    assert [i.value for i in got][:2] == [
        "http://93.184.216.34:60557/bin.sh",
        "https://malware-drop.example.net/payload.exe",
    ]
    assert got[0].confidence == 85 and got[1].confidence == 60  # online vs offline
    assert "Mozi" in got[0].labels and "None" not in got[2].labels
    assert got[0].context["reference"].startswith("https://urlhaus.abuse.ch/url/")


def test_threatfox_requires_key_and_parses() -> None:
    with pytest.raises(MissingKeyError, match="TL_ABUSECH_AUTH_KEY"):
        ThreatFox()
    got = items(ThreatFox(api_key="k"), "threatfox.json")
    ip = got[0]
    assert (ip.value, ip.type, ip.context["port"], ip.confidence) == ("93.184.216.34", IOCType.IPV4, 443, 100)
    assert got[1].type == IOCType.DOMAIN and got[1].context["malware"] == "QakBot"
    assert got[3].type == IOCType.SHA256
    assert got[4].type is None  # unknown ioc_type → guessed (and rejected) downstream
    assert list(ThreatFox(api_key="k").parse(b'{"query_status": "no_result"}')) == []


def test_feodo() -> None:
    got = items(FeodoTracker(), "feodo.json")
    assert len(got) == 3
    assert all("botnet-c2" in i.labels and i.context["port"] for i in got)


def test_otx_tlp_and_inactive() -> None:
    with pytest.raises(MissingKeyError):
        Otx()
    got = items(Otx(api_key="k"), "otx.json")
    values = [i.value for i in got]
    assert "old.example.com" not in values  # is_active == 0
    assert {i.tlp for i in got if i.context["pulse_id"].startswith("a")} == {"TLP:GREEN"}
    assert next(i for i in got if i.value == "192.0.43.10").tlp == "TLP:AMBER"
    mutex = next(i for i in got if i.context["otx_type"] == "Mutex")
    assert mutex.type is None  # unsupported type


def test_spamhaus() -> None:
    got = items(SpamhausDrop(), "spamhaus_drop.ndjson")
    assert len(got) == 5
    assert {i.type for i in got} == {IOCType.IPV4_NET, IOCType.IPV6_NET}
    assert got[0].context["sblid"].startswith("SBL")


def test_tor_and_openphish() -> None:
    assert len(items(TorExits(), "tor_exits.txt")) == 3
    phish = items(OpenPhish(), "openphish.txt")
    assert len(phish) == 3 and all(i.type == IOCType.URL for i in phish)


@pytest.mark.parametrize(
    ("connector", "body", "message"),
    [
        (CisaKev(), b'{"title": "x"}', "missing field"),
        (CisaKev(), b"[1, 2]", "not an object"),
        (CisaKev(), b'{"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2024-1"}]}', "dateAdded"),
        (CisaKev(), b"<html>maintenance</html>", "not JSON"),
        (UrlHaus(), b"# id,date,url\n1,2,3\n", "unexpected CSV header"),
        (ThreatFox(api_key="k"), b'{"query_status": "illegal_auth_key"}', "query_status"),
        (FeodoTracker(), b'{"error": "x"}', "not a list"),
        (FeodoTracker(), b'[{"ip": "1.2.3.4"}]', "ip_address"),
        (Otx(api_key="k"), b'{"pages": [{"next": null}]}', "results"),
        (SpamhausDrop(), b'{"cidr": "1.10.16.0/20"}\n', "no metadata"),
        (TorExits(), b"<!DOCTYPE html>\n", "one IP per line"),
        (OpenPhish(), b"<html>\n", "one URL per line"),
    ],
)
def test_schema_drift_fails_loudly(connector: Connector, body: bytes, message: str) -> None:
    with pytest.raises(SchemaDriftError, match=message):
        list(connector.parse(body))


def test_urlhaus_row_width_drift() -> None:
    body = fixture_bytes("urlhaus.csv").decode() + '"1","2026-10-08 00:00:00","http://x.example.com/"\n'
    with pytest.raises(SchemaDriftError, match="columns"):
        list(UrlHaus().parse(body.encode()))


def test_kev_tolerates_new_fields() -> None:
    # CISA added `forensicTriage` in 2026: additive fields must not break us.
    doc = json.loads(fixture_bytes("cisa_kev.json"))
    doc["vulnerabilities"][0]["brandNewField"] = {"x": 1}
    assert len(list(CisaKev().parse(json.dumps(doc).encode()))) == 3


@pytest.mark.parametrize(
    ("raw", "iso"),
    [
        ("2026-10-08 06:00:00 UTC", "2026-10-08T06:00:00+00:00"),
        ("2026-10-08T09:00:00", "2026-10-08T09:00:00+00:00"),
        ("2026-10-08T09:00:00Z", "2026-10-08T09:00:00+00:00"),
        ("2026-10-04", "2026-10-04T00:00:00+00:00"),
    ],
)
def test_parse_time(raw: str, iso: str) -> None:
    t = parse_time(raw)
    assert t is not None and t.isoformat() == iso
    assert parse_time("not a date") is None and parse_time(None) is None
