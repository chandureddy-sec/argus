"""Verify on an internal (private or reserved) address: answered from our own
data only, never sent to a provider."""

from __future__ import annotations

import pytest

from tests.test_argus_api import events
from tests.test_cases import App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import cases as case_store
from threatlens.internal import _mentions, classify
from threatlens.models import Asset


@pytest.mark.parametrize(
    ("value", "network", "label"),
    [
        ("192.168.31.224", "192.168.0.0/16", "Private network"),
        ("10[.]0[.]0[.]5", "10.0.0.0/8", "Private network"),
        ("172.20.1.1", "172.16.0.0/12", "Private network"),
        ("100.64.1.2", "100.64.0.0/10", "Carrier-grade NAT"),
        ("127.0.0.1", "127.0.0.0/8", "Loopback"),
        ("169.254.169.254", "169.254.0.0/16", "Link-local"),
        ("255.255.255.255", "255.255.255.255/32", "Broadcast"),
        ("fd12::5", "fc00::/7", "Unique local"),
        ("fe80::1%eth0", "fe80::/10", "Link-local"),
        ("::ffff:10.1.2.3", "10.0.0.0/8", "Private network"),
    ],
)
def test_classify_names_the_range(value: str, network: str, label: str) -> None:
    found = classify(value)
    assert found is not None
    assert (found.network, found.label) == (network, label)


@pytest.mark.parametrize(
    "value", ["8.8.8.8", "2606:4700:4700::1111", "example.com", "10.0.0.0/8", "not an ip"]
)
def test_classify_ignores_public_addresses_and_non_ips(value: str) -> None:
    assert classify(value) is None


def test_mentions_matches_whole_addresses_only() -> None:
    assert _mentions("beacon from 10.0.0.1.", "10.0.0.1")
    assert _mentions("host 10[.]0[.]0[.]1 is down", "10.0.0.1")
    assert not _mentions("see 10.0.0.12", "10.0.0.1")
    assert not _mentions("see 110.0.0.1", "10.0.0.1")


async def test_verify_answers_an_internal_address_locally(app: App) -> None:
    async with app.sm() as s, s.begin():
        for name, ips in [
            ("vpn.corp.example", ["192.168.31.224"]),  # leaks the address into public DNS
            ("git.corp.example", ["192.168.31.10"]),  # same /24
            ("www.corp.example", ["203.0.113.80", "192.168.31.22"]),  # same /24, not the address
            ("mail.corp.example", ["192.168.32.224"]),  # another subnet
        ]:
            s.add(
                Asset(
                    kind="host",
                    value=name,
                    canonical_key=f"domain:{name}",
                    target="corp.example",
                    details={"ips": ips},
                )
            )
        await case_store.create_case(
            s, title="Beacon from 192.168.31.224", actor="anna", tlp="TLP:GREEN", clearance="TLP:RED"
        )
        await case_store.create_case(
            s,
            title="Lateral movement",
            summary="pivot via 192.168.31.224",
            actor="anna",
            tlp="TLP:RED",
            clearance="TLP:RED",
        )
        await case_store.create_case(
            s, title="Printer at 192.168.31.22", actor="anna", tlp="TLP:GREEN", clearance="TLP:RED"
        )
    before = list(app.calls)
    await app.login("vera")  # a viewer: clearance TLP:GREEN
    r = await app.c.get("/app/api/verify/stream", params={"q": "192.168.31.224", "tlp": "TLP:CLEAR"})
    assert r.status_code == 200
    evs = events(r.text)
    assert [e["event"] for e in evs] == ["internal"]
    ev = evs[0]
    assert ev["query"] == {
        "type": "ipv4",
        "typeLabel": "Internal IPv4 address",
        "value": "192[.]168[.]31[.]224",
    }
    assert ev["range"]["label"] == "Private network"
    assert ev["range"]["standard"] == "RFC 1918"
    assert [n["name"] for n in ev["publicNames"]] == ["vpn[.]corp[.]example"]
    assert sorted(n["name"] for n in ev["nearbyNames"]) == ["git[.]corp[.]example", "www[.]corp[.]example"]
    assert [c["title"] for c in ev["cases"]] == ["Beacon from 192[.]168[.]31[.]224"]  # not RED, not .22
    assert app.calls == before  # no provider, registry or feed was asked


async def test_internal_lookup_respects_clearance(app: App) -> None:
    async with app.sm() as s, s.begin():
        await case_store.create_case(
            s,
            title="Lateral movement",
            summary="pivot via 10.9.8.7",
            actor="anna",
            tlp="TLP:RED",
            clearance="TLP:RED",
        )
    await app.login("anna")  # analyst: TLP:AMBER+STRICT
    ev = events((await app.c.get("/app/api/verify/stream", params={"q": "10.9.8.7"})).text)[0]
    assert ev["cases"] == []
    assert ev["publicNames"] == []
    assert ev["nearbyNames"] == []
