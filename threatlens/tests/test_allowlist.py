from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from threatlens.allowlist import Allowlist, Entry, org_profile_entries
from threatlens.ioc.types import IOCType, Observable
from threatlens.rawstore import RawStore, RawStoreError

T = IOCType

ALLOW = Allowlist(
    [
        *org_profile_entries(["acme.com"], ["203.0.113.0/24", "2001:db8::/32"]),
        Entry("domain", "amazonaws.com", "suppress", "Tranco top 10000 (#5)", "tranco"),
        Entry("domain", "github.com", "suppress", "Tranco top 10000 (#30)", "tranco"),
        Entry("cidr", "104.16.0.0/13", "flag", "Cloudflare edge range", "cloudflare"),
        Entry("domain", "partner.example", "suppress", "analyst: vendor portal", "manual"),
    ]
)


def v(t: IOCType, value: str) -> tuple[str | None, tuple[str, ...]]:
    verdict = ALLOW.check(Observable(t, value))
    return verdict.effect, verdict.labels


@pytest.mark.parametrize(
    ("t", "value", "effect", "label"),
    [
        (T.DOMAIN, "acme.com", "suppress", "own-asset"),
        (T.DOMAIN, "vpn.eu.acme.com", "suppress", "own-asset"),  # subdomains of our own domain
        (T.DOMAIN, "notacme.com", None, None),  # label boundary, not substring
        (T.DOMAIN, "github.com", "suppress", "popular-domain"),
        (T.DOMAIN, "gist.github.com", "suppress", "popular-domain"),
        (T.DOMAIN, "evil.s3.amazonaws.com", None, None),  # private suffix: a tenant, not Amazon
        (T.URL, "https://github.com/evil/payload.exe", "flag", "popular-domain-host"),
        (T.URL, "https://login.acme.com/reset", "suppress", "own-asset"),
        (T.URL, "http://104.16.1.1/x", "flag", "shared-cdn"),
        (T.EMAIL, "ceo@acme.com", "suppress", "own-asset"),
        (T.IPV4, "203.0.113.77", "suppress", "own-asset"),
        (T.IPV4, "104.23.255.1", "flag", "shared-cdn"),
        (T.IPV4, "104.24.0.1", None, None),  # just outside 104.16.0.0/13
        (T.IPV6, "2001:db8::5", "suppress", "own-asset"),
        (T.IPV4_NET, "203.0.113.128/25", "suppress", "own-asset"),  # inside our range
        (T.IPV4_NET, "203.0.0.0/16", "suppress", "contains-own-assets"),  # would block us
        (T.DOMAIN, "portal.partner.example", "suppress", "allowlisted"),
    ],
)
def test_verdicts(t: IOCType, value: str, effect: str | None, label: str | None) -> None:
    got_effect, labels = v(t, value)
    assert got_effect == effect
    if label:
        assert label in labels


def test_suppress_beats_flag_and_reasons_accumulate() -> None:
    a = Allowlist(
        [
            Entry("cidr", "104.16.0.0/13", "flag", "CDN", "cloudflare"),
            Entry("cidr", "104.16.1.0/24", "suppress", "own edge", "org_profile"),
        ]
    )
    verdict = a.check(Observable(T.IPV4, "104.16.1.9"))
    assert verdict.suppressed
    assert set(verdict.reasons) == {"CDN", "own edge"}
    assert len(a) == 2


def test_rawstore_roundtrip_dedup_and_integrity(tmp_path: Path) -> None:
    store = RawStore(tmp_path)
    sha, ref = store.put("cisa_kev", b"payload")
    assert sha == hashlib.sha256(b"payload").hexdigest()
    assert store.put("cisa_kev", b"payload") == (sha, ref)  # same content, same file
    assert store.get(ref, sha) == b"payload"

    (tmp_path / ref).write_bytes(gzip.compress(b"tampered"))
    with pytest.raises(RawStoreError, match="integrity"):
        store.get(ref, sha)


@pytest.mark.parametrize("source", ["../etc", "UPPER", "a/b", ""])
def test_rawstore_rejects_path_tricks(tmp_path: Path, source: str) -> None:
    with pytest.raises(RawStoreError):
        RawStore(tmp_path).put(source, b"x")
    with pytest.raises(RawStoreError):
        RawStore(tmp_path).get("../../outside.gz", "0" * 64)
