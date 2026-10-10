from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from threatlens.ioc.defang import defang, refang
from threatlens.ioc.extract import defang_text, extract
from threatlens.ioc.normalize import guess, normalize, registrable_domain
from threatlens.ioc.types import IOCType, Observable, Rejected

T = IOCType


def ok(t: IOCType, raw: str) -> str:
    r = normalize(t, raw)
    assert isinstance(r, Observable), r
    return r.value


def bad(t: IOCType, raw: str) -> str:
    r = normalize(t, raw)
    assert isinstance(r, Rejected), r
    return r.reason


# ── normalization ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("t", "raw", "want"),
    [
        (T.IPV4, " 45.137.21.9 ", "45.137.21.9"),
        (T.IPV6, "2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"),
        (T.IPV4_NET, "1.10.16.7/20", "1.10.16.0/20"),  # host bits cleared
        (T.IPV4, "8.8.8.8/32", "8.8.8.8"),  # /32 is a single address
        (T.DOMAIN, "Evil-Update.COM.", "evil-update.com"),
        (T.DOMAIN, "*.evil.net", "evil.net"),
        (T.DOMAIN, "пример.рф", "xn--e1afmkfd.xn--p1ai"),
        (T.URL, "HTTPS://Evil.com:443", "https://evil.com/"),
        (T.URL, "http://evil.com:8080/a?b=1#frag", "http://evil.com:8080/a?b=1"),
        (T.URL, "http://[2001:4860:4860::8888]/x", "http://[2001:4860:4860::8888]/x"),
        (T.URL, "hxxp://evil[.]com/x", "http://evil.com/x"),
        (T.EMAIL, "Bob@Bad-Mail.RU", "Bob@bad-mail.ru"),
        (T.MD5, "9E107D9D372BB6826BD81D3542A419D6", "9e107d9d372bb6826bd81d3542a419d6"),
        (T.CVE, "cve-2024-3400", "CVE-2024-3400"),
        (T.FILENAME, '"Invoice.EXE"', "invoice.exe"),
        (T.REGKEY, "HKLM\\Software\\Run\\", r"hkey_local_machine\software\run"),
    ],
)
def test_normalize(t: IOCType, raw: str, want: str) -> None:
    assert ok(t, raw) == want


@pytest.mark.parametrize(
    ("t", "raw", "reason"),
    [
        (T.IPV4, "10.1.2.3", "non-public"),
        (T.IPV4, "169.254.169.254", "non-public"),
        (T.IPV4, "999.1.1.1", "not an IP"),
        (T.IPV4_NET, "192.168.0.0/16", "non-public network"),
        (T.DOMAIN, "corp.local", "no public suffix"),
        (T.DOMAIN, "localhost", "not a valid domain"),
        (T.DOMAIN, "-bad-.com", "not a valid domain"),
        (T.DOMAIN, "com", "not a valid domain"),
        (T.URL, "javascript:alert(1)", "not an http"),
        (T.URL, "http://10.0.0.1/admin", "host: non-public"),
        (T.URL, "http://" + "a" * 2050 + ".com/", "longer than"),
        (T.EMAIL, "user@intranet.local", "domain:"),
        (T.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty-file"),
        (T.MD5, "0" * 32, "placeholder"),
        (T.SHA1, "xyz", "hex digest"),
        (T.CVE, "CVE-24-1", "not a CVE"),
        (T.FILENAME, r"C:\Windows\evil.exe", "bare file name"),
        (T.REGKEY, r"HKXX\Software", "known hive"),
    ],
)
def test_normalize_rejects(t: IOCType, raw: str, reason: str) -> None:
    assert reason in bad(t, raw)


def test_guess() -> None:
    cases = {
        "hxxps://evil[.]com": (T.URL, "https://evil.com/"),
        "CVE-2021-44228": (T.CVE, "CVE-2021-44228"),
        "1.10.16.0/20": (T.IPV4_NET, "1.10.16.0/20"),
        "2606:4700::1111": (T.IPV6, "2606:4700::1111"),
        "a" * 40: (T.SHA1, "a" * 40),  # single repeated char → rejected below
        "bad@evil.ru": (T.EMAIL, "bad@evil.ru"),
        "HKCU\\Run": (T.REGKEY, "hkey_current_user\\run"),
        "evil[.]com": (T.DOMAIN, "evil.com"),
    }
    for raw, (t, value) in cases.items():
        r = guess(raw)
        if raw == "a" * 40:
            assert isinstance(r, Rejected)
            continue
        assert r == Observable(t, value), raw


def test_registrable_domain_honours_private_suffixes() -> None:
    assert registrable_domain("login.microsoft.com") == "microsoft.com"
    assert registrable_domain("evil.s3.amazonaws.com") == "evil.s3.amazonaws.com"
    assert registrable_domain("x.y.github.io") == "y.github.io"


# ── defang ───────────────────────────────────────────────────────────────────


def test_defang_examples() -> None:
    assert defang("https://evil.com/a.php", T.URL) == "hxxps[://]evil[.]com/a.php"
    assert defang("evil.com", T.DOMAIN) == "evil[.]com"
    assert defang("bob@evil.com", T.EMAIL) == "bob[@]evil[.]com"
    assert defang("2001:db8::1", T.IPV6) == "2001[:]db8[:][:]1"
    assert refang("hxxps[://]evil[.]com") == "https://evil.com"
    assert refang("evil(dot)com and bob[at]x[.]org") == "evil.com and bob@x.org"


_domains = st.from_regex(
    r"[a-z][a-z0-9]{0,10}(\.[a-z][a-z0-9]{0,10}){0,2}\.(com|net|org|ru|io)", fullmatch=True
)


@given(_domains)
def test_defang_roundtrip_domains(d: str) -> None:
    assert refang(defang(d, T.DOMAIN)) == d


@given(
    _domains, st.from_regex(r"(/[a-z0-9._-]{0,8}){0,3}", fullmatch=True), st.sampled_from(["http", "https"])
)
def test_defang_roundtrip_urls(d: str, path: str, scheme: str) -> None:
    url = f"{scheme}://{d}{path or '/'}"
    assert refang(defang(url, T.URL)) == url
    # Defanged form never contains a live scheme or dotted host.
    assert "://" not in defang(url, T.URL).replace("[://]", "")


@given(st.ip_addresses())
def test_ip_normalization_idempotent(ip: object) -> None:
    r = normalize(T.IPV4, str(ip))
    if isinstance(r, Observable):
        assert normalize(r.type, r.value) == r
        assert refang(defang(r.value, r.type)) == r.value


@given(_domains)
def test_domain_normalization_idempotent(d: str) -> None:
    r = normalize(T.DOMAIN, d)
    if isinstance(r, Observable):
        assert normalize(T.DOMAIN, r.value) == r


# ── extraction ───────────────────────────────────────────────────────────────

REPORT = r"""C2 at hxxps://evil-update[.]com/gate.php?id=1 and 45.137.21[.]9:443; internal 10.0.0.5.
Dropper invoice_0423.exe SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.
Mail phish@bad-mail.ru. Exploits CVE-2024-3400. Run key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\upd
IPv6 2001:4860:4860::8888. Lookalike login-microsoftonline.co, internal corp.local, net 1.10.16.0/20.
Version 1.2.3.4.5 and time 12:30:45 are not indicators."""


def test_extract_report() -> None:
    got = {(o.type, o.value) for o in extract(REPORT) if isinstance(o, Observable)}
    assert got == {
        (T.URL, "https://evil-update.com/gate.php?id=1"),
        (T.IPV4, "45.137.21.9"),
        (T.FILENAME, "invoice_0423.exe"),
        (T.SHA256, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        (T.EMAIL, "phish@bad-mail.ru"),
        (T.CVE, "CVE-2024-3400"),
        (T.REGKEY, r"hkey_current_user\software\microsoft\windows\currentversion\run\upd"),
        (T.IPV6, "2001:4860:4860::8888"),
        (T.DOMAIN, "login-microsoftonline.co"),
        (T.IPV4_NET, "1.10.16.0/20"),
    }


def test_extract_reports_rejections_on_request() -> None:
    rejected = [r for r in extract(REPORT, include_rejected=True) if isinstance(r, Rejected)]
    assert {r.raw for r in rejected} >= {"10.0.0.5", "corp.local"}
    assert all(r.reason for r in rejected)


def test_extract_dedups_and_masks() -> None:
    out = extract("evil.com evil.com http://evil.com/x bob@evil.com")
    keys = [o.key for o in out if isinstance(o, Observable)]
    # The domain appears once; the URL host and email domain aren't re-reported.
    assert keys == ["url|http://evil.com/x", "email-addr|bob@evil.com", "domain-name|evil.com"]


@settings(max_examples=300)
@given(st.text(max_size=500))
def test_extract_never_crashes(text: str) -> None:
    for r in extract(text, include_rejected=True):
        assert isinstance(r, Observable | Rejected)


@settings(max_examples=200)
@given(
    st.lists(
        st.sampled_from(["hxxp://", "[.]", "evil", "com", " ", "/", "1.2.3.4", "@", ":", "CVE-2024-0001"])
    )
)
def test_extract_never_crashes_on_ioc_like_noise(parts: list[str]) -> None:
    extract("".join(parts), include_rejected=True)


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("[ipv4-addr:value = '162.243.103.246']", "[ipv4-addr:value = '162[.]243[.]103[.]246']"),
        (
            "[url:value = 'https://evil.example.com/a.exe']",
            "[url:value = 'hxxps[://]evil[.]example[.]com/a.exe']",
        ),
        ("from bob@evil.com via 2001:db8::1", "from bob[@]evil[.]com via 2001[:]db8[:][:]1"),
        ("drops a.exe, CVE-2024-1234, d41d8cd98f00b204e9800998ecf8427e", None),  # inert: unchanged
        ("already evil[.]com and hxxp[://]x[.]org", None),
        ("", None),
    ],
)
def test_defang_text_for_display(text: str, shown: str | None) -> None:
    assert defang_text(text) == (text if shown is None else shown)
