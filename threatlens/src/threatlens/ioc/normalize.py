"""Normalization: one canonical spelling per observable, and refusal of values
that can never be useful indicators (bogons, non-public suffixes, empty-file
hashes, …).

Canonical forms:

* IPs: ``ipaddress`` compressed form; networks with host bits cleared.
* Domains: lower-case, IDNA (punycode), no trailing dot, public suffix required.
* URLs: lower-case scheme and host, default port dropped, empty path → ``/``,
  fragment dropped (never sent to a server), query kept as-is.
* Emails: domain normalized like a domain; local part kept (it is
  case-sensitive by RFC 5321, even if most providers ignore case).
* Hashes: lower-case hex. CVEs: upper-case.
* File names and registry keys: case-insensitive on Windows → lower-case key
  with registry hives expanded (``HKLM`` → ``hkey_local_machine``).
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

import tldextract

from threatlens.ioc.defang import refang
from threatlens.ioc.types import IOCType, Observable, Rejected
from threatlens.net.guard import is_public

Result = Observable | Rejected

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HEX = {IOCType.MD5: 32, IOCType.SHA1: 40, IOCType.SHA256: 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# Hashes of the empty file: they appear in feeds and match nothing malicious.
_EMPTY_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
_HIVES = {
    "hklm": "hkey_local_machine",
    "hkcu": "hkey_current_user",
    "hkcr": "hkey_classes_root",
    "hku": "hkey_users",
    "hkcc": "hkey_current_config",
}
_URL_SCHEMES = {"http", "https", "ftp"}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
MAX_URL = 2048


@lru_cache(maxsize=1)
def _psl() -> tldextract.TLDExtract:
    # suffix_list_urls=() → bundled Public Suffix List snapshot; never fetches.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@lru_cache(maxsize=1)
def _psl_private() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def registrable_domain(domain: str) -> str:
    """The domain an organization controls, honouring *private* suffixes:
    ``x.s3.amazonaws.com`` and ``x.github.io`` stay distinct per tenant, so an
    allowlist entry for ``amazonaws.com`` can't hide a malicious bucket."""
    r = _psl_private()(domain)
    return f"{r.domain}.{r.suffix}" if r.domain and r.suffix else domain


def _ip(raw: str, t: IOCType) -> Result:
    try:
        ip = ipaddress.ip_address(raw.strip().strip("[]"))
    except ValueError:
        return Rejected(t, raw, "not an IP address")
    t = IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    if not is_public(ip):
        return Rejected(t, raw, "non-public (bogon/private/reserved) address")
    return Observable(t, ip.compressed)


def _net(raw: str, t: IOCType) -> Result:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        return Rejected(t, raw, "not a CIDR network")
    t = IOCType.IPV4_NET if net.version == 4 else IOCType.IPV6_NET
    if net.num_addresses == 1:
        return _ip(str(net.network_address), t)
    if not net.is_global:
        return Rejected(t, raw, "non-public network")
    return Observable(t, net.compressed)


def _domain(raw: str) -> Result:
    d = raw.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]  # wildcard certificates / feeds: the base name is the indicator
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        return Rejected(IOCType.DOMAIN, raw, "invalid internationalized domain name")
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return Rejected(IOCType.DOMAIN, raw, "not a valid domain name")
    r = _psl()(d)
    if not r.suffix or not r.domain:
        return Rejected(IOCType.DOMAIN, raw, "no public suffix (internal or bare suffix)")
    return Observable(IOCType.DOMAIN, d)


def _url(raw: str) -> Result:
    s = raw.strip()
    if len(s) > MAX_URL:
        return Rejected(IOCType.URL, raw[:100], f"URL longer than {MAX_URL} characters")
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError:
        return Rejected(IOCType.URL, raw, "unparseable URL")
    scheme = parts.scheme.lower()
    if scheme not in _URL_SCHEMES or not parts.hostname:
        return Rejected(IOCType.URL, raw, "not an http(s)/ftp URL with a host")
    host_raw = parts.hostname
    host_obs = _ip(host_raw, IOCType.IPV4) if _looks_like_ip(host_raw) else _domain(host_raw)
    if isinstance(host_obs, Rejected):
        return Rejected(IOCType.URL, raw, f"host: {host_obs.reason}")
    host = f"[{host_obs.value}]" if host_obs.type == IOCType.IPV6 else host_obs.value
    netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    path = parts.path or "/"
    return Observable(IOCType.URL, urlunsplit((scheme, netloc, path, parts.query, "")))


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _email(raw: str) -> Result:
    local, at, domain = raw.strip().rpartition("@")
    if not at or not local or len(local) > 64 or any(c.isspace() for c in local):
        return Rejected(IOCType.EMAIL, raw, "not an email address")
    d = _domain(domain)
    if isinstance(d, Rejected):
        return Rejected(IOCType.EMAIL, raw, f"domain: {d.reason}")
    return Observable(IOCType.EMAIL, f"{local}@{d.value}")


def _hash(raw: str, t: IOCType) -> Result:
    h = raw.strip().lower()
    if len(h) != _HEX[t] or not _HEX_RE.match(h):
        return Rejected(t, raw, f"not a {_HEX[t]}-character hex digest")
    if h in _EMPTY_HASHES or len(set(h)) == 1:
        return Rejected(t, raw, "placeholder or empty-file hash")
    return Observable(t, h)


def _cve(raw: str) -> Result:
    c = raw.strip().upper()
    return Observable(IOCType.CVE, c) if _CVE_RE.match(c) else Rejected(IOCType.CVE, raw, "not a CVE ID")


def _filename(raw: str) -> Result:
    f = raw.strip().strip("\"'")
    if not f or "/" in f or "\\" in f or len(f) > 255 or "." not in f.strip("."):
        return Rejected(IOCType.FILENAME, raw, "not a bare file name with an extension")
    return Observable(IOCType.FILENAME, f.lower())


def _regkey(raw: str) -> Result:
    k = raw.strip().strip("\"'").replace("/", "\\").rstrip("\\")
    hive, sep, rest = k.partition("\\")
    hive_l = _HIVES.get(hive.lower(), hive.lower())
    if hive_l not in _HIVES.values() or not sep or not rest:
        return Rejected(IOCType.REGKEY, raw, "not a registry key under a known hive")
    return Observable(IOCType.REGKEY, f"{hive_l}\\{rest.lower()}")


def normalize(ioc_type: IOCType, raw: str) -> Result:
    """Normalize a value whose type is known (feeds usually say)."""
    raw = refang(raw)
    match ioc_type:
        case IOCType.IPV4 | IOCType.IPV6:
            return _net(raw, ioc_type) if "/" in raw else _ip(raw, ioc_type)
        case IOCType.IPV4_NET | IOCType.IPV6_NET:
            return _net(raw, ioc_type)
        case IOCType.DOMAIN:
            return _domain(raw)
        case IOCType.URL:
            return _url(raw)
        case IOCType.EMAIL:
            return _email(raw)
        case IOCType.MD5 | IOCType.SHA1 | IOCType.SHA256:
            return _hash(raw, ioc_type)
        case IOCType.CVE:
            return _cve(raw)
        case IOCType.FILENAME:
            return _filename(raw)
        case IOCType.REGKEY:
            return _regkey(raw)


_BY_LEN = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}


def guess(raw: str) -> Result:
    """Normalize a single value of unknown type (e.g. a pasted IOC)."""
    v = refang(raw).strip()
    lv = v.lower()
    if "://" in v:
        return _url(v)
    if lv.startswith("cve-"):
        return _cve(v)
    if lv.split("\\", 1)[0] in _HIVES or lv.startswith("hkey_"):
        return _regkey(v)
    if len(v) in _BY_LEN and _HEX_RE.match(lv):
        return _hash(v, _BY_LEN[len(v)])
    if "@" in v:
        return _email(v)
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        pass
    else:
        return _net(v, IOCType.IPV4_NET) if "/" in v else _ip(v, IOCType.IPV4)
    return _domain(v)
