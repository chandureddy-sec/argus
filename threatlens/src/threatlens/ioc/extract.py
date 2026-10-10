"""Extract IOCs from free text (reports, advisories, analyst notes).

Text is refanged first, then scanned in a fixed order: URLs, emails, registry
keys, hashes, CVEs, IPs/networks, file names, domains. Spans already claimed
by an earlier match are masked, so the host inside a URL or an email is not
reported a second time as a bare domain, and a SHA-256 is not also read as a
shorter hash.

File-name extensions that are also top-level domains (``.zip``, ``.mov``,
``.sh``) are read as **file names** in free text; a value that is really a
domain in those TLDs still arrives correctly from a feed that labels its type.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from threatlens.ioc.defang import defang, refang
from threatlens.ioc.normalize import Result, normalize
from threatlens.ioc.types import IOCType, Observable, Rejected

FILE_EXTS = (
    "exe|dll|sys|scr|cpl|ocx|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|lnk|jar|apk|"
    "elf|bin|so|dylib|docx?|docm|xlsx?|xlsm|xlsb|pptx?|pptm|rtf|one|zip|rar|7z|iso|img|vhdx?|"
    "gz|tgz|tar|cab|py|sh"
)
_FILE_EXT_SET = set(FILE_EXTS.replace("?", "").split("|")) | {"doc", "xls", "ppt", "vhd", "docx", "xlsx"}

_PATTERNS: list[tuple[IOCType, re.Pattern[str]]] = [
    (IOCType.URL, re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`{}|\\^]+", re.I)),
    (IOCType.EMAIL, re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")),
    (
        IOCType.REGKEY,
        re.compile(
            r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG"
            r"|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"'<>|]+",
            re.I,
        ),
    ),
    (IOCType.SHA256, re.compile(r"\b[a-fA-F0-9]{64}\b")),
    (IOCType.SHA1, re.compile(r"\b[a-fA-F0-9]{40}\b")),
    (IOCType.MD5, re.compile(r"\b[a-fA-F0-9]{32}\b")),
    (IOCType.CVE, re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    (
        IOCType.IPV4,
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?(?!\.?\d)"
        ),
    ),
    (
        IOCType.IPV6,
        re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![\w:])"),
    ),
    (IOCType.FILENAME, re.compile(rf"(?<![\w/\\.@-])[\w-][\w.-]{{0,120}}\.(?:{FILE_EXTS})\b", re.I)),
    (
        IOCType.DOMAIN,
        re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b", re.I),
    ),
]

_TRAILING = ".,;:!?)]}'\""


def _spans(text: str) -> Iterator[tuple[int, IOCType, str]]:
    masked = list(text)
    for ioc_type, pattern in _PATTERNS:
        for m in pattern.finditer("".join(masked)):
            value = m.group(0)
            if ioc_type == IOCType.URL:
                value = value.rstrip(_TRAILING)
            if ioc_type == IOCType.DOMAIN and value.rsplit(".", 1)[-1].lower() in _FILE_EXT_SET:
                continue  # already considered as a file name
            if ioc_type == IOCType.IPV6 and value.count(":") < 2:
                continue
            start = m.start()
            masked[start : start + len(value)] = " " * len(value)
            yield start, ioc_type, value


def _candidates(text: str) -> Iterator[tuple[IOCType, str]]:
    for _, ioc_type, value in _spans(text):
        yield ioc_type, value


def defang_text(text: str) -> str:
    """Defang every URL, email, IP and domain in free text for display.

    Unlike ``extract`` the text is not refanged first and nothing is
    validated: anything that looks live is made inert, and text that is
    already defanged is left as it is."""
    out: list[str] = []
    pos = 0
    for start, ioc_type, value in sorted(_spans(text), key=lambda s: s[0]):
        out += [text[pos:start], defang(value, ioc_type)]
        pos = start + len(value)
    out.append(text[pos:])
    return "".join(out)


def extract(text: str, *, include_rejected: bool = False) -> list[Result]:
    """Return unique observables in order of first appearance.

    With ``include_rejected``, values that matched a pattern but failed
    validation (private IPs, internal domains, …) are returned too, with the
    reason — useful to show an analyst why something was skipped.
    """
    seen: set[str] = set()
    out: list[Result] = []
    for ioc_type, value in _candidates(refang(text)):
        r = normalize(ioc_type, value)
        if isinstance(r, Observable):
            if r.key not in seen:
                seen.add(r.key)
                out.append(r)
        elif include_rejected and isinstance(r, Rejected):
            out.append(r)
    return out
