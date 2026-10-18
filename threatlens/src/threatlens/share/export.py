"""Indicator exports for firewalls, SIEMs and scripts (ADR 0019).

``/feeds/{token}/indicators/{format}`` serves every *shareable* indicator
(``share.select``: TLP at most the blocking policy's export limit, never RED,
redistributable sources only) scoring at least ``min_score`` (default 60, the
"block" threshold). Like the blocklist feed, it is protected by a feed token
instead of an API key, so a firewall's External Dynamic List can point at it.

Formats:

* ``ip.txt``, ``domain.txt``, ``url.txt``, ``sha256.txt``: one value per line
  (EDL shape; URLs without their scheme, as PAN-OS and FortiGate expect);
* ``indicators.csv`` / ``indicators.json``: value, type, score, TLP, sources;
* ``stix.json``: a STIX 2.1 bundle (same objects the TAXII server serves);
* ``wazuh-ip.cdb``, ``wazuh-domain.cdb``, ``wazuh-url.cdb``: Wazuh CDB lists
  (``key:value``; keys with a colon quoted; CIDRs on an octet boundary become
  Wazuh's dotted prefixes, others are listed address by address up to a /22).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from collections.abc import Iterable
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import blocking
from threatlens.share import select as sel
from threatlens.share import stix

router = APIRouter(include_in_schema=False)
MAX_ROWS = 200_000
RATE_PER_MINUTE = 60
TXT = "text/plain; charset=utf-8"
FORMATS: dict[str, tuple[str, tuple[str, ...]]] = {
    # format -> (media type, indicator types it carries; empty = all)
    "ip.txt": (TXT, ("ipv4-addr", "ipv6-addr", "ipv4-net", "ipv6-net")),
    "domain.txt": (TXT, ("domain-name",)),
    "url.txt": (TXT, ("url",)),
    "sha256.txt": (TXT, ("file-sha256",)),
    "indicators.csv": ("text/csv; charset=utf-8", ()),
    "indicators.json": ("application/json", ()),
    "stix.json": ("application/stix+json;version=2.1", ()),
    "wazuh-ip.cdb": (TXT, ("ipv4-addr", "ipv4-net")),
    "wazuh-domain.cdb": (TXT, ("domain-name",)),
    "wazuh-url.cdb": (TXT, ("url",)),
}


async def rows(s: AsyncSession, rules: sel.Rules) -> list[sel.Row]:
    out: list[sel.Row] = []
    after = None
    while len(out) < MAX_ROWS:
        page = await sel.page(s, rules, after=after, limit=5000)
        if not page:
            break
        out += page
        after = (page[-1].ind.updated_at, page[-1].ind.id)
    return out


def _cdb_key(k: str) -> str:
    return f'"{k}"' if ":" in k else k


def _wazuh_ip_keys(value: str) -> Iterable[str]:
    """Wazuh matches IPs by dotted prefix (``10.1.:`` is 10.1.0.0/16)."""
    net = ipaddress.ip_network(value, strict=False)
    if net.version != 4:
        return []
    if net.prefixlen == 32:
        return [str(net.network_address)]
    if net.prefixlen in (8, 16, 24):
        octets = str(net.network_address).split(".")[: net.prefixlen // 8]
        return [".".join(octets) + "."]
    if net.prefixlen >= 22:
        return [str(a) for a in net]
    return []  # too broad to list, not on an octet boundary: left out


def cdb(rows_: Iterable[sel.Row], kind: str) -> str:
    lines: dict[str, str] = {}
    for r in rows_:
        v = r.obs.value
        verdict = "malicious" if (r.ind.priority_score or 0) >= 60 else "suspicious"
        tag = f"{verdict} score={round(r.ind.priority_score or 0)} tlp={r.ind.tlp.split(':')[1].lower()}"
        keys = _wazuh_ip_keys(v) if kind == "ip" else [v]
        for k in keys:
            lines.setdefault(_cdb_key(k), tag)
    return "".join(f"{k}:{t}\n" for k, t in lines.items())


def flat(r: sel.Row) -> dict[str, object]:
    return {
        "value": r.obs.value,
        "type": r.obs.type,
        "score": round(r.ind.priority_score or 0, 1),
        "tlp": r.ind.tlp,
        "labels": "|".join(r.ind.labels or []),
        "sources": "|".join(sorted(src.name for src in r.sources if src.redistribution)) or "analyst",
        "first_seen": stix.ts(r.obs.first_seen),
        "last_seen": stix.ts(r.obs.last_seen),
        "valid_until": stix.ts(r.ind.valid_until),
    }


async def render(s: AsyncSession, fmt: str, rows_: list[sel.Row], producer: str) -> str:
    if fmt == "url.txt":
        return "".join(f"{r.obs.value.split('://', 1)[-1]}\n" for r in rows_)
    if fmt.endswith(".txt"):
        return "".join(f"{r.obs.value}\n" for r in rows_)
    if fmt.startswith("wazuh-"):
        return cdb(rows_, fmt[6:].split(".")[0])
    if fmt == "indicators.csv":
        from threatlens.argus_api import sheet_safe

        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        head = list(flat(rows_[0]) if rows_ else ["value", "type", "score", "tlp"])
        w.writerow(head)
        for r in rows_:
            w.writerow([sheet_safe(v) for v in flat(r).values()])  # nosemgrep
        return buf.getvalue()
    if fmt == "indicators.json":
        return json.dumps({"count": len(rows_), "indicators": [flat(r) for r in rows_]}, indent=1)
    if fmt == "stix.json":
        return json.dumps(await stix.build(s, rows_, producer), indent=1)
    raise HTTPException(404, "not found")


@router.get("/feeds/{token}/indicators/{fmt}")
async def indicators_feed(
    request: Request,
    token: str,
    fmt: str,
    min_score: Annotated[float, Query(ge=0, le=100)] = 60.0,
) -> Response:
    client = request.client.host if request.client else "unknown"
    if await request.app.state.limiter.hit(f"feed:{client}", RATE_PER_MINUTE):
        raise HTTPException(429, "too many feed pulls; wait a minute")
    spec = FORMATS.get(fmt)
    if spec is None:
        raise HTTPException(404, "not found")
    media, types = spec
    async with request.app.state.sessionmaker() as s, s.begin():
        if await blocking.check_token(s, token) is None:
            raise HTTPException(404, "not found")
        policy = await blocking.get_policy(s)
        rules = sel.Rules(policy["export_max_tlp"], min_score, types, revocations=False)
        body = await render(s, fmt, await rows(s, rules), request.app.state.settings.org_identity)
    return Response(body, media_type=media, headers={"Cache-Control": "no-store"})
