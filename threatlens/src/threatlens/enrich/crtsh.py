"""crt.sh: certificates logged for a domain in Certificate Transparency.

Useful for age ("first certificate issued two days ago") and for names that
share certificates. crt.sh is a free community service run by Sectigo: slow
for large domains and often briefly unavailable, so it gets a longer timeout
and failures are reported, never fatal.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from threatlens.enrich.base import Enricher, EnricherInfo, EnrichError, Evidence, Outcome, load_json, register
from threatlens.ioc.types import IOCType
from threatlens.net.http import SafeHttp

URL = "https://crt.sh/"
NEW_CERT_DAYS = 14
MAX_NAMES = 100


def _dt(v: object) -> datetime | None:
    if not isinstance(v, str) or not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


@register
class CrtSh(Enricher):
    info = EnricherInfo(
        name="crtsh",
        title="crt.sh (Certificate Transparency)",
        homepage="https://crt.sh/",
        applies_to=frozenset({IOCType.DOMAIN}),
        mode="passive",
        third_party=True,
        discloses=False,
        reliability="A",
        reliability_note="Public CT log entries: complete for publicly trusted certificates.",
        license="No terms published; CT log data is public by design",
        license_url="https://crt.sh/",
        commercial_use=True,
        redistribution=False,
        upstream="ct-logs",
        ttl=timedelta(hours=24),
        negative_ttl=timedelta(hours=24),
        verified="2026-10-10 (service returned 502 during the check; format from earlier use)",
        concurrency=1,
        timeout_s=30.0,
    )

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        res = await http.get(URL, params={"q": value, "output": "json"}, max_bytes=20 * 1024 * 1024)
        doc = load_json(res, "crt.sh")
        if not isinstance(doc, list):
            raise EnrichError("crt.sh: expected a JSON list")
        query = f"{URL}?q={value}&output=json"
        rows: list[dict[str, Any]] = [r for r in doc if isinstance(r, dict)]
        if not rows:
            return Outcome(
                "not_found",
                {"certificates": 0},
                [Evidence("crtsh", "info", 0, "No certificates in CT logs")],
                query=query,
                http_status=res.status,
            )
        names: set[str] = set()
        issuers: dict[str, int] = {}
        for r in rows:
            for n in str(r.get("name_value") or "").splitlines():
                names.add(n.strip().lower())
            issuer = str(r.get("issuer_name") or "")
            org = next((p.split("=", 1)[1] for p in issuer.split(", ") if p.startswith("O=")), issuer)
            issuers[org] = issuers.get(org, 0) + 1
        starts = sorted(d for d in (_dt(r.get("not_before")) for r in rows) if d)
        first, latest = (starts[0], starts[-1]) if starts else (None, None)
        summary = {
            "certificates": len(rows),
            "first_issued": first.isoformat() if first else None,
            "latest_issued": latest.isoformat() if latest else None,
            "issuers": dict(sorted(issuers.items(), key=lambda kv: -kv[1])[:5]),
            "names": sorted(names)[:MAX_NAMES],
            "names_total": len(names),
        }
        ref = f"https://crt.sh/?q={value}"
        ev = []
        age = (datetime.now(UTC) - first).days if first else None
        if age is not None and age < NEW_CERT_DAYS:
            ev.append(Evidence("crtsh", "suspicious", 20, f"First certificate issued {age} days ago", ref))
        ev.append(
            Evidence(
                "crtsh",
                "info",
                0,
                f"{len(rows)} certificates since {first.date() if first else '?'}, "
                f"covering {len(names)} names",
                ref,
            )
        )
        # The full list is large and public; keep the summary, not the raw rows.
        return Outcome("ok", summary, ev, raw=None, query=query, http_status=res.status)
