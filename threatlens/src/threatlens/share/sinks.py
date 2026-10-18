"""Integration drivers (ADR 0019): how each kind of destination is configured,
what it receives and how it is called. Request shapes follow each vendor's
current documentation (verified 2026-10-18, see docs/INTEGRATIONS.md):

* **Splunk HEC**: ``POST {url}/services/collector/event``, ``Authorization:
  Splunk <token>``, events concatenated in one body.
* **Elastic / OpenSearch**: ``POST {url}/_bulk`` (NDJSON), ECS
  ``threat.indicator.*`` documents keyed by the STIX id (re-sends update).
* **Microsoft Sentinel**: Entra ID client-credentials token (scope
  ``https://management.azure.com/.default``), then the STIX objects upload API
  ``api.ti.sentinel.azure.com/workspaces/{id}/threat-intelligence-stix-objects:upload``
  (api-version 2024-02-01-preview, at most 100 objects per request).
* **MISP**: ``POST {url}/events/add`` with ``Authorization: <key>``: one event
  per TLP level per run, attributes ``to_ids``.
* **Webhook**: ``POST`` JSON to any URL (both indicators and alerts).
* **Slack** incoming webhook, **Teams** Workflows webhook (Adaptive Card),
  **Telegram** Bot API ``sendMessage``, **email** over SMTP (STARTTLS).

SIEMs receive real (refanged) values: they must match log fields. People
(chat, email) receive defanged values, so nothing becomes a live link.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any, Literal
from urllib.parse import urlsplit

from threatlens.ioc.extract import defang_text
from threatlens.net.http import FetchError, SafeHttp, make_transport
from threatlens.settings import Settings
from threatlens.share import stix
from threatlens.share.select import Row

Role = Literal["indicators", "alerts", "both"]


class IntegrationError(ValueError):
    """A refused configuration or a failed delivery, in words an admin can act on."""


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    required: bool = True
    kind: Literal["text", "url", "int", "bool", "list", "password"] = "text"
    hint: str = ""
    default: Any = None


@dataclass(frozen=True)
class KindSpec:
    title: str
    role: Role
    config: tuple[FieldSpec, ...]
    secret: tuple[FieldSpec, ...] = ()
    batch: int = 500
    docs: str = ""


KINDS: dict[str, KindSpec] = {
    "splunk_hec": KindSpec(
        "Splunk (HTTP Event Collector)",
        "indicators",
        (
            FieldSpec("url", "HEC base URL", kind="url", hint="https://splunk.example.com:8088"),
            FieldSpec("index", "Index", required=False, hint="empty: the token's default index"),
            FieldSpec("sourcetype", "Sourcetype", required=False, default="argus:indicator"),
        ),
        (FieldSpec("token", "HEC token", kind="password"),),
        docs="https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data",
    ),
    "elastic": KindSpec(
        "Elastic / OpenSearch",
        "indicators",
        (
            FieldSpec("url", "Cluster URL", kind="url", hint="https://es.example.com:9200"),
            FieldSpec("index", "Index", required=False, default="argus-indicators"),
        ),
        (
            FieldSpec(
                "api_key", "API key (encoded)", required=False, kind="password", hint="or user + password"
            ),
            FieldSpec("username", "User", required=False),
            FieldSpec("password", "Password", required=False, kind="password"),
        ),
        docs="https://www.elastic.co/docs/reference/ecs/ecs-threat",
    ),
    "sentinel": KindSpec(
        "Microsoft Sentinel (STIX upload API)",
        "indicators",
        (
            FieldSpec("tenant_id", "Entra tenant id"),
            FieldSpec("client_id", "App (client) id"),
            FieldSpec("workspace_id", "Log Analytics workspace id"),
        ),
        (FieldSpec("client_secret", "Client secret", kind="password"),),
        batch=100,
        docs="https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api",
    ),
    "misp": KindSpec(
        "MISP (push events)",
        "indicators",
        (
            FieldSpec("url", "MISP URL", kind="url", hint="https://misp.example.org"),
            FieldSpec(
                "distribution", "Distribution (0 your org … 3 all)", required=False, kind="int", default=0
            ),
            FieldSpec("publish", "Publish the events", required=False, kind="bool", default=False),
        ),
        (FieldSpec("key", "Automation key", kind="password"),),
        batch=2000,
        docs="https://www.misp-project.org/openapi/",
    ),
    "webhook": KindSpec(
        "Webhook (JSON POST)",
        "both",
        (
            FieldSpec("url", "URL", kind="url"),
            FieldSpec("header_name", "Auth header", required=False, hint="e.g. X-Token"),
        ),
        (FieldSpec("header_value", "Auth header value", required=False, kind="password"),),
    ),
    "slack": KindSpec(
        "Slack (incoming webhook)",
        "alerts",
        (),
        (
            FieldSpec(
                "webhook_url", "Webhook URL", kind="password", hint="https://hooks.slack.com/services/…"
            ),
        ),
    ),
    "teams": KindSpec(
        "Microsoft Teams (Workflows webhook)",
        "alerts",
        (),
        (FieldSpec("webhook_url", "Workflow URL", kind="password"),),
    ),
    "telegram": KindSpec(
        "Telegram (bot)",
        "alerts",
        (FieldSpec("chat_id", "Chat id", hint="e.g. -1001234567890"),),
        (FieldSpec("bot_token", "Bot token", kind="password"),),
    ),
    "email": KindSpec(
        "Email (SMTP)",
        "alerts",
        (
            FieldSpec("host", "SMTP host"),
            FieldSpec("port", "Port", required=False, kind="int", default=587),
            FieldSpec("starttls", "STARTTLS", required=False, kind="bool", default=True),
            FieldSpec("sender", "From"),
            FieldSpec("to", "To (comma separated)", kind="list"),
        ),
        (
            FieldSpec("username", "User", required=False),
            FieldSpec("password", "Password", required=False, kind="password"),
        ),
    ),
}

SENTINEL_API = "2024-02-01-preview"
SENTINEL_SCOPE = "https://management.azure.com/.default"
MISP_TYPE = {
    "ipv4-addr": "ip-dst",
    "ipv6-addr": "ip-dst",
    "ipv4-net": "ip-dst",
    "ipv6-net": "ip-dst",
    "domain-name": "domain",
    "url": "url",
    "email-addr": "email-src",
    "file-md5": "md5",
    "file-sha1": "sha1",
    "file-sha256": "sha256",
}
ECS_TYPE = {
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "ipv4-net": "ipv4-addr",
    "ipv6-net": "ipv6-addr",
    "domain-name": "domain-name",
    "url": "url",
    "email-addr": "email-addr",
    "file-md5": "file",
    "file-sha1": "file",
    "file-sha256": "file",
}


def _check_url(v: str, label: str) -> str:
    parts = urlsplit(v.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise IntegrationError(f"{label}: a full http(s):// address")
    if parts.username or parts.password:
        raise IntegrationError(f"{label}: put credentials in the secret fields, not in the URL")
    return v.strip().rstrip("/")


def validate(
    kind: str, config: dict[str, Any], secret: dict[str, Any], *, partial_secret: bool = False
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Normalised (config, secret) for ``kind``. With ``partial_secret`` (an
    edit), missing secret fields keep their stored values (the caller merges)."""
    spec = KINDS.get(kind)
    if spec is None:
        raise IntegrationError("unknown integration kind")
    out: dict[str, Any] = {}
    for f in spec.config:
        v = config.get(f.name, f.default)
        if v in (None, "") and f.required:
            raise IntegrationError(f"{f.label}: required")
        if v in (None, ""):
            if f.default is not None:
                out[f.name] = f.default
            continue
        if f.kind == "url":
            v = _check_url(str(v), f.label)
        elif f.kind == "int":
            try:
                v = int(v)
            except (TypeError, ValueError) as e:
                raise IntegrationError(f"{f.label}: a number") from e
        elif f.kind == "bool":
            v = v in (True, "true", "on", "1", 1)
        elif f.kind == "list":
            v = [x.strip() for x in (v if isinstance(v, list) else str(v).split(",")) if x.strip()][:20]
        else:
            v = str(v).strip()[:500]
        out[f.name] = v
    sec: dict[str, Any] = {}
    for f in spec.secret:
        v = str(secret.get(f.name) or "").strip()
        if any(c in v for c in "\r\n") or len(v) > 4000:
            raise IntegrationError(f"{f.label}: one line, at most 4000 characters")
        if not v:
            if f.required and not partial_secret:
                raise IntegrationError(f"{f.label}: required")
            continue
        if f.name == "webhook_url":
            v = _check_url(v, f.label)
        sec[f.name] = v
    if kind == "misp" and not 0 <= int(out.get("distribution", 0)) <= 3:
        raise IntegrationError("Distribution: 0 to 3")
    return out, sec


def http_for(allow_internal: bool, settings: Settings, *, retries: int = 1) -> SafeHttp:
    """The client for one integration: the SSRF guard, plus the internal
    network when an admin allowed it (never link-local or cloud metadata)."""
    transport = make_transport(
        internal=allow_internal, loopback=allow_internal and settings.allow_loopback_destinations
    )
    return SafeHttp(transport=transport, allow_http=allow_internal, retries=retries, timeout=30.0)


def _redact(e: Exception, *secrets: str) -> str:
    msg = str(e)
    for sv in secrets:
        if sv:
            msg = msg.replace(sv, "***")
    return msg[:500]


# ── indicator payloads ───────────────────────────────────────────────────────


def _epoch(v: datetime | None) -> float:
    if v is None:
        return datetime.now(UTC).timestamp()
    return (v if v.tzinfo else v.replace(tzinfo=UTC)).timestamp()


def flat(r: Row, producer: str) -> dict[str, Any]:
    return {
        "value": r.obs.value,
        "type": r.obs.type,
        "score": round(r.ind.priority_score or 0, 1),
        "verdict": "revoked"
        if r.ind.status == "false_positive"
        else "malicious"
        if (r.ind.priority_score or 0) >= 60
        else "suspicious",
        "tlp": r.ind.tlp,
        "labels": list(r.ind.labels or []),
        "sources": sorted(s.name for s in r.sources if s.redistribution) or ["analyst"],
        "first_seen": stix.ts(r.obs.first_seen),
        "last_seen": stix.ts(r.obs.last_seen),
        "valid_until": stix.ts(r.ind.valid_until),
        "stix_id": r.ind.stix_id,
        "producer": producer,
    }


def ecs(r: Row, producer: str) -> dict[str, Any]:
    t = r.obs.type
    ind: dict[str, Any] = {
        "type": ECS_TYPE.get(t, t),
        "confidence": "High" if (r.ind.priority_score or 0) >= 60 else "Medium",
        "marking": {"tlp": r.ind.tlp.split(":", 1)[1], "tlp_version": "2.0"},
        "first_seen": stix.ts(r.obs.first_seen),
        "last_seen": stix.ts(r.obs.last_seen),
        "provider": ",".join(sorted(s.name for s in r.sources if s.redistribution)) or "analyst",
        "description": f"Argus priority {round(r.ind.priority_score or 0)}/100",
    }
    v = r.obs.value
    if t in ("ipv4-addr", "ipv6-addr"):
        ind["ip"] = v
    elif t in ("ipv4-net", "ipv6-net"):
        ind["ip"] = v.split("/")[0]
    elif t == "domain-name":
        ind["url"] = {"domain": v}
    elif t == "url":
        ind["url"] = {"full": v, "original": v}
    elif t == "email-addr":
        ind["email"] = {"address": v}
    elif t.startswith("file-"):
        ind["file"] = {"hash": {t.split("-", 1)[1]: v}}
    return {
        "@timestamp": stix.ts(r.ind.updated_at),
        "event": {
            "kind": "enrichment",
            "category": ["threat"],
            "type": ["indicator"],
            "dataset": "argus.indicators",
        },
        "threat": {"indicator": ind, "feed": {"name": producer}},
        "labels": {"argus_score": str(round(r.ind.priority_score or 0)), "argus_status": r.ind.status},
        "tags": list(r.ind.labels or [])[:20],
    }


@dataclass
class Sent:
    sent: int = 0
    held_back: int = 0
    detail: dict[str, Any] = field(default_factory=dict)


async def send_indicators(
    http: SafeHttp,
    kind: str,
    config: dict[str, Any],
    secret: dict[str, Any],
    rows: Sequence[Row],
    objects: Sequence[dict[str, Any]],
    producer: str,
) -> Sent:
    """Deliver one batch. ``objects`` are the STIX objects for ``rows`` (Sentinel)."""
    if not rows:
        return Sent()
    if kind == "splunk_hec":
        events = []
        for r in rows:
            e: dict[str, Any] = {
                "time": _epoch(r.ind.updated_at),
                "source": "argus",
                "sourcetype": config.get("sourcetype") or "argus:indicator",
                "event": flat(r, producer),
            }
            if config.get("index"):
                e["index"] = config["index"]
            events.append(json.dumps(e, separators=(",", ":")))
        await http.request(
            "POST",
            f"{config['url']}/services/collector/event",
            content="\n".join(events).encode(),
            headers={"Authorization": f"Splunk {secret['token']}", "Content-Type": "application/json"},
        )
        return Sent(len(rows))
    if kind == "elastic":
        index = config.get("index") or "argus-indicators"
        lines: list[str] = []
        for r in rows:
            lines.append(json.dumps({"index": {"_index": index, "_id": r.ind.stix_id}}))
            lines.append(json.dumps(ecs(r, producer), separators=(",", ":")))
        headers = {"Content-Type": "application/x-ndjson"}
        if secret.get("api_key"):
            headers["Authorization"] = f"ApiKey {secret['api_key']}"
        elif secret.get("username"):
            import base64

            cred = base64.b64encode(f"{secret['username']}:{secret.get('password', '')}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        res = await http.request(
            "POST", f"{config['url']}/_bulk", content=("\n".join(lines) + "\n").encode(), headers=headers
        )
        body = json.loads(res.body or b"{}")
        failed = sum(1 for it in body.get("items", []) if (it.get("index") or {}).get("status", 200) >= 300)
        return Sent(len(rows) - failed, detail={"failed": failed} if failed else {})
    if kind == "sentinel":
        token = await sentinel_token(http, config, secret)
        res = await http.post_json(
            f"https://api.ti.sentinel.azure.com/workspaces/{config['workspace_id']}"
            f"/threat-intelligence-stix-objects:upload?api-version={SENTINEL_API}",
            {"sourcesystem": producer, "stixobjects": list(objects)},
            headers={"Authorization": f"Bearer {token}"},
        )
        errors = (json.loads(res.body or b"{}") or {}).get("errors") or []
        return Sent(len(objects) - len(errors), detail={"errors": errors[:10]} if errors else {})
    if kind == "misp":
        return await misp_push(http, config, secret, rows, producer)
    if kind == "webhook":
        headers = {}
        if config.get("header_name") and secret.get("header_value"):
            headers[config["header_name"]] = secret["header_value"]
        await http.post_json(
            config["url"],
            {"source": producer, "kind": "indicators", "indicators": [flat(r, producer) for r in rows]},
            headers=headers,
        )
        return Sent(len(rows))
    raise IntegrationError(f"{kind} does not receive indicators")


async def sentinel_token(http: SafeHttp, config: dict[str, Any], secret: dict[str, Any]) -> str:
    res = await http.post_form(
        f"https://login.microsoftonline.com/{config['tenant_id']}/oauth2/v2.0/token",
        {
            "grant_type": "client_credentials",
            "client_id": config["client_id"],
            "client_secret": secret["client_secret"],
            "scope": SENTINEL_SCOPE,
        },
    )
    token = (json.loads(res.body or b"{}") or {}).get("access_token")
    if not token:
        raise IntegrationError("Entra ID returned no access token")
    return str(token)


async def misp_push(
    http: SafeHttp, config: dict[str, Any], secret: dict[str, Any], rows: Sequence[Row], producer: str
) -> Sent:
    """One event per TLP level; revoked (false positive) indicators are not pushed."""
    by_tlp: dict[str, list[Row]] = {}
    held = 0
    for r in rows:
        if r.ind.status == "false_positive" or r.obs.type not in MISP_TYPE:
            held += 1
            continue
        by_tlp.setdefault(r.ind.tlp, []).append(r)
    sent = 0
    events = []
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    for tlp, group in by_tlp.items():
        attrs = [
            {
                "type": MISP_TYPE[r.obs.type],
                "value": r.obs.value,
                "to_ids": True,
                "category": "Payload delivery" if r.obs.type.startswith("file-") else "Network activity",
                "comment": f"Argus priority {round(r.ind.priority_score or 0)}/100; "
                f"sources: {', '.join(sorted(s.name for s in r.sources if s.redistribution)) or 'analyst'}",
            }
            for r in group
        ]
        event = {
            "Event": {
                "info": f"{producer} indicators {today} ({tlp})",
                "distribution": int(config.get("distribution", 0)),
                "threat_level_id": 2,
                "analysis": 2,
                "published": bool(config.get("publish", False)),
                "Tag": [{"name": tlp.lower()}],
                "Attribute": attrs,
            }
        }
        res = await http.post_json(
            f"{config['url']}/events/add",
            event,
            headers={"Authorization": secret["key"], "Accept": "application/json"},
        )
        doc = json.loads(res.body or b"{}")
        events.append(str((doc.get("Event") or {}).get("id", "?")))
        sent += len(group)
    return Sent(sent, held, {"events": events})


# ── alerts ───────────────────────────────────────────────────────────────────


@dataclass
class Alert:
    title: str
    lines: list[str]
    link: str | None
    tlp: str
    rule: str


def _text(a: Alert) -> str:
    body = "\n".join(defang_text(x) for x in a.lines)
    return f"{a.tlp} · {defang_text(a.title)}\n{body}" + (f"\n{a.link}" if a.link else "")


async def send_alert(
    http: SafeHttp, kind: str, config: dict[str, Any], secret: dict[str, Any], a: Alert
) -> None:
    try:
        if kind == "slack":
            lines = "\n".join(f"• {defang_text(x)}" for x in a.lines)
            text = f"*{a.tlp}* · *{defang_text(a.title)}*\n{lines}" + (
                f"\n<{a.link}|Open in Argus>" if a.link else ""
            )
            await http.post_json(secret["webhook_url"], {"text": text, "unfurl_links": False})
        elif kind == "teams":
            body: list[dict[str, Any]] = [
                {
                    "type": "TextBlock",
                    "text": a.tlp,
                    "size": "Small",
                    "weight": "Bolder",
                    "color": "Attention",
                },
                {"type": "TextBlock", "text": defang_text(a.title), "weight": "Bolder", "wrap": True},
                *(
                    {"type": "TextBlock", "text": defang_text(x), "wrap": True, "spacing": "None"}
                    for x in a.lines
                ),
            ]
            card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
                "actions": [{"type": "Action.OpenUrl", "title": "Open in Argus", "url": a.link}]
                if a.link
                else [],
            }
            await http.post_json(
                secret["webhook_url"],
                {
                    "type": "message",
                    "attachments": [
                        {
                            "contentType": "application/vnd.microsoft.card.adaptive",
                            "contentUrl": None,
                            "content": card,
                        }
                    ],
                },
            )
        elif kind == "telegram":
            await http.post_json(
                f"https://api.telegram.org/bot{secret['bot_token']}/sendMessage",
                {"chat_id": config["chat_id"], "text": _text(a)[:4000], "disable_web_page_preview": True},
            )
        elif kind == "webhook":
            headers = {}
            if config.get("header_name") and secret.get("header_value"):
                headers[config["header_name"]] = secret["header_value"]
            await http.post_json(
                config["url"],
                {
                    "kind": "alert",
                    "rule": a.rule,
                    "title": defang_text(a.title),
                    "lines": [defang_text(x) for x in a.lines],
                    "tlp": a.tlp,
                    "link": a.link,
                },
                headers=headers,
            )
        elif kind == "email":
            await asyncio.to_thread(_smtp_send, config, secret, a)
        else:
            raise IntegrationError(f"{kind} does not receive alerts")
    except FetchError as e:
        raise IntegrationError(_redact(e, *secret.values())) from e


def _smtp_send(config: dict[str, Any], secret: dict[str, Any], a: Alert) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[{a.tlp}] {defang_text(a.title)}"[:200]
    msg["From"] = config["sender"]
    msg["To"] = ", ".join(config["to"])
    msg.set_content(_text(a))
    port = int(config.get("port") or 587)
    try:
        with smtplib.SMTP(config["host"], port, timeout=20) as smtp:
            if config.get("starttls", True):
                smtp.starttls()
            if secret.get("username"):
                smtp.login(secret["username"], secret.get("password", ""))
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise IntegrationError(f"SMTP: {_redact(e, *secret.values())}") from e


async def test(
    http: SafeHttp, kind: str, config: dict[str, Any], secret: dict[str, Any], producer: str
) -> str:
    """Check the connection without sending intelligence; returns what was checked."""
    try:
        if kind == "splunk_hec":
            await http.request(
                "POST",
                f"{config['url']}/services/collector/event",
                content=json.dumps(
                    {"event": {"argus_test": True, "producer": producer}, "sourcetype": "argus:test"}
                ).encode(),
                headers={"Authorization": f"Splunk {secret['token']}"},
            )
            return "HEC accepted a test event (sourcetype argus:test)"
        if kind == "elastic":
            headers = {"Authorization": f"ApiKey {secret['api_key']}"} if secret.get("api_key") else {}
            if not headers and secret.get("username"):
                import base64

                cred = base64.b64encode(
                    f"{secret['username']}:{secret.get('password', '')}".encode()
                ).decode()
                headers = {"Authorization": f"Basic {cred}"}
            res = await http.get(f"{config['url']}/", headers=headers)
            ver = (json.loads(res.body or b"{}").get("version") or {}).get("number", "?")
            return f"cluster answered (version {ver})"
        if kind == "sentinel":
            await sentinel_token(http, config, secret)
            return "Entra ID issued a token for the Sentinel API"
        if kind == "misp":
            res = await http.get(
                f"{config['url']}/servers/getVersion",
                headers={"Authorization": secret["key"], "Accept": "application/json"},
            )
            return f"MISP answered (version {json.loads(res.body or b'{}').get('version', '?')})"
        await send_alert(
            http,
            kind,
            config,
            secret,
            Alert(
                "Argus test message",
                ["If you can read this, alerts will reach this channel."],
                None,
                "TLP:CLEAR",
                "test",
            ),
        )
        return "test message sent"
    except FetchError as e:
        raise IntegrationError(_redact(e, *secret.values())) from e
