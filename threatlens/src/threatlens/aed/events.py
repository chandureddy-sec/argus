"""AED Slice 5 — event store interface + in-memory implementation.

The in-memory store makes the ingest -> store -> detect flow fully testable.
The persistent Postgres-backed store (daily-partitioned ``aed_events`` +
``aed_alerts``) is provided by the Alembic migration and wired at serve time;
it implements the same interface.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Protocol

CLASS_AUTHENTICATION = 3002


class EventStore(Protocol):
    def store(self, events: list[dict[str, Any]], now: datetime) -> None: ...
    def recent_failed(
        self, agent_id: str, src_ip: str, now: datetime, window_s: int
    ) -> list[dict[str, Any]]: ...
    def events_for(self, agent_id: str, limit: int = 100) -> list[dict[str, Any]]: ...
    def add_alert(self, alert: dict[str, Any]) -> None: ...
    def list_alerts(self) -> list[dict[str, Any]]: ...
    def last_alert_at(self, agent_id: str, src_ip: str) -> datetime | None: ...
    def set_alert_at(self, agent_id: str, src_ip: str, now: datetime) -> None: ...


class InMemoryEventStore:
    """Lab/test store. Events are already redacted when they arrive here."""

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []
        self._alerts: list[dict[str, Any]] = []
        self._last_alert: dict[tuple[str, str], datetime] = {}

    def store(self, events: list[dict[str, Any]], now: datetime) -> None:
        for ev in events:
            fields = ev.get("fields") or {}
            self._rows.append(
                {
                    "agent_id": ev.get("agent_id"),
                    "src_ip": fields.get("src_ip"),
                    "status": fields.get("status"),
                    "class_uid": ev.get("class_uid"),
                    "stored_at": now,
                    "event": ev,
                }
            )

    def recent_failed(self, agent_id: str, src_ip: str, now: datetime, window_s: int) -> list[dict[str, Any]]:
        cutoff = now - timedelta(seconds=window_s)
        return [
            r["event"]
            for r in self._rows
            if r["agent_id"] == agent_id
            and r["src_ip"] == src_ip
            and r["class_uid"] == CLASS_AUTHENTICATION
            and r["status"] == "failure"
            and r["stored_at"] >= cutoff
        ]

    def events_for(self, agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """One agent's recent events, newest first, as **normalized** fields only
        (already redacted — usernames hashed, no raw payload leaves here). Powers
        the endpoint detail timeline."""
        rows = [r for r in self._rows if r["agent_id"] == agent_id]
        out: list[dict[str, Any]] = []
        for r in reversed(rows[-limit:]):
            ev = r["event"]
            f = ev.get("fields") or {}
            out.append(
                {
                    "time": ev.get("time"),
                    "class_uid": ev.get("class_uid"),
                    "activity": f.get("activity"),
                    "status": f.get("status"),
                    "src_ip": f.get("src_ip"),
                    "user": f.get("user"),
                    "hostname": f.get("hostname"),
                    "stored_at": r["stored_at"].isoformat(),
                }
            )
        return out

    def add_alert(self, alert: dict[str, Any]) -> None:
        self._alerts.append(alert)

    def list_alerts(self) -> list[dict[str, Any]]:
        return list(self._alerts)

    def last_alert_at(self, agent_id: str, src_ip: str) -> datetime | None:
        return self._last_alert.get((agent_id, src_ip))

    def set_alert_at(self, agent_id: str, src_ip: str, now: datetime) -> None:
        self._last_alert[(agent_id, src_ip)] = now
