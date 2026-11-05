"""AED Slice 5 — the one detection rule: repeated failed SSH logins from one source.

Evaluated per (agent, src_ip): if there are >= ``threshold`` failed SSH logins
within ``window_s``, raise one alert (with evidence, severity, confidence and
false-positive guidance). A ``cooldown_s`` re-arm means one brute-force burst
produces one alert, not hundreds.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .events import EventStore


class SSHBruteForce:
    def __init__(self, threshold: int = 10, window_s: int = 300, cooldown_s: int = 600) -> None:
        self.threshold = threshold
        self.window_s = window_s
        self.cooldown_s = cooldown_s

    def evaluate(self, store: EventStore, agent_id: str, src_ip: str, now: datetime) -> dict[str, Any] | None:
        evs = store.recent_failed(agent_id, src_ip, now, self.window_s)
        count = len(evs)
        if count < self.threshold:
            return None
        last = store.last_alert_at(agent_id, src_ip)
        if last is not None and (now - last).total_seconds() <= self.cooldown_s:
            return None

        times = sorted(str(e.get("time") or "") for e in evs)
        users = sorted(
            {
                str((e.get("fields") or {}).get("user_hash") or (e.get("fields") or {}).get("user") or "")
                for e in evs
            }
            - {""}
        )
        severity = "high" if count >= 50 else "medium"
        confidence = 0.9 if count >= int(self.threshold * 1.5) else 0.7

        store.set_alert_at(agent_id, src_ip, now)
        return {
            "rule": "ssh_bruteforce",
            "agent_id": agent_id,
            "src_ip": src_ip,
            "count": count,
            "window_s": self.window_s,
            "severity": severity,
            "confidence": confidence,
            "created_at": now.isoformat(),
            "evidence": {
                "failed_count": count,
                "window_s": self.window_s,
                "first_time": times[0] if times else None,
                "last_time": times[-1] if times else None,
                "accounts_tried": users[:20],
            },
            "fp_guidance": (
                "Benign causes include a misconfigured service or cron account, a vulnerability "
                "scanner, or an automation host. Before treating this as malicious, confirm whether "
                "the same source IP also *succeeds* on this host and whether it is a known lab scanner."
            ),
        }
