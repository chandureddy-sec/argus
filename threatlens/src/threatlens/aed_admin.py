"""Client for the AED gateway's admin API (Slice 6).

The AED gateway is a **separate process** (its own :8443 app, never mounted on
the :8000 API). Its admin endpoints — the endpoint registry, the alert list and
agent revocation — are protected by a bearer token, not by mTLS. This client is
how the analyst API on :8000 reaches them, holding the admin token server-side
so it never reaches the browser.

STATUS: the client and its callers are unit-tested with an injected transport.
Pointing it at a live gateway (``TL_AED_ADMIN_URL`` + ``TL_AED_ADMIN_TOKEN``) is
a serve-time, lab-only concern; when unset, the proxy routes return 503.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx


class AedAdminError(Exception):
    """The AED gateway could not be reached or returned an error status."""


class AedAdminClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        http: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = token
        self._http = http  # tests inject an httpx.AsyncClient with a MockTransport
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def _call(self, method: str, path: str, *, json: Any = None) -> httpx.Response:
        url = self._base + path
        try:
            if self._http is not None:
                r = await self._http.request(method, url, headers=self._headers(), json=json)
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as c:
                    r = await c.request(method, url, headers=self._headers(), json=json)
        except httpx.HTTPError as e:
            raise AedAdminError(str(e)) from e
        if r.status_code >= 400:
            raise AedAdminError(f"AED gateway returned HTTP {r.status_code}")
        return r

    async def endpoints(self) -> list[dict[str, Any]]:
        r = await self._call("GET", "/aed/endpoints")
        return list(r.json().get("agents", []))

    async def alerts(self) -> list[dict[str, Any]]:
        r = await self._call("GET", "/aed/alerts")
        return list(r.json().get("alerts", []))

    async def create_enrollment(self, os: str, name: str | None, group: str | None) -> dict[str, Any]:
        """Mint an enrollment on the gateway; returns its one-time response
        (token, install command, CA fingerprint, expiry)."""
        r = await self._call("POST", "/aed/enrollments", json={"os": os, "name": name, "group": group})
        return dict(r.json())

    async def revoke(self, agent_id: str) -> None:
        await self._call("POST", f"/aed/agents/{quote(agent_id, safe='')}/revoke")


def build_aed_admin(base_url: str | None, token: str | None) -> AedAdminClient | None:
    """Build the client when both the URL and token are configured; else None."""
    if base_url and token:
        return AedAdminClient(base_url, token)
    return None
