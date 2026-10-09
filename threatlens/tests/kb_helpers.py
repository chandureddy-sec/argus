"""A mock upstream for the knowledge sources, built from recorded fixtures
(tests/fixtures/kb). NVD queries are answered from a pool of real CVE
records, honouring the parameters the client sends."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

KB = Path(__file__).parent / "fixtures" / "kb"


def kb_bytes(name: str) -> bytes:
    return (KB / name).read_bytes()


def nvd_pool() -> list[dict[str, Any]]:
    pool: list[dict[str, Any]] = json.loads(kb_bytes("nvd_pool.json"))["vulnerabilities"]
    return pool


def _matches_cpe(cve: dict[str, Any], prefix: str) -> bool:
    return any(
        m.get("criteria", "").startswith(prefix + ":")
        for cfg in cve.get("configurations", [])
        for n in cfg["nodes"]
        for m in n["cpeMatch"]
    )


def index_doc(versions: dict[str, list[str]] | None = None) -> bytes:
    """The real index, reduced to Enterprise; ``versions`` overrides the list."""
    idx = json.loads(kb_bytes("attack_index.json"))
    idx["collections"] = [c for c in idx["collections"] if c["name"] == "Enterprise ATT&CK"]
    if versions:
        base = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
        idx["collections"][0]["versions"] = [
            {"version": v, "url": f"{base}/enterprise-attack-{v}.json", "modified": "2026-08-05T21:33:58Z"}
            for v in versions["enterprise-attack"]
        ]
    return json.dumps(idx).encode()


class KbUpstream:
    """Callable httpx handler; records requests for assertions."""

    def __init__(self, attack_versions: list[str] | None = None, nvd_status: int = 200) -> None:
        self.attack_versions = attack_versions or ["19.2", "19.1"]
        self.nvd_status = nvd_status
        self.requests: list[httpx.Request] = []
        self.pool = nvd_pool()

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        host, path = req.url.host, req.url.path
        if host == "raw.githubusercontent.com":
            if path.endswith("/index.json"):
                return httpx.Response(200, content=index_doc({"enterprise-attack": self.attack_versions}))
            for v in ("19.1", "19.2"):
                if path.endswith(f"enterprise-attack-{v}.json"):
                    return httpx.Response(200, content=kb_bytes(f"enterprise-attack-{v}.json"))
            return httpx.Response(404)
        if host == "services.nvd.nist.gov":
            return self.nvd(req)
        if host == "epss.empiricalsecurity.com":
            if req.headers.get("if-none-match") == '"e1"':
                return httpx.Response(304)
            return httpx.Response(200, content=kb_bytes("epss_scores.csv.gz"), headers={"ETag": '"e1"'})
        if host == "api.osv.dev":
            ident = path.rsplit("/", 1)[-1]
            f = KB / f"osv_{ident}.json"
            return (
                httpx.Response(200, content=f.read_bytes())
                if f.exists()
                else httpx.Response(404, json={"code": 5})
            )
        return httpx.Response(404)

    def nvd(self, req: httpx.Request) -> httpx.Response:
        if self.nvd_status != 200:
            return httpx.Response(self.nvd_status)
        q = req.url.params
        items = self.pool
        if "cveId" in q:
            items = [v for v in items if v["cve"]["id"] == q["cveId"]]
        if "hasKev" in q:
            items = [v for v in items if v["cve"].get("cisaExploitAdd")]
        if "virtualMatchString" in q:
            items = [v for v in items if _matches_cpe(v["cve"], q["virtualMatchString"])]
        start = int(q.get("startIndex", 0))
        per = int(q.get("resultsPerPage", 2000))
        page = items[start : start + per]
        return httpx.Response(
            200,
            json={
                "resultsPerPage": len(page),
                "startIndex": start,
                "totalResults": len(items),
                "format": "NVD_CVE",
                "version": "2.0",
                "vulnerabilities": page,
            },
        )


def combined(
    *handlers: Callable[[httpx.Request], httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    """First handler whose answer isn't 404 wins."""

    def handle(req: httpx.Request) -> httpx.Response:
        resp = httpx.Response(404)
        for h in handlers:
            resp = h(req)
            if resp.status_code != 404:
                return resp
        return resp

    return handle
