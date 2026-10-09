"""Hardened HTTP client: SSRF guard, redirects, size caps, retries, conditional GET.

A real HTTP server on 127.0.0.1 is used so the guard runs on real sockets.
Requests to it are only possible when 127.0.0.1 is explicitly allowed, which
is itself the first thing tested.
"""

from __future__ import annotations

import gzip
import ipaddress
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from threatlens.net.guard import BlockedAddressError, check_addresses, is_public
from threatlens.net.http import (
    FetchError,
    ResponseTooLargeError,
    SafeHttp,
    UnsafeURLError,
    make_transport,
)

# ── guard ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0",  # noqa: S104 - the point of the test
        "224.0.0.1",
        "198.18.0.1",
        "192.0.2.1",  # documentation
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",
        "2002:7f00:0001::",  # 6to4 wrapping 127.0.0.1
        "64:ff9b::a9fe:a9fe",  # NAT64 wrapping 169.254.169.254
    ],
)
def test_non_public_addresses_are_blocked(addr: str) -> None:
    assert not is_public(ipaddress.ip_address(addr))


@pytest.mark.parametrize("addr", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_pass(addr: str) -> None:
    assert is_public(ipaddress.ip_address(addr))


def test_mixed_resolution_is_refused() -> None:
    # A name resolving to a public and a private address could connect to either.
    with pytest.raises(BlockedAddressError):
        check_addresses("rebind.example", ["93.184.216.34", "10.0.0.5"])
    assert check_addresses("ok.example", ["93.184.216.34"]) == "93.184.216.34"
    assert check_addresses("lab", ["127.0.0.1"], allow=frozenset({"127.0.0.1"})) == "127.0.0.1"


# ── local server ──────────────────────────────────────────────────────────────

CALLS: dict[str, int] = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep test output clean
        pass

    def _send(self, code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        CALLS[self.path] = CALLS.get(self.path, 0) + 1
        p = self.path
        if p == "/ok":
            self._send(200, b"hello", {"ETag": '"v1"', "Content-Type": "text/plain"})
        elif p == "/etag":
            if self.headers.get("If-None-Match") == '"v1"':
                self._send(304)
            else:
                self._send(200, b"fresh", {"ETag": '"v1"'})
        elif p == "/big":
            self._send(200, b"x" * 5000)
        elif p == "/bomb":  # 10 MB of zeros, ~10 KB on the wire
            self._send(200, gzip.compress(b"\0" * 10_000_000), {"Content-Encoding": "gzip"})
        elif p == "/redirect-meta":
            self._send(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        elif p == "/redirect-ok":
            self._send(302, headers={"Location": "/ok"})
        elif p == "/loop":
            self._send(302, headers={"Location": "/loop"})
        elif p == "/flaky":
            self._send(503 if CALLS[p] < 3 else 200, b"recovered")
        elif p == "/slowdown":
            self._send(429, headers={"Retry-After": "3600"})
        elif p == "/gone":
            self._send(404)
        else:
            self._send(500)


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


async def no_sleep(_: float) -> None:
    return None


def lab_client(**kw: object) -> SafeHttp:
    # The only way to reach 127.0.0.1: explicit allow + http opt-in.
    return SafeHttp(
        transport=make_transport(frozenset({"127.0.0.1"})),
        allow_http=True,
        sleep=no_sleep,
        **kw,  # type: ignore[arg-type]
    )


# ── SSRF ──────────────────────────────────────────────────────────────────────


async def test_loopback_is_refused_by_default(server: str) -> None:
    async with SafeHttp(allow_http=True) as http:
        with pytest.raises(BlockedAddressError):
            await http.get(f"{server}/ok")


async def test_alternative_ip_spellings_are_refused(server: str) -> None:
    port = server.rsplit(":", 1)[1]
    # Each spelling is either resolved to 127.0.0.1 and blocked, or (on
    # resolvers that don't accept it) fails to resolve; it never connects.
    async with SafeHttp(allow_http=True, retries=0) as http:
        for host in ["localhost", "2130706433", "127.1", "0x7f.0.0.1"]:
            with pytest.raises((BlockedAddressError, FetchError)):
                await http.get(f"http://{host}:{port}/ok")


async def test_redirect_to_metadata_is_refused(server: str) -> None:
    async with lab_client() as http:
        with pytest.raises(BlockedAddressError, match=r"169\.254\.169\.254"):
            await http.get(f"{server}/redirect-meta")


async def test_https_only_by_default() -> None:
    async with SafeHttp() as http:
        with pytest.raises(UnsafeURLError):
            await http.get("http://example.com/")
        with pytest.raises(UnsafeURLError):
            await http.get("file:///etc/passwd")
        with pytest.raises(UnsafeURLError):
            await http.get("https://user:pw@example.com/")


def test_transport_uses_guarded_pool() -> None:
    # Fails loudly if an httpx upgrade stops routing requests through `_pool`.
    t = make_transport()
    assert type(t._pool._network_backend).__name__ == "GuardedBackend"


# ── behaviour ─────────────────────────────────────────────────────────────────


async def test_fetch_and_redirect(server: str) -> None:
    async with lab_client() as http:
        r = await http.get(f"{server}/redirect-ok")
    assert r.status == 200
    assert r.body == b"hello"
    assert r.url.endswith("/ok")
    assert r.etag == '"v1"'
    assert len(r.sha256) == 64


async def test_conditional_get(server: str) -> None:
    async with lab_client() as http:
        first = await http.get(f"{server}/etag")
        second = await http.get(f"{server}/etag", etag=first.etag)
    assert first.body == b"fresh"
    assert second.not_modified
    assert second.body == b""


async def test_size_caps(server: str) -> None:
    async with lab_client(max_bytes=1000) as http:
        with pytest.raises(ResponseTooLargeError):
            await http.get(f"{server}/big")
        with pytest.raises(ResponseTooLargeError):  # decoded size, not wire size
            await http.get(f"{server}/bomb")


async def test_redirect_loop(server: str) -> None:
    async with lab_client(max_redirects=3) as http:
        with pytest.raises(FetchError, match="redirects"):
            await http.get(f"{server}/loop")


async def test_retries_then_succeeds(server: str) -> None:
    async with lab_client(retries=3) as http:
        r = await http.get(f"{server}/flaky")
    assert r.body == b"recovered"
    assert CALLS["/flaky"] == 3


async def test_long_retry_after_gives_up_immediately(server: str) -> None:
    async with lab_client(retries=3) as http:
        with pytest.raises(FetchError) as e:
            await http.get(f"{server}/slowdown")
    assert e.value.status == 429
    assert e.value.retry_after == 3600
    assert CALLS["/slowdown"] == 1


async def test_client_errors_are_not_retried(server: str) -> None:
    async with lab_client(retries=3) as http:
        with pytest.raises(FetchError) as e:
            await http.get(f"{server}/gone")
    assert e.value.status == 404
    assert CALLS["/gone"] == 1
