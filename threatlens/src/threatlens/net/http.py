"""The one HTTP client every outbound request goes through.

Hardening, in order of the threats it answers (docs/THREAT_MODEL.md):

* SSRF (E1): connections go through :class:`GuardedBackend`, which refuses
  non-public addresses at connect time; redirects are followed manually so
  every hop is re-checked; only ``https`` unless a caller opts in; no proxy
  settings are read from the environment.
* Resource exhaustion (D1): a hard cap on the *decoded* body (so a gzip bomb
  hits the cap, not memory), plus connect/read timeouts.
* Flaky or rate-limited sources: retries with exponential backoff and jitter
  on transport errors, 429 and 5xx; ``Retry-After`` is honoured up to a limit.
* Cheap polling: ``ETag`` / ``If-Modified-Since`` turn unchanged feeds into a
  304 with no body.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from threatlens import __version__
from threatlens.net.guard import BlockedAddressError, GuardedBackend

USER_AGENT = f"ThreatLens/{__version__} (threat intelligence collector)"
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_rng = secrets.SystemRandom()


class FetchError(Exception):
    """A request failed after retries; ``status`` is set for HTTP errors."""

    def __init__(self, message: str, status: int | None = None, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after  # seconds the server asked us to wait, if any


class ResponseTooLargeError(FetchError):
    pass


class UnsafeURLError(FetchError):
    pass


@dataclass(frozen=True)
class FetchResult:
    url: str  # final URL after redirects
    status: int  # 200-range or 304
    body: bytes
    content_type: str
    etag: str | None
    last_modified: str | None
    headers: Mapping[str, str] = field(default_factory=dict)  # lower-case names

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


def make_transport(allow_addresses: frozenset[str] = frozenset()) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose connection pool uses the SSRF-guarded backend.

    httpx doesn't expose httpcore's ``network_backend`` argument, so the pool
    is replaced after construction; ``test_http`` fails loudly if a future
    httpx version stops using ``_pool``.
    """
    transport = httpx.AsyncHTTPTransport(retries=0, trust_env=False)
    ssl_context = httpx.create_ssl_context()
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        max_connections=20,
        max_keepalive_connections=10,
        keepalive_expiry=30.0,
        http1=True,
        http2=False,
        network_backend=GuardedBackend(allow_addresses),
    )
    return transport


class SafeHttp:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = 5,
        retries: int = 3,
        backoff_base: float = 1.0,
        max_retry_after: float = 60.0,
        allow_http: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client = httpx.AsyncClient(
            transport=transport or make_transport(),
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
        )
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.retries = retries
        self.backoff_base = backoff_base
        self.max_retry_after = max_retry_after
        self.allow_http = allow_http
        self._sleep = sleep

    async def __aenter__(self) -> SafeHttp:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _check_url(self, url: str) -> None:
        parts = urlsplit(url)
        allowed = {"https", "http"} if self.allow_http else {"https"}
        if parts.scheme not in allowed:
            raise UnsafeURLError(f"scheme {parts.scheme!r} not allowed: {url}")
        if not parts.hostname:
            raise UnsafeURLError(f"no host in URL: {url}")
        if parts.username or parts.password:
            raise UnsafeURLError("credentials in URLs are not allowed")

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
        accept: frozenset[int] = frozenset(),
        max_bytes: int | None = None,
    ) -> FetchResult:
        """GET ``url``. Statuses in ``accept`` (e.g. a 404 that carries a JSON
        "not found" body) are returned as results instead of raising."""
        h = dict(headers or {})
        if etag:
            h["If-None-Match"] = etag
        if last_modified:
            h["If-Modified-Since"] = last_modified
        return await self.request("GET", url, params=params, headers=h, accept=accept, max_bytes=max_bytes)

    async def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> FetchResult:
        return await self.request("POST", url, json=payload, headers=headers, max_bytes=max_bytes)

    async def post_form(
        self,
        url: str,
        form: Mapping[str, str],
        *,
        headers: Mapping[str, str] | None = None,
        accept: frozenset[int] = frozenset(),
        max_bytes: int | None = None,
    ) -> FetchResult:
        return await self.request("POST", url, form=form, headers=headers, accept=accept, max_bytes=max_bytes)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
        form: Mapping[str, str] | None = None,
        accept: frozenset[int] = frozenset(),
        max_bytes: int | None = None,
    ) -> FetchResult:
        limit = max_bytes or self.max_bytes
        attempt = 0
        while True:
            try:
                return await self._follow(method, url, params, headers, json, form, accept, limit)
            except (BlockedAddressError, UnsafeURLError, ResponseTooLargeError):
                raise  # never retry a policy refusal
            except FetchError as e:
                delay = e.retry_after
                if e.status not in RETRY_STATUSES or attempt >= self.retries:
                    raise
                if delay is not None and delay > self.max_retry_after:
                    raise  # the source asked for a long pause: respect it, try next run
            except httpx.TransportError as e:
                if attempt >= self.retries:
                    raise FetchError(f"{type(e).__name__} after {attempt + 1} attempts: {url}") from e
                delay = None
            attempt += 1
            await self._sleep(self._backoff(attempt, delay))

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return retry_after
        base: float = self.backoff_base * 2.0 ** (attempt - 1)
        jitter: float = _rng.uniform(0, self.backoff_base)
        return base + jitter

    async def _follow(
        self,
        method: str,
        url: str,
        params: Mapping[str, str] | None,
        headers: Mapping[str, str] | None,
        json: Any,
        form: Mapping[str, str] | None,
        accept: frozenset[int],
        limit: int,
    ) -> FetchResult:
        for _ in range(self.max_redirects + 1):
            self._check_url(url)
            req = self._client.build_request(
                method, url, params=params, headers=headers, json=json, data=form
            )
            resp = await self._client.send(req, stream=True)
            try:
                if resp.status_code in _REDIRECTS and "location" in resp.headers:
                    url = urljoin(str(resp.url), resp.headers["location"])
                    params = None  # already part of the URL we are leaving
                    if resp.status_code == 303 or (resp.status_code in (301, 302) and method == "POST"):
                        method, json, form = "GET", None, None
                    continue
                return await self._read(resp, limit, accept)
            finally:
                await resp.aclose()
        raise FetchError(f"more than {self.max_redirects} redirects: {url}")

    async def _read(
        self, resp: httpx.Response, limit: int, accept: frozenset[int] = frozenset()
    ) -> FetchResult:
        if resp.status_code == 304:
            return FetchResult(str(resp.url), 304, b"", "", resp.headers.get("etag"), None)
        if resp.status_code >= 400 and resp.status_code not in accept:
            raise FetchError(
                f"HTTP {resp.status_code} from {resp.url}", resp.status_code, self._retry_after(resp)
            )
        declared = resp.headers.get("content-length")
        encoded = bool(resp.headers.get("content-encoding"))  # compressed length says little
        if declared and declared.isdigit() and int(declared) > limit and not encoded:
            raise ResponseTooLargeError(f"{resp.url}: {declared} bytes exceeds the {limit}-byte limit")
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():  # decoded bytes: a gzip bomb hits the cap
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError(f"{resp.url}: body exceeds the {limit}-byte limit")
            chunks.append(chunk)
        return FetchResult(
            url=str(resp.url),
            status=resp.status_code,
            body=b"".join(chunks),
            content_type=resp.headers.get("content-type", ""),
            etag=resp.headers.get("etag"),
            last_modified=resp.headers.get("last-modified"),
            headers={k.lower(): v for k, v in resp.headers.items()},
        )

    def _retry_after(self, resp: httpx.Response) -> float | None:
        value = resp.headers.get("retry-after")
        if not value:
            return None
        if value.isdigit():
            secs = float(value)
        else:
            try:
                when = parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return None
            secs = (when - datetime.now(UTC)).total_seconds()
        return max(0.0, secs)
