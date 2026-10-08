"""SSRF guard: decide which IP addresses outbound requests may reach.

The check runs at *connect time*, on the addresses DNS actually returned, so it
can't be bypassed by DNS rebinding (a name that resolves to a public IP when
validated and a private one when connecting), alternative IP spellings
(``2130706433``, ``0x7f.1``, ``017700000001`` all resolve to 127.0.0.1), or a
redirect to an internal host: every new connection is checked again.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import Any

import anyio
import httpcore

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Not covered by is_global on every Python version, or worth naming explicitly.
_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 (embeds IPv4)
    ipaddress.ip_network("64:ff9b:1::/48"),
]


class BlockedAddressError(ConnectionError):
    """Raised when a request would connect to a non-public address."""


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_v4(ip)
        if inner is not None and not is_public(inner):
            return False
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)


def check_addresses(host: str, addresses: Iterable[str], allow: frozenset[str] = frozenset()) -> str:
    """Return the first address to connect to, or raise if any is non-public.

    A name that resolves to *both* public and private addresses is refused:
    which one gets used is up to the resolver, so it must be treated as private.
    """
    addrs = list(dict.fromkeys(addresses))
    if not addrs:
        raise BlockedAddressError(f"{host}: no addresses")
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%", 1)[0])  # drop IPv6 zone ids
        if str(ip) not in allow and not is_public(ip):
            raise BlockedAddressError(f"{host} resolves to non-public address {ip}")
    return addrs[0]


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that resolves names itself and refuses
    non-public destinations before opening the socket."""

    def __init__(self, allow: frozenset[str] = frozenset()) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._allow = allow  # tests only: explicitly permitted addresses

    async def resolve(self, host: str, port: int) -> list[str]:
        try:
            infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:  # gaierror: surface as a normal connection failure
            raise httpcore.ConnectError(f"cannot resolve {host}: {e}") from e
        return [str(info[4][0]) for info in infos]

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        address = check_addresses(host, await self.resolve(host, port), self._allow)
        # Connect to the vetted address. TLS still verifies the certificate
        # against the original host name, which httpcore passes as SNI.
        return await self._inner.connect_tcp(
            address, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - signature fixed by httpcore
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise BlockedAddressError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)
