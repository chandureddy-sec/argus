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
        if inner is not None:
            # A v6 carrying a translated v4 (NAT64, 6to4, Teredo, IPv4-mapped)
            # is a route to the embedded v4; publicness is decided there. The
            # outer v6 sits in a translation prefix that is_global / the extra
            # blocklist would otherwise reject even when the embedded v4 is
            # perfectly public (e.g. a DNS64 resolver returning 64:ff9b::<pub>).
            return is_public(inner)
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version)


# Internal networks an admin may open for one integration or feed (a SIEM or
# MISP inside the LAN). Link-local (169.254.0.0/16, fe80::/10: cloud metadata
# lives there), multicast and unspecified addresses are never reachable.
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT, used by some VPNs
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
]
LOOPBACK = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]


def is_internal(ip: IPAddress) -> bool:
    return any(ip in net for net in INTERNAL_NETWORKS if net.version == ip.version)


def is_loopback(ip: IPAddress) -> bool:
    return any(ip in net for net in LOOPBACK if net.version == ip.version)


def check_addresses(
    host: str,
    addresses: Iterable[str],
    allow: frozenset[str] = frozenset(),
    *,
    internal: bool = False,
    loopback: bool = False,
) -> str:
    """Return the first address to connect to, or raise if any is non-public.

    A name that resolves to *both* public and private addresses is refused:
    which one gets used is up to the resolver, so it must be treated as private.
    ``internal`` additionally permits private LAN ranges and ``loopback`` the
    host itself; both are per-integration admin choices, never the default.
    """
    addrs = list(dict.fromkeys(addresses))
    if not addrs:
        raise BlockedAddressError(f"{host}: no addresses")
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%", 1)[0])  # drop IPv6 zone ids
        if str(ip) in allow or is_public(ip):
            continue
        if internal and is_internal(ip):
            continue
        if loopback and is_loopback(ip):
            continue
        raise BlockedAddressError(f"{host} resolves to non-public address {ip}")
    return addrs[0]


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that resolves names itself and refuses
    non-public destinations before opening the socket."""

    def __init__(
        self, allow: frozenset[str] = frozenset(), *, internal: bool = False, loopback: bool = False
    ) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._allow = allow  # tests only: explicitly permitted addresses
        self._internal = internal
        self._loopback = loopback

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
        address = check_addresses(
            host,
            await self.resolve(host, port),
            self._allow,
            internal=self._internal,
            loopback=self._loopback,
        )
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
