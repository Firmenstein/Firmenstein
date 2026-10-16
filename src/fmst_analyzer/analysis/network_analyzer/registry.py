"""Network callsite registry.

Only calls that establish, identify, query, or configure a network resource
become candidates. Handle-only lifecycle operations remain available to the
Agent through code navigation but do not independently fan out work.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkAPI:
    family: str


_EXACT: dict[str, NetworkAPI] = {
    # Socket creation and endpoint operations.
    "socket": NetworkAPI("socket"),
    "socketpair": NetworkAPI("socket"),
    "accept": NetworkAPI("accepted_socket"),
    "accept4": NetworkAPI("accepted_socket"),
    "bind": NetworkAPI("endpoint"),
    "connect": NetworkAPI("endpoint"),
    "listen": NetworkAPI("endpoint"),
    "sendto": NetworkAPI("endpoint"),
    "sendmsg": NetworkAPI("endpoint"),
    # Socket configuration and identity queries.
    "setsockopt": NetworkAPI("socket_option"),
    "getsockopt": NetworkAPI("socket_option"),
    "getsockname": NetworkAPI("socket_identity"),
    "getpeername": NetworkAPI("socket_identity"),
    # Name, protocol, service, and host queries.
    "getaddrinfo": NetworkAPI("resolver"),
    "getnameinfo": NetworkAPI("resolver"),
    "gethostbyaddr": NetworkAPI("resolver"),
    "gethostbyaddr_r": NetworkAPI("resolver"),
    "gethostbyname": NetworkAPI("resolver"),
    "gethostbyname2": NetworkAPI("resolver"),
    "gethostbyname_r": NetworkAPI("resolver"),
    "gethostbyname2_r": NetworkAPI("resolver"),
    "gethostname": NetworkAPI("host_query"),
    "gethostid": NetworkAPI("host_query"),
    "getprotobyname": NetworkAPI("protocol_query"),
    "getprotobynumber": NetworkAPI("protocol_query"),
    "getservbyname": NetworkAPI("service_query"),
    "getservbyport": NetworkAPI("service_query"),
    # Interface identity queries.
    "getifaddrs": NetworkAPI("interface"),
    "if_nametoindex": NetworkAPI("interface"),
    "if_indextoname": NetworkAPI("interface"),
    "if_nameindex": NetworkAPI("interface"),
    # ioctl is deliberately broad; only the Agent can establish fd provenance
    # and distinguish socket SIOC* from /dev-backed requests.
    "ioctl": NetworkAPI("ioctl"),
}


def normalize_api_name(name: str) -> str:
    return name[len("__imp_"):] if name.startswith("__imp_") else name


def lookup_network_api(name: str) -> NetworkAPI | None:
    normalized = normalize_api_name(name)
    exact = _EXACT.get(normalized)
    if exact is not None:
        return exact
    if normalized.startswith("gethostby"):
        return NetworkAPI("resolver")
    if normalized.startswith("if_") and "name" in normalized:
        return NetworkAPI("interface")
    # Resolver implementations expose a sizeable, vendor-dependent res_*
    # surface. Prefix matching is still deterministic API selection; it does
    # not infer arguments or network ownership.
    if normalized.startswith("res_") or normalized.startswith("__res_"):
        return NetworkAPI("resolver")
    return None


__all__ = [
    "NetworkAPI",
    "lookup_network_api",
    "normalize_api_name",
]
