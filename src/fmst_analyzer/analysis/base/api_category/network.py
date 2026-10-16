"""
Network resource operations classification.

This module covers network utility APIs: name/address resolution (DNS),
network interface queries, and protocol/service database lookups.

Socket APIs (socket, bind, connect, send, recv, etc.) are in ipc.py.
I/O multiplexing (epoll) is in file.py (fd-based resources).
Hostname management (sethostname, setdomainname) is in runtime.py (system config).

Classification (2-category system):
- create: (empty — no standalone resources created)
- info: APIs querying network-related information (DNS, interfaces, protocols)
"""

from typing import List
from .base import BaseResourceOps


class NetworkResourceOps(BaseResourceOps):
    @property
    def create_predefined(self) -> List[str]:
        return []

    @property
    def info_predefined(self) -> List[str]:
        return [
            # === Name Resolution (by name/address) ===
            # Hostname resolution (hostname -> IP)
            "gethostbyname",   # gethostbyname(name) - deprecated, not thread-safe
            "gethostbyname2",  # gethostbyname2(name, af)
            "gethostbyname_r", # gethostbyname_r() - thread-safe variant
            "gethostbyname2_r",
            "gethostbyaddr",   # gethostbyaddr(addr, len, type) - reverse lookup
            "gethostbyaddr_r", # gethostbyaddr_r() - thread-safe

            # Modern name resolution
            "getaddrinfo",    # getaddrinfo(node, service, hints, res)
            "getnameinfo",    # getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags)

            # Resource cleanup
            "freeaddrinfo",   # freeaddrinfo(res)
            "freeifaddrs",    # freeifaddrs(ifa)
            "if_freenameindex", # if_freenameindex(ptr)

            # === Network Interface Queries (by name/index) ===
            "if_nametoindex", # if_nametoindex(ifname)
            "if_indextoname", # if_indextoname(ifindex, ifname)
            "if_nameindex",   # if_nameindex()
            "getifaddrs",     # getifaddrs(ifap)

            # === Protocol/Service/Network Database Queries ===
            "getprotobyname",    # getprotobyname(name)
            "getprotobynumber",  # getprotobynumber(proto)

            "getservbyname",     # getservbyname(name, proto)
            "getservbyport",     # getservbyport(port, proto)

            # Hostname queries (not management — see runtime.py for set*)
            "gethostname",       # int gethostname(char *name, size_t len)
            "getdomainname",     # int getdomainname(char *name, size_t len)
        ]
