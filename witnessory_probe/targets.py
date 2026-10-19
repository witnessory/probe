"""
Targets: public domain names only, and only their public addresses.

A probe must never reach into anyone's internal network, including its host's. Addresses are never accepted as
targets, and names for local networks (.local, .internal, .home.arpa, ...) are refused. A name is resolved here, as a
fully qualified name (local search domains never apply), and if any address it resolves to is not public, the name is
not contacted. "Not public" includes private, loopback, link-local, shared (CGNAT) and reserved ranges, the IPv6
forms that carry an IPv4 address (NAT64, 6to4, Teredo, IPv4-compatible), and an IPv6 address inside the host's own
/64 (home networks use public IPv6 addresses).
"""

import ipaddress
import re
import socket

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".private", ".lan", ".home", ".corp",
                  ".home.arpa", ".onion", ".invalid", ".arpa")
NOT_PUBLIC_V6 = [ipaddress.ip_network(n) for n in (
    "64:ff9b::/96", "64:ff9b:1::/48",      # NAT64: can translate to the host's private IPv4
    "2002::/16",                           # 6to4
    "2001::/32",                           # Teredo
    "::/96",                               # IPv4-compatible (deprecated)
    "::ffff:0:0:0/96",                     # IPv4-translated
    "fec0::/10",                           # site-local (deprecated)
)]

# Tests point names at a local server; never set outside tests.
TEST_RESOLVE = None          # {name: "127.0.0.1"}


class Refused(ValueError):
    """Input the probe will not connect to."""


def normalise(domain) -> str:
    """A lower-case ASCII host name with at least two labels, or Refused."""
    if not isinstance(domain, str):
        raise Refused("a target must be a domain name")
    d = domain.strip().rstrip(".").lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/", 1)[0]
    if ":" in d or not d:
        raise Refused("give a domain name, without a port")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise Refused("not a valid domain name")
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(LABEL.match(x) for x in labels) or labels[-1].isdigit():
        raise Refused("not a valid domain name")
    if ("." + d).endswith(LOCAL_SUFFIXES):
        raise Refused("a name for a local network")
    return d


def _own_v6_net():
    """The /64 of this host's IPv6 address towards the internet, or None (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860::8888", 53))
            return ipaddress.ip_network(s.getsockname()[0].split("%")[0] + "/64", strict=False)
    except OSError:
        return None


def is_public(ip) -> bool:
    if not ip.is_global or ip.is_multicast:
        return False
    if ip.version == 6:
        if ip.ipv4_mapped is not None or any(ip in n for n in NOT_PUBLIC_V6):
            return False
        own = _own_v6_net()
        if own is not None and ip in own:
            return False
    return True


def public_address(name, port):
    """The address to connect to: the first public address of the name (IPv4 first), or None if it does not
    resolve. Refused if any address it resolves to is not public."""
    if TEST_RESOLVE is not None and name in TEST_RESOLVE:
        return TEST_RESOLVE[name]
    try:
        infos = socket.getaddrinfo(name + ".", port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return None
    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not is_public(ip):
            raise Refused("the name resolves to a non-public address")
        if str(ip) not in addrs:
            addrs.append(str(ip))
    addrs.sort(key=lambda a: ":" in a)
    return addrs[0] if addrs else None
