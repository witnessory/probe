"""
Targets: public domain names only, and only their public addresses.

A probe must never reach into anyone's internal network, including its host's. Addresses are never accepted as
targets; a name is resolved here, and if any address it resolves to is not public (private, loopback,
link-local, reserved, shared), the name is not contacted.
"""

import ipaddress
import re
import socket

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

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
    return d


def public_address(name, port):
    """The address to connect to: the first public address of the name (IPv4 first), or None if it does not
    resolve. Refused if any address it resolves to is not public."""
    if TEST_RESOLVE is not None and name in TEST_RESOLVE:
        return TEST_RESOLVE[name]
    try:
        infos = socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return None
    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise Refused("the name resolves to a non-public address")
        if str(ip) not in addrs:
            addrs.append(str(ip))
    addrs.sort(key=lambda a: ":" in a)
    return addrs[0] if addrs else None
