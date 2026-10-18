"""
The measurement types a probe can run. A task chooses one of these by name; nothing else can be run.

Each type: the port it uses, the parameters a task may set (none yet), and `run(name)`, which measures one public
domain name and returns one observation. Names are resolved and checked here (targets.py) before any connection.
"""

import socket
import ssl

from cryptography import x509

from . import _handshake as hs
from . import _ssh
from . import targets

# Certificate algorithm names, as the observatory names them (so results compare directly).
OIDS = {
    "1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.2.1": "ecPublicKey", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
for _i, _n in enumerate(("SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f",
                         "SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f")):
    OIDS[f"2.16.840.1.101.3.4.3.{20 + _i}"] = f"SLH-DSA-{_n}"
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
PQ_CLASSES = ("pq_hybrid", "pq_pure")


def is_pq(name):
    return bool(name) and name.startswith(("ML-DSA", "SLH-DSA", "ML-KEM"))


def _refused(name, why):
    return {"target": name, "outcome": "refused_non_public", "error": why}


# ---------------------------------------------------------------- tls_pq

TLS_PORT = 443
TLS_TIMEOUT = 8.0


def certificate(name, ip, port, timeout):
    """The served leaf certificate's algorithms (read only; the connection is closed at once)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=name) as w:
            der = w.getpeercert(True)
        cert = x509.load_der_x509_certificate(der)
        sig = cert.signature_algorithm_oid.dotted_string
        key = cert.public_key_algorithm_oid.dotted_string
        sig, key = OIDS.get(sig, sig), OIDS.get(key, key)
        if key == "ecPublicKey":
            curve = cert.public_key().curve.name
            key = f"ecPublicKey ({CURVES.get(curve, curve)})"
    except (OSError, ssl.SSLError, ValueError, TypeError, AttributeError) as e:
        return {"error": type(e).__name__}
    return {"signature_algorithm": sig, "key_algorithm": key, "post_quantum": is_pq(sig) or is_pq(key.split(" ")[0])}


def tls_level(browser, pq_only):
    if browser["group_class"] in PQ_CLASSES and browser["tls_version"] == "1.3":
        return "ready"
    if pq_only["group_class"] in PQ_CLASSES:
        return "partly"
    if browser["group_class"] is not None or pq_only["outcome"] == "alert":
        return "not_yet"
    return "unknown"


def tls_pq(name):
    port, timeout = TLS_PORT, TLS_TIMEOUT
    tried, notes = name, []
    try:
        ip = targets.public_address(name, port)
    except targets.Refused as e:
        return _refused(name, str(e))
    if ip:
        browser = hs.probe(name, port, "browser", timeout, ip)
    else:
        browser = {"profile": "browser", "outcome": "error", "error": "dns", "group_class": None, "tls_version": None}
    if browser["outcome"] == "error" and browser.get("error") in hs.NETWORK_FAIL and not name.startswith("www."):
        try:
            www_ip = targets.public_address("www." + name, port)
        except targets.Refused:
            www_ip = None
        if www_ip:
            tried, ip = "www." + name, www_ip
            browser = hs.probe(tried, port, "browser", timeout, ip)
            notes.append(f"{name} did not answer on port {port}; measured www.{name}")
    pq_only = hs.probe(tried, port, "pq_only", timeout, ip) if ip else dict(browser, profile="pq_only")
    level = tls_level(browser, pq_only)
    return {"target": name, "name_measured": tried, "outcome": "no_answer" if level == "unknown" else "measured",
            "level": level,
            "browser": browser, "pq_only": pq_only,
            "certificate": certificate(tried, ip, port, timeout) if ip and level != "unknown" else None,
            "notes": notes}


# ---------------------------------------------------------------- ssh_kex

SSH_PORT = 22
SSH_TIMEOUT = 6.0


def ssh_kex(name):
    try:
        ip = targets.public_address(name, SSH_PORT)
    except targets.Refused as e:
        return _refused(name, str(e))
    if not ip:
        return {"target": name, "outcome": "no_answer", "ssh": {"outcome": "error", "error": "dns"}}
    obs = _ssh.observe(name, SSH_PORT, SSH_TIMEOUT, connect_to=ip)
    answered = obs["outcome"] in ("kexinit", "not_ssh2")
    return {"target": name, "outcome": "measured" if answered else "no_answer", "ssh": obs}


# ---------------------------------------------------------------- registry

MEASURES = {
    "tls_pq": {"version": "1", "port": TLS_PORT, "params": {}, "run": tls_pq},
    "ssh_kex": {"version": "1", "port": SSH_PORT, "params": {}, "run": ssh_kex},
}


def failed(obs) -> bool:
    """An observation with no answer from the server. "measured" means the server answered, however negatively
    (an alert, a classical group); "no_answer" (no address, a time-out, refused, reset) and "refused_non_public"
    measured nothing, and earn no credit."""
    return obs.get("outcome") != "measured"
