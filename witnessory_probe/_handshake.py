"""
TLS key exchange: which group a server selects for a browser-like ClientHello, and whether it accepts a
post-quantum-only one. Sends ClientHellos and reads only the server's reply; never completes a handshake,
sends no application data, reads no content.

The same measurement as the Witnessory observatory's handshake sensor, so a probe's result means exactly what
the observatory's figure means. Standard library only. A server's reply is read up to one handshake message of
at most 64 KB, and at most 2 KB of it is kept (its hash covers all of it).
"""

import hashlib
import os
import secrets
import socket
import time

INSTRUMENT = "handshake_sensor"
INSTRUMENT_VERSION = "1.1.0"
DEFINITION_VERSION = "1"

MAX_MESSAGE = 64 * 1024        # largest handshake message read from a server
RAW_KEEP = 2048               # bytes of a server's raw reply kept in the result

HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096", 0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00", 0x639A: "SecP256r1Kyber768Draft00",
}
PQ_HYBRID = {0x11EB, 0x11EC, 0x11ED}
PQ_PURE = {0x0200, 0x0201, 0x0202}
PQ_DRAFT = {0x6399, 0x639A}

ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          42: "bad_certificate", 47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error",
          70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
          109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
          120: "no_application_protocol"}

CIPHERS_TLS13 = [0x1301, 0x1302, 0x1303]
CIPHERS_TLS12 = [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0201]

PROFILES = {
    "browser": {"groups": [0x11EC, 0x001D, 0x0017, 0x0018], "shares": [0x11EC, 0x001D], "tls12": True},
    "pq_only": {"groups": [0x11EC], "shares": [0x11EC], "tls12": False},
}


def group_class(g):
    if g is None:
        return None
    if g in PQ_HYBRID:
        return "pq_hybrid"
    if g in PQ_PURE:
        return "pq_pure"
    if g in PQ_DRAFT:
        return "pq_draft_obsolete"
    return "classical"


# --------------------------------------------------------------------------
# Key shares
# --------------------------------------------------------------------------

MLKEM_Q = 3329


def mlkem768_encapsulation_key() -> bytes:
    """A well-formed ML-KEM-768 encapsulation key (FIPS 203 ByteEncode12 of 3x256
    coefficients below q, plus a 32-byte seed). The sensor never decapsulates,
    so it needs no private key; the key only has to pass the server's checks."""
    coeffs = [secrets.randbelow(MLKEM_Q) for _ in range(768)]
    out = bytearray()
    for i in range(0, 768, 2):
        a, b = coeffs[i], coeffs[i + 1]
        out += bytes([a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4])
    return bytes(out) + os.urandom(32)


X25519_P = 2 ** 255 - 19


def x25519_public_key(private: bytes = None) -> bytes:
    """A genuine X25519 public key: X25519(k, 9) for a random private key k (RFC 7748, section 5).

    Random bytes are not enough: servers that validate the client's key (canonical, on the curve) answer them with
    illegal_parameter, and would drop out of the measurement instead of being counted."""
    k = bytearray(private if private is not None else os.urandom(32))   # a given key only in tests
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    n, p = int.from_bytes(k, "little"), X25519_P
    x2, z2, x3, z3, swap = 1, 0, 9, 1, 0
    for t in range(254, -1, -1):                            # the Montgomery ladder of RFC 7748
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        da, cb = (x3 - z3) * a % p, (x3 + z3) * b % p
        x3, z3 = (da + cb) ** 2 % p, 9 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def key_share_for(group: int) -> bytes:
    if group == 0x001D:
        return x25519_public_key()
    if group == 0x11EC:  # draft-ietf-tls-ecdhe-mlkem: ML-KEM-768 encapsulation key first, then X25519
        return mlkem768_encapsulation_key() + x25519_public_key()
    raise ValueError(f"no key share generator for group 0x{group:04x}")


# --------------------------------------------------------------------------
# ClientHello
# --------------------------------------------------------------------------

def _u8(n): return n.to_bytes(1, "big")
def _u16(n): return n.to_bytes(2, "big")
def _u24(n): return n.to_bytes(3, "big")
def _ext(t, body): return _u16(t) + _u16(len(body)) + body


def build_client_hello(server_name: str, profile: str) -> bytes:
    p = PROFILES[profile]
    ciphers = CIPHERS_TLS13 + (CIPHERS_TLS12 if p["tls12"] else [])
    exts = b""
    if server_name and not _is_ip(server_name):
        name = server_name.encode("idna")
        exts += _ext(0x0000, _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name)
    exts += _ext(0x0017, b"")                                        # extended_master_secret
    exts += _ext(0xFF01, b"\x00")                                    # renegotiation_info
    groups = b"".join(_u16(g) for g in p["groups"])
    exts += _ext(0x000A, _u16(len(groups)) + groups)                 # supported_groups
    exts += _ext(0x000B, b"\x01\x00")                                # ec_point_formats
    sigs = b"".join(_u16(s) for s in SIG_ALGS)
    exts += _ext(0x000D, _u16(len(sigs)) + sigs)                     # signature_algorithms
    alpn = b"\x02h2\x08http/1.1"
    exts += _ext(0x0010, _u16(len(alpn)) + alpn)                     # ALPN
    versions = b"\x03\x04" + (b"\x03\x03" if p["tls12"] else b"")
    exts += _ext(0x002B, _u8(len(versions)) + versions)              # supported_versions
    exts += _ext(0x002D, b"\x01\x01")                                # psk_key_exchange_modes
    shares = b""
    for g in p["shares"]:
        ks = key_share_for(g)
        shares += _u16(g) + _u16(len(ks)) + ks
    exts += _ext(0x0033, _u16(len(shares)) + shares)                 # key_share
    cs = b"".join(_u16(c) for c in ciphers)
    body = (b"\x03\x03" + os.urandom(32) + _u8(32) + os.urandom(32)
            + _u16(len(cs)) + cs + b"\x01\x00" + _u16(len(exts)) + exts)
    hs = b"\x01" + _u24(len(body)) + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def _is_ip(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# Reading the server's reply
# --------------------------------------------------------------------------

class HandshakeReader:
    def __init__(self, sock, deadline):
        self.sock, self.deadline, self.buf, self.raw = sock, deadline, b"", b""

    def _recv_exact(self, n):
        data = b""
        while len(data) < n:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("read deadline exceeded")
            self.sock.settimeout(left)
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("connection closed by peer")
            data += chunk
        return data

    def next(self):
        """Return ('handshake', type, body) or ('alert', level, desc) or ('other', ctype, None)."""
        while True:
            if len(self.buf) >= 4:
                ml = int.from_bytes(self.buf[1:4], "big")
                if ml > MAX_MESSAGE:
                    raise ValueError("oversized handshake message")
                if len(self.buf) >= 4 + ml:
                    mt, body = self.buf[0], self.buf[4:4 + ml]
                    self.buf = self.buf[4 + ml:]
                    return ("handshake", mt, body)
            hdr = self._recv_exact(5)
            body = self._recv_exact(int.from_bytes(hdr[3:5], "big"))
            self.raw += hdr + body
            if hdr[0] == 21:
                return ("alert", body[0] if body else None, body[1] if len(body) > 1 else None)
            if hdr[0] != 22:
                return ("other", hdr[0], None)
            self.buf += body


def parse_server_hello(body: bytes) -> dict:
    i = 0
    legacy_version = body[i:i + 2]; i += 2
    random = body[i:i + 32]; i += 32
    sid_len = body[i]; i += 1 + sid_len
    cipher = int.from_bytes(body[i:i + 2], "big"); i += 2
    i += 1  # compression
    out = {"hrr": random == HRR_RANDOM, "cipher": cipher, "version": int.from_bytes(legacy_version, "big"),
           "group": None}
    if i + 2 <= len(body):
        end = i + 2 + int.from_bytes(body[i:i + 2], "big")
        i += 2
        while i + 4 <= end:
            et = int.from_bytes(body[i:i + 2], "big")
            el = int.from_bytes(body[i + 2:i + 4], "big")
            ed = body[i + 4:i + 4 + el]
            i += 4 + el
            if et == 0x002B and len(ed) >= 2:
                out["version"] = int.from_bytes(ed[:2], "big")
            elif et == 0x0033 and len(ed) >= 2:
                out["group"] = int.from_bytes(ed[:2], "big")
    return out


def probe(host: str, port: int, profile: str, timeout: float = 8.0, connect_to: str = None) -> dict:
    """One ClientHello, one reply. Returns an observation dict."""
    t0 = time.monotonic()
    obs = {"profile": profile, "outcome": None, "tls_version": None, "cipher": None, "group": None,
           "group_name": None, "group_class": None, "alert": None, "error": None, "ip": None,
           "raw_reply_sha256": None, "raw_reply_hex": None, "raw_truncated": False, "ms": None}
    sock = None
    try:
        sock = socket.create_connection((connect_to or host, port), timeout=timeout)
        obs["ip"] = sock.getpeername()[0]
        sock.sendall(build_client_hello(host, profile))
        rd = HandshakeReader(sock, time.monotonic() + timeout)
        kind, a, b = rd.next()
        if kind == "alert":
            obs["outcome"] = "alert"
            obs["alert"] = ALERTS.get(b, f"alert_{b}")
        elif kind == "other":
            obs["outcome"] = "unexpected_record"
            obs["error"] = f"record_type_{a}"
        elif a != 2:
            obs["outcome"] = "unexpected_message"
            obs["error"] = f"handshake_type_{a}"
        else:
            sh = parse_server_hello(b)
            obs["cipher"] = f"0x{sh['cipher']:04x}"
            if sh["version"] == 0x0304:
                obs["tls_version"] = "1.3"
                obs["outcome"] = "hello_retry" if sh["hrr"] else "server_hello"
                obs["group"] = sh["group"]
            else:
                obs["tls_version"] = {0x0303: "1.2", 0x0302: "1.1", 0x0301: "1.0"}.get(sh["version"], hex(sh["version"]))
                obs["outcome"] = "server_hello"
                # TLS 1.2: the curve is in ServerKeyExchange, sent in the clear
                for _ in range(6):
                    kind, mt, mb = rd.next()
                    if kind != "handshake":
                        break
                    if mt == 12:
                        if mb and mb[0] == 3:
                            obs["group"] = int.from_bytes(mb[1:3], "big")
                        else:
                            obs["group_name"] = "non_ec_dhe"
                        break
                    if mt == 14:
                        obs["group_name"] = "rsa_key_transport"
                        break
            if obs["group"] is not None:
                obs["group_name"] = GROUPS.get(obs["group"], f"0x{obs['group']:04x}")
                obs["group_class"] = group_class(obs["group"])
                obs["group"] = f"0x{obs['group']:04x}"
            elif obs["group_name"] in ("rsa_key_transport", "non_ec_dhe"):
                obs["group_class"] = "classical"
        obs["raw_reply_sha256"] = hashlib.sha256(rd.raw).hexdigest()
        obs["raw_reply_hex"] = rd.raw[:RAW_KEEP].hex()
        obs["raw_truncated"] = len(rd.raw) > RAW_KEEP
    except socket.gaierror:
        obs["outcome"], obs["error"] = "error", "dns"
    except (socket.timeout, TimeoutError):
        obs["outcome"], obs["error"] = "error", "timeout"
    except ConnectionRefusedError:
        obs["outcome"], obs["error"] = "error", "refused"
    except (ConnectionResetError, ConnectionError, BrokenPipeError):
        obs["outcome"], obs["error"] = "error", "reset_or_closed"
    except OSError as e:
        obs["outcome"], obs["error"] = "error", f"os_{e.errno}"
    except Exception as e:  # malformed reply etc.
        obs["outcome"], obs["error"] = "error", f"parse_{type(e).__name__}"
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        obs["ms"] = round(1000 * (time.monotonic() - t0))
    return obs


NETWORK_FAIL = {"dns", "timeout", "refused", "reset_or_closed"}
