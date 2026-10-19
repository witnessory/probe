"""
SSH key exchange: the server's identification line and its KEXINIT (the methods it offers). Sends its own
identification and KEXINIT, reads the server's, and disconnects: no key exchange, no login.

The same measurement as the Witnessory observatory's ssh sensor, so a probe's result means exactly what the
observatory's figure means. The identification line names the probe and links to what it is. Standard library only.
"""

import hashlib
import os
import socket
import struct
import time

INSTRUMENT = "ssh_sensor"
INSTRUMENT_VERSION = "1.1.0"
DEFINITION_VERSION = "1"
CLIENT_ID = "SSH-2.0-witnessory_probe https://witnessory.org/probe.html"
MSG_KEXINIT = 20
MAX_PACKET = 35000            # the size every SSH implementation must accept (RFC 4253)
MAX_NAMES, MAX_NAME = 64, 128   # names kept per list, and characters per name
KEXINIT_KEEP = 4096          # bytes of the server's offer kept in the result
MAX_PRE_BANNER_LINES = 32

# Default key-exchange order of the OpenSSH 10.2p1 client (`ssh -G`), used as the reference client
# for "what a current client would get". Recorded in every reading.
REFERENCE_CLIENT = {"name": "OpenSSH 10.2p1 default KexAlgorithms", "kex": [
    "mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"]}

# Names in the kex list that are protocol signals, not key-exchange methods.
PSEUDO = ("ext-info-", "kex-strict-", "kex-guess")


def kex_class(name: str) -> str:
    n = name.lower()
    if n.startswith(PSEUDO) or "ext-info" in n or "kex-strict" in n:
        return "signal"
    if "mlkem" in n:
        return "mlkem_hybrid"
    if "sntrup" in n:
        return "sntrup_hybrid"
    if "kyber" in n:
        return "pq_draft_obsolete"
    return "classical"


PQ_CLASSES = ("mlkem_hybrid", "sntrup_hybrid")


# --------------------------------------------------------------------------
# Wire format (RFC 4251 section 5, RFC 4253 sections 4.2, 6, 7.1)
# --------------------------------------------------------------------------

def name_list(names) -> bytes:
    b = ",".join(names).encode("ascii")
    return struct.pack("!I", len(b)) + b


def build_kexinit() -> bytes:
    """A client KEXINIT: the reference client's kex order and common defaults for the rest."""
    lists = [REFERENCE_CLIENT["kex"] + ["ext-info-c"],
             ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"],
             ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"],
             ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"],
             ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"], ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"],
             ["none"], ["none"], [], []]
    payload = bytes([MSG_KEXINIT]) + os.urandom(16) + b"".join(name_list(l) for l in lists) + b"\x00" + b"\x00" * 4
    return packet(payload)


def packet(payload: bytes) -> bytes:
    """Unencrypted binary packet: length, padding length, payload, random padding (block size 8, min 4)."""
    pad = 8 - ((5 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    return struct.pack("!IB", 1 + len(payload) + pad, pad) + payload + os.urandom(pad)


def parse_kexinit(payload: bytes) -> dict:
    if not payload or payload[0] != MSG_KEXINIT:
        raise ValueError(f"not a KEXINIT (message {payload[0] if payload else None})")
    i = 17                                        # message byte + 16-byte cookie
    fields = ["kex", "host_key", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c",
              "lang_c2s", "lang_s2c"]
    out = {}
    for f in fields:
        (n,) = struct.unpack("!I", payload[i:i + 4])
        raw = payload[i + 4:i + 4 + n]
        if len(raw) != n:
            raise ValueError("truncated name-list")
        out[f] = [x[:MAX_NAME] for x in raw.decode("ascii", "replace").split(",") if x][:MAX_NAMES]
        i += 4 + n
    out["first_kex_packet_follows"] = bool(payload[i]) if i < len(payload) else None
    return out


class Reader:
    def __init__(self, sock, deadline):
        self.sock, self.deadline, self.buf = sock, deadline, b""

    def _fill(self, n):
        while len(self.buf) < n:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("read deadline exceeded")
            self.sock.settimeout(left)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed by peer")
            self.buf += chunk

    def line(self, limit=8192):
        while b"\n" not in self.buf:
            if len(self.buf) > limit:
                raise ValueError("identification line too long")
            self._fill(len(self.buf) + 1)
        ln, self.buf = self.buf.split(b"\n", 1)
        return ln.rstrip(b"\r")

    def packet_payload(self):
        self._fill(5)
        length, pad = struct.unpack("!IB", self.buf[:5])
        if length < 5 or length > MAX_PACKET or pad >= length:
            raise ValueError("implausible packet length")
        self._fill(4 + length)
        payload = self.buf[5:4 + length - pad]
        self.buf = self.buf[4 + length:]
        return payload


def observe(host, port=22, timeout=6.0, connect_to=None, keep_raw=True):
    t0 = time.monotonic()
    obs = {"outcome": None, "error": None, "ip": None, "banner": None, "pre_banner_lines": 0,
           "kex": None, "host_key": None, "enc_s2c": None, "mac_s2c": None,
           "kex_classes": None, "reference_client_selects": None, "reference_client_class": None,
           "kexinit_sha256": None, "kexinit_hex": None, "ms": None}
    sock = None
    try:
        sock = socket.create_connection((connect_to or host, port), timeout=timeout)
        obs["ip"] = sock.getpeername()[0]
        rd = Reader(sock, time.monotonic() + timeout)
        while True:                               # servers may send other lines before the SSH- line
            ln = rd.line()
            if ln.startswith(b"SSH-"):
                obs["banner"] = ln.decode("ascii", "replace")[:255]
                break
            obs["pre_banner_lines"] += 1
            if obs["pre_banner_lines"] > MAX_PRE_BANNER_LINES:
                raise ValueError("no SSH identification line")
        if not (obs["banner"].startswith("SSH-2.0-") or obs["banner"].startswith("SSH-1.99-")):
            obs["outcome"] = "not_ssh2"
            return obs
        sock.sendall(CLIENT_ID.encode("ascii") + b"\r\n" + build_kexinit())
        payload = rd.packet_payload()
        ki = parse_kexinit(payload)
        obs.update({"kex": ki["kex"], "host_key": ki["host_key"], "enc_s2c": ki["enc_s2c"],
                    "mac_s2c": ki["mac_s2c"]})
        classes = {}
        for k in ki["kex"]:
            c = kex_class(k)
            if c != "signal":
                classes[c] = classes.get(c, 0) + 1
        obs["kex_classes"] = dict(sorted(classes.items()))
        offered = set(ki["kex"])
        pick = next((k for k in REFERENCE_CLIENT["kex"] if k in offered), None)
        obs["reference_client_selects"] = pick
        obs["reference_client_class"] = kex_class(pick) if pick else "no_common_method"
        obs["kexinit_sha256"] = hashlib.sha256(payload).hexdigest()
        if keep_raw:
            obs["kexinit_hex"] = payload.hex() if len(payload) <= KEXINIT_KEEP else None
        obs["outcome"] = "kexinit"
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
    except Exception as e:  # malformed reply
        obs["outcome"], obs["error"] = "error", f"parse_{type(e).__name__}"
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        obs["ms"] = round(1000 * (time.monotonic() - t0))
    return obs
