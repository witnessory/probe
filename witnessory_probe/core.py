"""
Primitives: canonical JSON, hashes, times, and the probe's keys (Ed25519, plus ML-DSA-65 where the installed
cryptography library supports it).

Signatures are byte-compatible with the observatory's records: the same canonical JSON, the same raw-message
signatures that `openssl pkeyutl -sign -rawin` makes, the same probe ID (SHA-256 of the Ed25519 public key's DER).
Private keys are PKCS#8 PEM written by this library; they never leave the host.
"""

import base64
import datetime as dt
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:                                   # an older cryptography: Ed25519 only
    mldsa = None

PROTOCOL = 3


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def write_atomic(path, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def write_json(path, obj):
    write_atomic(path, json.dumps(obj, indent=1, sort_keys=True).encode())


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


# ---------------------------------------------------------------- keys

def has_mldsa() -> bool:
    if mldsa is None:
        return False
    try:
        mldsa.MLDSA65PrivateKey.generate()
        return True
    except UnsupportedAlgorithm:
        return False


def _generate(alg):
    if alg == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return mldsa.MLDSA65PrivateKey.generate()


def public_pem(key) -> str:
    """The public key as PEM with LF line endings: one text per key on every platform."""
    pub = key.public_key() if hasattr(key, "public_key") else key
    return pub.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode().replace("\r\n", "\n")


def pem_der(pem: str) -> bytes:
    return ser.load_pem_public_key(pem.encode()).public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)


def probe_id(ed25519_pem: str) -> str:
    return sha256(pem_der(ed25519_pem))


def key_id(public_keys: dict) -> str:
    """The ID of a key set {alg: pem}: SHA-256 of the canonical JSON of {alg: SHA-256 of DER}."""
    return sha256(canonical({alg: sha256(pem_der(pem)) for alg, pem in public_keys.items()}))


class Keys:
    """A key set on disk: <dir>/<alg>.key (private, PKCS#8 PEM) and <alg>.pub."""

    def __init__(self, keydir):
        self.dir = keydir
        self.private = {}
        for fn in sorted(os.listdir(keydir)):
            if fn.endswith(".key"):
                with open(os.path.join(keydir, fn), "rb") as f:
                    self.private[fn[:-4]] = ser.load_pem_private_key(f.read(), None)
        if "ed25519" not in self.private:
            raise FileNotFoundError(f"no ed25519 key in {keydir}")

    @staticmethod
    def create(keydir):
        os.makedirs(keydir, exist_ok=True)
        try:
            os.chmod(keydir, 0o700)
        except OSError:
            pass
        for alg in ["ed25519"] + (["mldsa65"] if has_mldsa() else []):
            key = _generate(alg)
            path = os.path.join(keydir, f"{alg}.key")
            write_atomic(path, key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            write_atomic(os.path.join(keydir, f"{alg}.pub"), public_pem(key).encode())
        return Keys(keydir)

    def public_keys(self) -> dict:
        return {alg: public_pem(k) for alg, k in self.private.items()}

    def probe_id(self) -> str:
        return probe_id(public_pem(self.private["ed25519"]))

    def sign_all(self, data: bytes) -> dict:
        return {alg: b64(k.sign(data)) for alg, k in sorted(self.private.items())}

    def sign_ed25519(self, data: bytes) -> str:
        return b64(self.private["ed25519"].sign(data))


def verify(pem: str, data: bytes, sig: bytes) -> bool:
    try:
        ser.load_pem_public_key(pem.encode()).verify(sig, data)
        return True
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        return False


def verify_all(public_keys: dict, data: bytes, signatures: dict) -> bool:
    """True only if every key in the set has a valid signature (a hybrid set needs both)."""
    if not public_keys:
        return False
    for alg, pem in public_keys.items():
        s = signatures.get(alg)
        try:
            if not s or not verify(pem, data, unb64(s)):
                return False
        except ValueError:
            return False
    return True
