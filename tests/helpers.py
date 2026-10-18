"""Local stand-ins for the internet and the coordinator, so the tests run offline."""

import datetime as dt
import http.server
import json
import os
import secrets
import socket
import tempfile
import threading

from witnessory_probe import _ssh, core


class LocalServer:
    """A TCP server on 127.0.0.1 that answers each connection with `reply(first_bytes)` (bytes, or None to
    close without answering)."""

    def __init__(self, reply):
        self.reply = reply
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            conn.settimeout(3)
            first = conn.recv(65536)
            out = self.reply(first)
            if out:
                conn.sendall(out)
                conn.settimeout(0.5)
                try:
                    while conn.recv(65536):
                        pass
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop = True
        self.sock.close()


def tls_server_hello(group=0x11EC, version=0x0304):
    """A TLS 1.3 ServerHello selecting `group` (X25519MLKEM768 by default)."""
    key = os.urandom(1120 if group == 0x11EC else 32)
    exts = (b"\x00\x2b\x00\x02" + version.to_bytes(2, "big")
            + b"\x00\x33" + (4 + len(key)).to_bytes(2, "big") + group.to_bytes(2, "big")
            + len(key).to_bytes(2, "big") + key)
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x13\x01" + b"\x00" + len(exts).to_bytes(2, "big") + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def tls_alert(desc=40):
    return b"\x15\x03\x03\x00\x02\x02" + bytes([desc])


def ssh_reply(kex=("mlkem768x25519-sha256", "curve25519-sha256")):
    lists = [list(kex), ["ssh-ed25519"], ["aes128-ctr"], ["aes128-ctr"], ["hmac-sha2-256"], ["hmac-sha2-256"],
             ["none"], ["none"], [], []]
    payload = bytes([_ssh.MSG_KEXINIT]) + os.urandom(16) + b"".join(_ssh.name_list(x) for x in lists) + b"\x00" * 5
    return b"SSH-2.0-OpenSSH_10.2\r\n" + _ssh.packet(payload)


class SSHServer(LocalServer):
    """SSH speaks first: send the banner and KEXINIT on connect."""

    def __init__(self, kex=("mlkem768x25519-sha256", "curve25519-sha256")):
        self.data = ssh_reply(kex)
        super().__init__(None)

    def _one(self, conn):
        try:
            conn.sendall(self.data)
            conn.settimeout(1)
            try:
                while conn.recv(65536):
                    pass
            except OSError:
                pass
        finally:
            conn.close()


class TaskSigner:
    """The coordinator's task keys, for tests."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.keys = core.Keys.create(os.path.join(self.dir, "k"))
        pub = self.keys.public_keys()
        self.keyset = {"key_id": core.key_id(pub), "public_keys": pub}

    def task(self, measure="tls_pq", targets=("site.test",), probe_id=None, params=None, valid_hours=1,
             start_offset_min=-1, **override):
        now = core.utc_now()
        t = {"type": "witnessory.task", "version": 1, "task_id": secrets.token_hex(16),
             "issued_utc": core.iso(now + dt.timedelta(minutes=start_offset_min)),
             "not_before_utc": core.iso(now + dt.timedelta(minutes=start_offset_min)),
             "expires_utc": core.iso(now + dt.timedelta(minutes=start_offset_min, hours=valid_hours)),
             "probe_id": probe_id, "measure": measure, "targets": list(targets), "params": params or {}}
        t.update(override)
        return t

    def sign(self, task):
        return {"task": task, "key_id": self.keyset["key_id"], "signatures": self.keys.sign_all(core.canonical(task))}


class FakeCoordinator:
    """Enough of the coordinator to test a probe end to end; checks every signature the real one will."""

    def __init__(self):
        self.cards, self.bundles, self.refusals, self.queue, self.errors = {}, {}, [], [], []
        self.served_tasks = 0
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def _authorised(self, body):
                pid = self.headers.get("X-Witnessory-Probe")
                card = fake.cards.get(pid)
                t = self.headers.get("X-Witnessory-Time", "")
                msg = core.canonical({"method": self.command, "path": self.path, "time": t,
                                      "body_sha256": core.sha256(body)})
                try:
                    skew = abs((core.utc_now() - core.parse_iso(t)).total_seconds())
                    sig = core.unb64(self.headers.get("X-Witnessory-Signature", ""))
                except ValueError:
                    return None
                if card and skew < 300 and core.verify(card["public_keys"]["ed25519"], msg, sig):
                    return pid
                fake.errors.append(f"unauthorised {self.command} {self.path}")
                return None

            def do_POST(self):
                body = self._body()
                obj = json.loads(body)
                if self.path == "/v1/enrol":
                    raw = core.unb64(obj["card_b64"])
                    card = json.loads(raw)
                    ok = (core.probe_id(card["public_keys"]["ed25519"]) == card["probe_id"]
                          and core.verify_all(card["public_keys"], raw, obj["signatures"]))
                    if not ok:
                        fake.errors.append("bad enrolment")
                        return self._answer(400, {"error": "bad card"})
                    fake.cards[card["probe_id"]] = card
                    return self._answer(200, {"probe_id": card["probe_id"], "accepted": True})
                pid = self._authorised(body)
                if not pid:
                    return self._answer(401, {"error": "unauthorised"})
                if self.path == "/v1/bundles":
                    hbody = core.unb64(obj["header_b64"])
                    h = json.loads(hbody)
                    files_ok = all(core.sha256(core.unb64(obj["files"][f["sha256"]])) == f["sha256"]
                                   for f in h["files"])
                    if (h["probe_id"] != pid or not files_ok
                            or not core.verify_all(fake.cards[pid]["public_keys"], hbody, obj["signatures"])):
                        fake.errors.append("bad bundle")
                        return self._answer(400, {"error": "bad bundle"})
                    bid = core.sha256(hbody)
                    fake.bundles[bid] = obj
                    return self._answer(200, {"stored": bid})
                if self.path == "/v1/refusals":
                    fake.refusals.append(obj)
                    return self._answer(200, {"ok": True})
                self._answer(404, {"error": "not found"})

            def do_GET(self):
                if self.path == "/v1/tasks" and self._authorised(b""):
                    tasks, fake.queue = fake.queue, []
                    fake.served_tasks += len(tasks)
                    return self._answer(200, {"tasks": tasks, "next_poll_s": 120})
                self._answer(401, {"error": "unauthorised"})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
