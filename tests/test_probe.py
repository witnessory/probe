"""The probe's rules, offline: keys, task checks, target safety, measurements, sealing, and a full run cycle."""

import json
import os
import shutil
import socket
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization as ser

from witnessory_probe import client, core, measures, targets, tasks
from witnessory_probe.home import Busy, Probe

from helpers import FakeCoordinator, LocalServer, SSHServer, TaskSigner, tls_alert, tls_server_hello

SETTINGS = {"max_targets_per_task": 100, "disabled_measures": []}


class Keys(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_hybrid_keys_sign_and_verify(self):
        k = core.Keys.create(os.path.join(self.dir, "k"))
        self.assertEqual(sorted(k.private), ["ed25519", "mldsa65"] if core.has_mldsa() else ["ed25519"])
        sigs = k.sign_all(b"data")
        self.assertTrue(core.verify_all(k.public_keys(), b"data", sigs))
        self.assertFalse(core.verify_all(k.public_keys(), b"other", sigs))
        if core.has_mldsa():                                     # a hybrid set needs every signature
            self.assertFalse(core.verify_all(k.public_keys(), b"data", {"ed25519": sigs["ed25519"]}))

    def test_probe_id_is_the_hash_of_the_ed25519_key(self):
        k = core.Keys.create(os.path.join(self.dir, "k"))
        der = k.private["ed25519"].public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(k.probe_id(), core.sha256(der))
        self.assertEqual(core.Keys(os.path.join(self.dir, "k")).probe_id(), k.probe_id())   # reloads the same
        self.assertNotIn("\r", k.public_keys()["ed25519"])


class Tasks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = TaskSigner()
        cls.trusted = [cls.signer.keyset]

    def check(self, env, probe_id="p" * 64, settings=SETTINGS, seen=()):
        return tasks.check(env, self.trusted, probe_id, settings, set(seen))

    def rejected(self, env, reason, **kw):
        with self.assertRaises(tasks.Rejected) as cm:
            self.check(env, **kw)
        self.assertEqual(str(cm.exception), reason)

    def test_a_valid_task_passes_with_clean_targets(self):
        t = self.check(self.signer.sign(self.signer.task(targets=["Example.ORG", "example.org.", "https://b.example/x"])))
        self.assertEqual(t["targets"], ["example.org", "b.example"])

    def test_signatures_and_keys(self):
        env = self.signer.sign(self.signer.task())
        env["task"]["targets"] = ["changed.example"]
        self.rejected(env, "bad signature")
        other = TaskSigner()
        self.rejected(other.sign(other.task()), "untrusted key")
        env = self.signer.sign(self.signer.task())
        env["signatures"].pop("ed25519")
        self.rejected(env, "bad signature")

    def test_time_rules(self):
        s = self.signer
        self.rejected(s.sign(s.task(valid_hours=1, start_offset_min=-180)), "expired")
        self.rejected(s.sign(s.task(start_offset_min=60)), "not yet valid")
        self.rejected(s.sign(s.task(valid_hours=24 * 8)), "bad validity")
        t = s.task()
        self.check(s.sign(s.task(start_offset_min=3)))                  # within the clock allowance
        self.rejected(s.sign(t), "already run", seen=[t["task_id"]])

    def test_scope_rules(self):
        s = self.signer
        self.rejected(s.sign(s.task(probe_id="q" * 64)), "another probe")
        self.rejected(s.sign(s.task(measure="shell")), "unknown measure")
        self.rejected(s.sign(s.task(measure="ssh_kex")), "measure turned off by host",
                      settings=dict(SETTINGS, disabled_measures=["ssh_kex"]))
        self.rejected(s.sign(s.task(params={"port": 8443})), "unknown parameter")
        self.rejected(s.sign(s.task(targets=[])), "no targets")
        self.rejected(s.sign(s.task(targets=[f"s{i}.example" for i in range(101)])), "too many targets")
        self.rejected(s.sign(s.task(targets=[f"s{i}.example" for i in range(1001)])), "too many targets",
                      settings=dict(SETTINGS, max_targets_per_task=5000))
        for bad in ("10.0.0.1", "[::1]", "2001:db8::1", "localhost", "example.org:22", "a..b", ""):
            self.rejected(s.sign(s.task(targets=["fine.example", bad])), "invalid target")
        self.rejected(s.sign(s.task(extra="field")), "malformed")


class Targets(unittest.TestCase):
    def test_non_public_addresses_are_never_contacted(self):
        real = socket.getaddrinfo
        socket.getaddrinfo = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))]
        try:
            o = measures.tls_pq("internal.example")
            self.assertEqual(o["outcome"], "refused_non_public")
            self.assertEqual(measures.ssh_kex("internal.example")["outcome"], "refused_non_public")
        finally:
            socket.getaddrinfo = real


class Measures(unittest.TestCase):
    def setUp(self):
        self.ports = (measures.TLS_PORT, measures.SSH_PORT)
        targets.TEST_RESOLVE = {"site.test": "127.0.0.1", "www.site.test": "127.0.0.1"}

    def tearDown(self):
        measures.TLS_PORT, measures.SSH_PORT = self.ports
        targets.TEST_RESOLVE = None

    def serve_tls(self, reply):
        srv = LocalServer(lambda first: reply if first[:1] == b"\x16" else None)
        self.addCleanup(srv.close)
        measures.TLS_PORT = srv.port

    def test_ready(self):
        self.serve_tls(tls_server_hello())
        o = measures.tls_pq("site.test")
        self.assertEqual((o["level"], o["browser"]["group_name"], o["browser"]["tls_version"]),
                         ("ready", "X25519MLKEM768", "1.3"))
        self.assertFalse(measures.failed(o))

    def test_classical(self):
        self.serve_tls(tls_server_hello(group=0x001D))
        self.assertEqual(measures.tls_pq("site.test")["level"], "not_yet")

    def test_alert_is_an_answer(self):
        self.serve_tls(tls_alert())
        o = measures.tls_pq("site.test")
        self.assertEqual((o["level"], o["browser"]["alert"]), ("not_yet", "handshake_failure"))

    def test_nothing_listening(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        measures.TLS_PORT = s.getsockname()[1]
        s.close()
        o = measures.tls_pq("site.test")
        self.assertEqual(o["level"], "unknown")
        self.assertTrue(measures.failed(o))

    def test_ssh(self):
        srv = SSHServer()
        self.addCleanup(srv.close)
        measures.SSH_PORT = srv.port
        o = measures.ssh_kex("site.test")["ssh"]
        self.assertEqual((o["outcome"], o["reference_client_selects"], o["banner"]),
                         ("kexinit", "mlkem768x25519-sha256", "SSH-2.0-OpenSSH_10.2"))


class Home(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.probe = Probe(os.path.join(self.dir, "p"))
        self.probe.init()

    def header(self, bid):
        with open(os.path.join(self.probe.bundles, bid + ".json"), "rb") as f:
            return json.loads(f.read())

    def test_genesis_is_the_signed_card(self):
        p = self.probe
        bid = p.state["head"]
        h = self.header(bid)
        self.assertEqual((h["seq"], h["prev"], h["layer"], h["type"], h["protocol"]),
                         (0, None, "identity", "nullius.bundle", 3))
        with open(os.path.join(p.bundles, bid + ".json"), "rb") as f:
            body = f.read()
        self.assertEqual(core.sha256(body), bid)
        up = p.bundle_upload(bid)
        self.assertTrue(core.verify_all(p.card["public_keys"], body, up["signatures"]))
        card = json.loads(core.unb64(up["files"][h["files"][0]["sha256"]]))
        self.assertEqual(card["probe_id"], p.probe_id)
        with self.assertRaises(FileExistsError):
            Probe(p.home).init()

    def test_chain_and_recovery_from_a_lost_state(self):
        p = self.probe
        first = p.state["head"]
        b1 = p.seal("tls_pq", "ok", [("result", "result.json", b"{}")], None, core.utc_now(), None)
        self.assertEqual((self.header(b1)["seq"], self.header(b1)["prev"]), (1, first))
        os.remove(os.path.join(p.home, "state.json"))
        q = Probe(p.home)
        q.acquire()
        self.addCleanup(q.release)
        self.assertEqual((q.state["seq"], q.state["head"]), (2, b1))     # never reuses a position
        with self.assertRaises(Busy):
            Probe(p.home).acquire()


class RunCycle(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.coord = FakeCoordinator()
        self.addCleanup(self.coord.close)
        self.signer = TaskSigner()
        self.probe = Probe(os.path.join(self.dir, "p"))
        self.probe.init()
        self.probe.update_settings(trusted_task_keys=[self.signer.keyset])
        srv = LocalServer(lambda first: tls_server_hello() if first[:1] == b"\x16" else None)
        self.addCleanup(srv.close)
        self.port = measures.TLS_PORT
        measures.TLS_PORT = srv.port
        targets.TEST_RESOLVE = {"site.test": "127.0.0.1"}

    def tearDown(self):
        measures.TLS_PORT = self.port
        targets.TEST_RESOLVE = None

    def test_end_to_end(self):
        p, c, s = self.probe, self.coord, self.signer
        good = s.sign(s.task())
        unsigned = {"task": s.task(), "key_id": s.keyset["key_id"], "signatures": {}}
        c.queue = [good, s.sign(s.task(measure="shell")), unsigned]
        r = client.cycle(p, client.Coordinator(c.url, p))
        self.assertEqual((len(r["ran"]), len(r["refused"]), r["sent"], r["next_poll_s"]), (1, 2, 2, 120))
        self.assertEqual(c.errors, [])
        self.assertEqual(sorted(x["reason"] for x in c.refusals), ["bad signature", "unknown measure"])
        self.assertEqual(p.state["unsent"], [])
        headers = sorted((json.loads(core.unb64(b["header_b64"])) for b in c.bundles.values()), key=lambda h: h["seq"])
        self.assertEqual([h["layer"] for h in headers], ["identity", "tls_pq"])
        self.assertEqual(headers[1]["prev"], core.sha256(core.canonical(headers[0])))
        self.assertEqual(headers[1]["task"]["task_id"], good["task"]["task_id"])
        result = json.loads(core.unb64(c.bundles[core.sha256(core.canonical(headers[1]))]["files"]
                                       [headers[1]["files"][0]["sha256"]]))
        self.assertEqual(result["observations"][0]["level"], "ready")
        self.assertEqual([e["outcome"] for e in p.read_log()],
                         ["ok", "refused: unknown measure", "refused: bad signature"])
        c.queue = [good]                                             # the same task again
        r = client.cycle(p, client.Coordinator(c.url, p))
        self.assertEqual(r["refused"], [(good["task"]["task_id"], "already run")])

    def test_limits_and_pause(self):
        p, c, s = self.probe, self.coord, self.signer
        coord = client.Coordinator(c.url, p)
        p.update_settings(max_targets_per_hour=1)
        c.queue = [s.sign(s.task(targets=["site.test", "other.test"]))]
        self.assertEqual(client.cycle(p, coord)["refused"][0][1], "over the host's hourly limit")
        p.update_settings(paused=True)
        c.queue = [s.sign(s.task())]
        self.assertEqual(client.cycle(p, coord)["ran"], [])
        self.assertEqual(len(c.queue), 1)                            # a paused probe does not even ask

    def test_nothing_is_lost_when_the_coordinator_is_down(self):
        p = self.probe
        dead = client.Coordinator("http://127.0.0.1:9", p)
        with self.assertRaises(client.Unreachable):
            client.cycle(p, dead)
        self.assertEqual(len(p.state["unsent"]), 1)
        r = client.cycle(p, client.Coordinator(self.coord.url, p))
        self.assertEqual((r["sent"], p.state["unsent"]), (1, []))


@unittest.skipUnless(os.environ.get("WITNESSORY_LIVE"), "live network test: set WITNESSORY_LIVE=1")
class Live(unittest.TestCase):
    def test_a_known_ready_site(self):
        self.assertEqual(measures.tls_pq("cloudflare.com")["level"], "ready")


if __name__ == "__main__":
    unittest.main()
