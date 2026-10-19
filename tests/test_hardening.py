"""Hardening found necessary by the pre-launch review: what a hostile coordinator, server or name cannot do."""

import http.server
import ipaddress
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest

from witnessory_probe import client, core, home, measures, targets, tasks
from witnessory_probe.home import Probe

from helpers import FakeCoordinator, LocalServer, SSHServer, TaskSigner, tls_server_hello


class Base(unittest.TestCase):
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
        targets.TEST_RESOLVE = {"site.test": "127.0.0.1", "other.test": "127.0.0.1"}

    def tearDown(self):
        measures.TLS_PORT = self.port
        targets.TEST_RESOLVE = None

    def cycle(self):
        return client.cycle(self.probe, client.Coordinator(self.coord.url, self.probe))


class Coordinator(Base):
    def test_redirects_are_never_followed(self):
        hits = []
        lan = LocalServer(lambda first: hits.append(first) or b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        self.addCleanup(lan.close)

        class Redirect(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{lan.port}/admin")
                self.end_headers()
            do_POST = do_GET

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        with self.assertRaises(client.Unreachable):
            client.cycle(self.probe, client.Coordinator(f"http://127.0.0.1:{srv.server_address[1]}", self.probe))
        self.assertEqual(hits, [])

    def test_the_coordinator_must_be_https(self):
        for bad in ("http://coordinator.example.org", "ftp://x.example", "", "https://"):
            with self.assertRaises(ValueError):
                client.Coordinator(bad, self.probe)
        client.Coordinator("https://coordinator.example.org", self.probe)
        client.Coordinator("http://127.0.0.1:8080", self.probe)

    def test_malformed_tasks_are_refused_and_the_rest_runs(self):
        s = self.signer
        good = s.sign(s.task())
        sig_list = s.sign(s.task())
        sig_list["signatures"] = ["x"]
        sig_int = s.sign(s.task())
        sig_int["signatures"] = {"ed25519": 5, "mldsa65": None}
        surrogate = s.sign(s.task())
        surrogate["task"]["targets"] = ["\ud800.example"]
        self.coord.queue = [7, "x", None, [], {"task": 3}, sig_list, sig_int, surrogate, good]
        r = self.cycle()
        self.assertEqual(r["ran"], [good["task"]["task_id"]])
        self.assertEqual(len(r["refused"]), 8)

    def test_malformed_answers_do_not_stop_the_probe(self):
        for raw in (b'{"tasks": "nope", "next_poll_s": "soon"}', b'[1, 2]', b'{"tasks": [1]}'):
            self.coord.raw_answer = raw
            try:
                r = self.cycle()
                self.assertEqual(r["ran"], [])
            except client.Unreachable:
                pass                                      # a non-object answer is "unreachable", not a crash

    def test_no_poll_when_the_hour_is_used_up(self):
        self.probe.update_settings(max_targets_per_hour=10)
        self.probe.spend(10)
        self.probe.save_state()
        self.cycle()
        self.assertEqual(self.coord.polls, [])
        self.probe.state["hour"] = None
        self.cycle()
        self.assertIn("budget=10", self.coord.polls[0])
        self.assertIn("measures=tls_pq%2Cssh_kex", self.coord.polls[0])


class Results(Base):
    def test_one_site_error_does_not_sink_the_task(self):
        real = measures.MEASURES["tls_pq"]["run"]

        def flaky(name):
            if name == "other.test":
                raise RuntimeError("surprise")
            return real(name)
        measures.MEASURES["tls_pq"]["run"] = flaky
        self.addCleanup(measures.MEASURES["tls_pq"].__setitem__, "run", real)
        self.coord.queue = [self.signer.sign(self.signer.task(targets=["site.test", "other.test"]))]
        self.assertEqual(len(self.cycle()["ran"]), 1)
        b = list(self.coord.bundles.values())[-1]
        h = json.loads(core.unb64(b["header_b64"]))
        result = json.loads(core.unb64(b["files"][h["files"][0]["sha256"]]))
        self.assertEqual([o["outcome"] for o in result["observations"]], ["measured", "no_answer"])
        self.assertEqual(h["status"], "partial")

    def test_results_always_fit(self):
        big = {"type": "witnessory.result", "observations": [
            {"target": f"s{i}.example", "browser": {"raw_reply_hex": "ab" * 2048}, "pq_only": {"raw_reply_hex": "cd" * 2048}}
            for i in range(200)]}
        data = home.fit(big)
        self.assertLessEqual(len(data), home.RESULT_MAX)
        r = json.loads(data)
        self.assertTrue(any(o["browser"].get("raw_dropped") for o in r["observations"]))
        self.assertEqual(len(r["observations"]), 200)                       # nothing omitted: only copies dropped
        huge = {"type": "witnessory.result", "observations": [{"target": "x" * 5000} for _ in range(200)]}
        data = home.fit(huge)
        r = json.loads(data)
        self.assertLessEqual(len(data), home.RESULT_MAX)
        self.assertGreater(r["observations_omitted"], 0)
        self.assertEqual(len(r["observations"]), 200)                       # reduced, never removed

    def test_a_few_oversized_answers_never_push_out_the_others(self):
        honest = [{"target": f"h{i}.example", "outcome": "measured", "level": "ready"} for i in range(48)]
        hostile = [{"target": f"x{i}.example", "outcome": "measured", "ssh": {"kex": ["k" * 60] * 64,
                    "host_key": ["h" * 60] * 64, "kexinit_hex": "ab" * 2048}} for i in range(2)]
        obs = [measures.bounded(o) for o in hostile + honest]
        self.assertTrue(all(len(core.canonical(o)) <= measures.OBS_MAX for o in obs))
        r = json.loads(home.fit({"type": "witnessory.result", "observations": obs}))
        self.assertEqual([o["target"] for o in r["observations"][2:]], [o["target"] for o in honest])
        self.assertNotIn("observations_omitted", r)

    def test_a_bundle_sealed_just_before_a_crash_is_still_sent(self):
        p = self.probe
        before = dict(p.state, unsent=list(p.state["unsent"]))
        bid = p.seal("tls_pq", "ok", [("result", "result.json", b"{}")], None, core.utc_now(), None)
        core.write_json(os.path.join(p.home, "state.json"), before)      # the crash: state not saved
        q = Probe(p.home)
        q.acquire()
        self.addCleanup(q.release)
        self.assertIn(bid, q.state["unsent"])
        self.assertEqual(q.state["head"], bid)

    def test_old_sent_results_are_pruned_but_headers_stay(self):
        import datetime as dt
        p = self.probe
        bid = p.seal("tls_pq", "ok", [("result", "result.json", b'{"old": 1}')], None, core.utc_now(), None)
        p.mark_sent(bid)
        keep = p.seal("tls_pq", "ok", [("result", "result.json", b'{"unsent": 1}')], None, core.utc_now(), None)
        later = core.utc_now() + dt.timedelta(days=31)
        self.assertEqual(p.prune(now=later), 1)
        self.assertFalse(os.path.exists(os.path.join(p.objects, core.sha256(b'{"old": 1}'))))
        self.assertTrue(os.path.exists(os.path.join(p.bundles, bid + ".json")))
        self.assertTrue(os.path.exists(os.path.join(p.objects, core.sha256(b'{"unsent": 1}'))))   # not sent yet
        self.assertIn(keep, p.state["unsent"])
        self.assertTrue(os.path.exists(os.path.join(p.home, "card.json")))

    def test_an_unreadable_bundle_is_set_aside(self):
        p = self.probe
        bid = p.seal("tls_pq", "ok", [("result", "result.json", b'{"lost": 1}')], None, core.utc_now(), None)
        os.remove(os.path.join(p.objects, core.sha256(b'{"lost": 1}')))
        self.coord.queue = [self.signer.sign(self.signer.task())]
        r = self.cycle()
        self.assertEqual(len(r["ran"]), 1)
        self.assertNotIn(bid, p.state["unsent"])
        self.assertEqual(p.state["rejected"][-1]["bundle"], bid)


class Resilience(Base):
    def test_a_bundle_the_coordinator_keeps_failing_does_not_block_new_tasks(self):
        p = self.probe
        stuck = p.seal("tls_pq", "ok", [("result", "result.json", b'{"s": 1}')], None, core.utc_now(), None)
        real = client.Coordinator.upload

        def upload(coord, bid):
            if bid == stuck:
                raise client.Unreachable("POST /v1/bundles: HTTP 500", 500)
            return real(coord, bid)
        client.Coordinator.upload = upload
        self.addCleanup(setattr, client.Coordinator, "upload", real)
        self.coord.queue = [self.signer.sign(self.signer.task())]
        r = self.cycle()
        self.assertEqual(len(r["ran"]), 1)                              # new work went ahead
        self.assertEqual(p.state["unsent"], [stuck])                    # the stuck one waits at the back

    def test_a_corrupt_state_file_is_rebuilt(self):
        p = self.probe
        head = p.state["head"]
        with open(os.path.join(p.home, "state.json"), "w") as f:
            f.write("{not json")
        q = Probe(p.home)
        q.acquire()
        self.addCleanup(q.release)
        self.assertEqual((q.state["seq"], q.state["head"]), (1, head))

    def test_set_aside_results_are_never_pruned(self):
        import datetime as dt
        p = self.probe
        bid = p.seal("tls_pq", "ok", [("result", "result.json", b'{"kept": 1}')], None, core.utc_now(), None)
        p.set_aside(bid, "HTTP 409")
        self.assertEqual(p.prune(now=core.utc_now() + dt.timedelta(days=40)), 0)
        self.assertTrue(os.path.exists(os.path.join(p.objects, core.sha256(b'{"kept": 1}'))))

    def test_the_per_task_limit_is_sent(self):
        self.probe.update_settings(max_targets_per_task=7)
        self.cycle()
        self.assertIn("max_per_task=7", self.coord.polls[0])

    def test_stopping_happens_between_tasks(self):
        s = self.signer
        self.coord.queue = [s.sign(s.task()), s.sign(s.task())]
        done = []
        r = client.cycle(self.probe, client.Coordinator(self.coord.url, self.probe), stop=lambda: bool(done) or done.append(1))
        self.assertEqual(len(r["ran"]), 1)


class Servers(unittest.TestCase):
    def setUp(self):
        self.ports = (measures.TLS_PORT, measures.SSH_PORT)
        targets.TEST_RESOLVE = {"site.test": "127.0.0.1"}

    def tearDown(self):
        measures.TLS_PORT, measures.SSH_PORT = self.ports
        targets.TEST_RESOLVE = None

    def serve(self, data):
        srv = LocalServer(lambda first: data if first[:1] == b"\x16" else None)
        self.addCleanup(srv.close)
        measures.TLS_PORT = srv.port

    def test_an_oversized_handshake_message_is_refused(self):
        body = b"\x00" * 70000                                         # a ServerHello claiming 70,000 bytes
        msg = b"\x02" + len(body).to_bytes(3, "big") + body
        records = b"".join(b"\x16\x03\x03" + len(msg[i:i + 16384]).to_bytes(2, "big") + msg[i:i + 16384]
                           for i in range(0, len(msg), 16384))
        self.serve(records)
        o = measures.tls_pq("site.test")
        self.assertEqual(o["browser"]["error"], "parse_ValueError")

    def test_large_replies_are_kept_short(self):
        pad = b"\x00\x15" + (12000).to_bytes(2, "big") + b"\x00" * 12000          # a padding extension
        key = os.urandom(1120)
        exts = b"\x00\x2b\x00\x02\x03\x04\x00\x33" + (4 + len(key)).to_bytes(2, "big") + b"\x11\xec" + \
            len(key).to_bytes(2, "big") + key + pad
        body = b"\x03\x03" + os.urandom(32) + b"\x00\x13\x01\x00" + len(exts).to_bytes(2, "big") + exts
        msg = b"\x02" + len(body).to_bytes(3, "big") + body
        self.serve(b"\x16\x03\x03" + len(msg).to_bytes(2, "big") + msg)
        o = measures.tls_pq("site.test")
        self.assertEqual(o["level"], "ready")
        self.assertTrue(o["browser"]["raw_truncated"])
        self.assertEqual(len(o["browser"]["raw_reply_hex"]), 4096)

    def test_ssh_name_lists_are_capped(self):
        names = tuple(f"kex{i}-{'x' * 50}" for i in range(100)) + ("bad\x00name", "y" * 300)
        srv = SSHServer(kex=names)
        self.addCleanup(srv.close)
        measures.SSH_PORT = srv.port
        o = measures.ssh_kex("site.test")["ssh"]
        self.assertEqual(len(o["kex"]), 64)                                 # 64 kept
        self.assertTrue(all(len(k) <= 64 and k.isprintable() and k.isascii() for k in o["kex"]))
        self.assertIsNone(o["kexinit_hex"])
        big = SSHServer(kex=tuple(f"kex{i}-{'x' * 300}" for i in range(500)))    # 150 KB: over the packet cap
        self.addCleanup(big.close)
        measures.SSH_PORT = big.port
        self.assertEqual(measures.ssh_kex("site.test")["outcome"], "no_answer")


class Names(unittest.TestCase):
    def test_local_names_and_translated_addresses_are_refused(self):
        for n in ("printer.local", "nas.home.arpa", "intranet.corp", "x.internal", "router.lan"):
            with self.assertRaises(targets.Refused):
                targets.normalise(n)
        for a in ("64:ff9b::a00:1", "64:ff9b:1::1", "2002:c0a8:101::1", "2001:0:4136:e378::1", "::ffff:10.0.0.1",
                  "::a00:1", "fec0::1", "100.64.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "ff02::1",
                  "::ffff:0:a00:1"):
            self.assertFalse(targets.is_public(ipaddress.ip_address(a)), a)
        self.assertTrue(targets.is_public(ipaddress.ip_address("8.8.8.8")))

    def test_names_resolve_as_fully_qualified(self):
        seen = []
        real = socket.getaddrinfo
        socket.getaddrinfo = lambda name, *a, **k: seen.append(name) or [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                                                         ("93.184.215.14", 443))]
        try:
            targets.public_address("example.org", 443)
        finally:
            socket.getaddrinfo = real
        self.assertEqual(seen, ["example.org."])


class Setup(unittest.TestCase):
    def test_a_probe_without_ml_dsa_refuses_to_start(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        real = core.has_mldsa
        core.has_mldsa = lambda: False
        try:
            with self.assertRaises(RuntimeError):
                Probe(os.path.join(d, "p")).init()
        finally:
            core.has_mldsa = real
        self.assertFalse(os.path.exists(os.path.join(d, "p", "card.json")))

    def test_version_must_be_an_integer(self):
        s = TaskSigner()
        with self.assertRaises(tasks.Rejected):
            tasks.check(s.sign(s.task(version=True)), [s.keyset], "p" * 64, {"disabled_measures": []}, set())


if __name__ == "__main__":
    unittest.main()
