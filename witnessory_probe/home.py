"""
The probe's home folder: keys, identity card, settings, the chain of sealed bundles, and the host's log.

  keys/                 ed25519.key/.pub, mldsa65.key/.pub (private keys never leave the host)
  card.json             the probe card (also sealed as bundle 0)
  settings.json         the host's settings: caps, opt-outs, pause, coordinator, trusted task keys
  state.json            position in the chain, unsent bundles, tasks already run, this hour's count
  bundles/              <id>.json and <id>.<alg>.sig
  objects/              files by SHA-256 (results, the card)
  log.jsonl             one line per task: when, type, targets, outcome (what the host reads)
"""

import concurrent.futures as cf
import json
import os
import platform

from . import VERSION, core, measures

DEFAULT_SETTINGS = {
    "coordinator": None,
    "trusted_task_keys": [],            # [{"key_id", "public_keys": {alg: pem}}]
    "max_targets_per_task": 100,
    "max_targets_per_hour": 600,
    "concurrency": 4,
    "disabled_measures": [],
    "paused": False,
}


def shipped_defaults():
    """The coordinator and its public task key set, shipped with this release (defaults.json): a new probe needs
    no setup. A host can change either in settings.json."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "defaults.json")
    return core.read_json(path, {}) or {}


def default_home():
    return os.environ.get("WITNESSORY_PROBE_HOME") or os.path.join(os.path.expanduser("~"), ".witnessory-probe")


class Busy(RuntimeError):
    """Another copy of the probe is using this home."""


class Lock:
    """An exclusive lock on the home, held by the OS: released if the process dies."""

    def __init__(self, path):
        self.f = open(path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.f.close()
            raise Busy(f"another probe is running with {os.path.dirname(path)}")

    def release(self):
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        self.f.close()


class Probe:
    def __init__(self, home=None):
        self.home = home or default_home()
        self.keys_dir = os.path.join(self.home, "keys")
        self.bundles = os.path.join(self.home, "bundles")
        self.objects = os.path.join(self.home, "objects")
        self.keys = None
        self.card = core.read_json(os.path.join(self.home, "card.json"))
        if self.card:
            self.keys = core.Keys(self.keys_dir)
            self.probe_id = self.card["probe_id"]
        self.state = core.read_json(os.path.join(self.home, "state.json"),
                                    {"seq": 0, "head": None, "unsent": [], "seen": {}, "hour": None})
        self.lock = None

    # ------------------------------------------------------------ setup
    @property
    def initialised(self):
        return self.card is not None

    def init(self):
        if self.initialised:
            raise FileExistsError(f"a probe already lives in {self.home}")
        for d in (self.home, self.bundles, self.objects):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.settings_path):
            shipped = shipped_defaults()
            core.write_json(self.settings_path, dict(DEFAULT_SETTINGS, coordinator=shipped.get("coordinator"),
                                                     trusted_task_keys=shipped.get("trusted_task_keys", [])))
        self.keys = core.Keys.create(self.keys_dir)
        self.probe_id = self.keys.probe_id()
        self.card = {"type": "nullius.probe_card", "protocol": core.PROTOCOL, "probe_id": self.probe_id,
                     "created_utc": core.iso(core.utc_now()), "public_keys": self.keys.public_keys(),
                     "software": {"name": "witnessory-probe", "version": VERSION}}
        card_bytes = core.canonical(self.card)
        self.seal("identity", "ok", [("probe_card", "card.json", card_bytes)], None, core.utc_now(), None)
        core.write_atomic(os.path.join(self.home, "card.json"), card_bytes)
        return self.probe_id

    def acquire(self):
        self.lock = Lock(os.path.join(self.home, "probe.lock"))
        self.reconcile()

    def release(self):
        if self.lock:
            self.lock.release()
            self.lock = None

    # ------------------------------------------------------------ settings and state
    @property
    def settings_path(self):
        return os.path.join(self.home, "settings.json")

    def settings(self):
        return dict(DEFAULT_SETTINGS, **(core.read_json(self.settings_path, {}) or {}))

    def update_settings(self, **changes):
        s = core.read_json(self.settings_path, {}) or {}
        s.update(changes)
        core.write_json(self.settings_path, s)

    def save_state(self):
        core.write_json(os.path.join(self.home, "state.json"), self.state)

    def reconcile(self):
        """Rebuild position and head from the bundles actually signed (state.json is only a cache): a probe
        must never sign two different bundles at the same position."""
        best = None
        for fn in os.listdir(self.bundles):
            if fn.endswith(".json"):
                h = core.read_json(os.path.join(self.bundles, fn))
                if best is None or h["seq"] > best[0]:
                    best = (h["seq"], fn[:-5])
        if best and best[0] >= self.state["seq"]:
            self.state["seq"], self.state["head"] = best[0] + 1, best[1]
            self.save_state()

    # ------------------------------------------------------------ sealing
    def _store(self, data: bytes) -> str:
        h = core.sha256(data)
        path = os.path.join(self.objects, h)
        if not os.path.exists(path):
            core.write_atomic(path, data)
        return h

    def seal(self, layer, status, files, instrument, started, task_ref):
        """files: [(role, name, bytes)]. Returns the bundle ID."""
        header = {
            "type": "nullius.bundle", "protocol": core.PROTOCOL,
            "probe_id": self.probe_id, "seq": self.state["seq"], "prev": self.state["head"],
            "layer": layer, "status": status,
            "started_utc": core.iso(started), "created_utc": core.iso(core.utc_now()),
            "vantage": {}, "instrument": instrument,
            "files": [{"role": r, "name": n, "sha256": self._store(b)} for r, n, b in files],
            "task": task_ref,
            "host": {"python": platform.python_version(), "probe_version": VERSION},
        }
        body = core.canonical(header)
        bid = core.sha256(body)
        # Signatures first, then the header: a header on disk always has its signatures.
        for alg, sig in self.keys.sign_all(body).items():
            core.write_atomic(os.path.join(self.bundles, f"{bid}.{alg}.sig"), core.unb64(sig))
        core.write_atomic(os.path.join(self.bundles, f"{bid}.json"), body)
        self.state["seq"] += 1
        self.state["head"] = bid
        self.state["unsent"].append(bid)
        self.save_state()
        return bid

    def bundle_upload(self, bid):
        """The upload body for a sealed bundle: the header's exact bytes, signatures, files."""
        with open(os.path.join(self.bundles, f"{bid}.json"), "rb") as f:
            raw = f.read()
        header = json.loads(raw)
        sigs = {}
        for fn in os.listdir(self.bundles):
            if fn.startswith(bid + ".") and fn.endswith(".sig"):
                with open(os.path.join(self.bundles, fn), "rb") as f:
                    sigs[fn[len(bid) + 1:-4]] = core.b64(f.read())
        files = {}
        for entry in header["files"]:
            with open(os.path.join(self.objects, entry["sha256"]), "rb") as f:
                files[entry["sha256"]] = core.b64(f.read())
        return {"header_b64": core.b64(raw), "signatures": sigs, "files": files}

    def mark_sent(self, bid):
        if bid in self.state["unsent"]:
            self.state["unsent"].remove(bid)
            self.save_state()

    # ------------------------------------------------------------ the host's log and limits
    def log(self, entry):
        with open(os.path.join(self.home, "log.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(dict(entry, time_utc=core.iso(core.utc_now())), sort_keys=True) + "\n")

    def read_log(self, n=20):
        try:
            with open(os.path.join(self.home, "log.jsonl"), encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return []
        return [json.loads(x) for x in lines[-n:]]

    def hour_used(self, now=None):
        now = now or core.utc_now()
        h = self.state.get("hour")
        if not h or (now - core.parse_iso(h["start"])).total_seconds() >= 3600:
            return 0
        return h["count"]

    def spend(self, n, now=None):
        now = now or core.utc_now()
        h = self.state.get("hour")
        if not h or (now - core.parse_iso(h["start"])).total_seconds() >= 3600:
            h = {"start": core.iso(now), "count": 0}
        h["count"] += n
        self.state["hour"] = h

    def seen(self, now=None):
        """Task IDs already run, forgetting those expired over a day ago."""
        now = now or core.utc_now()
        keep = {t: e for t, e in self.state.get("seen", {}).items()
                if (now - core.parse_iso(e)).total_seconds() < 86400}
        self.state["seen"] = keep
        return keep

    # ------------------------------------------------------------ running a checked task
    def execute(self, task, envelope_sha256):
        """Run a task already checked by tasks.check(); seal and log the result. Returns the bundle ID."""
        m = measures.MEASURES[task["measure"]]
        started = core.utc_now()
        self.state.setdefault("seen", {})[task["task_id"]] = task["expires_utc"]
        self.spend(len(task["targets"]))
        self.save_state()
        workers = max(1, min(int(self.settings().get("concurrency", 4)), 16))
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            observations = list(pool.map(m["run"], task["targets"]))
        bad = sum(measures.failed(o) for o in observations)
        status = "ok" if bad == 0 else ("failed" if bad == len(observations) else "partial")
        result = {"type": "witnessory.result", "version": 1, "measure": task["measure"],
                  "measure_version": m["version"], "task_id": task["task_id"],
                  "started_utc": core.iso(started), "finished_utc": core.iso(core.utc_now()),
                  "observations": observations}
        bid = self.seal(task["measure"], status, [("result", "result.json", core.canonical(result))],
                        {"name": f"witnessory-probe/{task['measure']}", "version": m["version"]}, started,
                        {"task_id": task["task_id"], "task_sha256": envelope_sha256})
        self.log({"task_id": task["task_id"], "measure": task["measure"], "targets": task["targets"],
                  "outcome": status, "bundle": bid})
        return bid
