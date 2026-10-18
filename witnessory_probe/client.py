"""
Talking to the coordinator (docs/PROTOCOL.md, "The coordinator"), and one run cycle.

A cycle: enrol if needed, send every unsent bundle, fetch tasks, check each, run those that pass, report those
that do not. Nothing is lost when the network drops: bundles stay unsent until the coordinator stores them.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from . import VERSION, core, tasks

UA = f"witnessory-probe/{VERSION}"
TIMEOUT = 30
POLL_MIN, POLL_MAX, POLL_DEFAULT = 60, 3600, 300


class Unreachable(RuntimeError):
    """The coordinator could not be reached or answered with an error."""


class Coordinator:
    def __init__(self, base_url, probe):
        self.base = base_url.rstrip("/")
        self.probe = probe

    def _request(self, method, path, body=None, signed=True):
        data = core.canonical(body) if body is not None else b""
        headers = {"User-Agent": UA, "Content-Type": "application/json"}
        if signed:
            t = core.iso(core.utc_now())
            msg = core.canonical({"method": method, "path": path, "time": t, "body_sha256": core.sha256(data)})
            headers.update({"X-Witnessory-Probe": self.probe.probe_id, "X-Witnessory-Time": t,
                            "X-Witnessory-Signature": self.probe.keys.sign_ed25519(msg)})
        req = urllib.request.Request(self.base + path, data=data if method != "GET" else None, method=method,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise Unreachable(f"{method} {path}: HTTP {e.code}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise Unreachable(f"{method} {path}: {type(e).__name__}")

    def enrol(self):
        card = self.probe.card
        return self._request("POST", "/v1/enrol",
                             {"card": card, "signatures": self.probe.keys.sign_all(core.canonical(card))},
                             signed=False)

    def tasks(self):
        return self._request("GET", "/v1/tasks")

    def upload(self, bid):
        return self._request("POST", "/v1/bundles", self.probe.bundle_upload(bid))

    def refuse(self, task_id, reason):
        return self._request("POST", "/v1/refusals", {"task_id": task_id, "reason": reason})


def cycle(probe, coordinator):
    """One cycle. Returns {"ran", "refused", "sent", "next_poll_s"}; raises Unreachable if the coordinator
    cannot be reached (the caller waits and tries again)."""
    out = {"ran": [], "refused": [], "sent": 0, "next_poll_s": POLL_DEFAULT}
    if not probe.state.get("enrolled"):
        coordinator.enrol()
        probe.state["enrolled"] = True
        probe.save_state()
    for bid in list(probe.state["unsent"]):
        coordinator.upload(bid)
        probe.mark_sent(bid)
        out["sent"] += 1
    settings = probe.settings()
    if settings.get("paused"):
        return out
    answer = coordinator.tasks()
    out["next_poll_s"] = min(max(int(answer.get("next_poll_s") or POLL_DEFAULT), POLL_MIN), POLL_MAX)
    for env in answer.get("tasks") or []:
        task_id = (env.get("task") or {}).get("task_id") if isinstance(env, dict) else None
        try:
            task = tasks.check(env, settings.get("trusted_task_keys") or [], probe.probe_id, settings, probe.seen())
            budget = int(settings.get("max_targets_per_hour", 600)) - probe.hour_used()
            if len(task["targets"]) > budget:
                raise tasks.Rejected("over the host's hourly limit")
        except tasks.Rejected as e:
            probe.log({"task_id": task_id, "measure": (env.get("task") or {}).get("measure")
                       if isinstance(env, dict) else None, "targets": [], "outcome": f"refused: {e}"})
            if isinstance(task_id, str):
                coordinator.refuse(task_id[:64], str(e))
            out["refused"].append((task_id, str(e)))
            continue
        bid = probe.execute(task, core.sha256(core.canonical(env)))
        out["ran"].append(task["task_id"])
        coordinator.upload(bid)
        probe.mark_sent(bid)
        out["sent"] += 1
    return out
