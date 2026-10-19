"""
Talking to the coordinator (docs/PROTOCOL.md, "The coordinator"), and one run cycle.

A cycle: enrol if needed, send every unsent bundle, fetch tasks (only if the host's hourly budget allows any), check
each, run those that pass, report those that do not. Nothing is lost when the network drops: bundles stay unsent
until the coordinator stores them. Nothing the coordinator sends can stop the cycle: a malformed answer or task is
refused and the rest carries on.

The coordinator is trusted for nothing but delivery. Its address must be https (plain http only to this machine,
for development), redirects are never followed (a redirect could point the probe at its own network), and answers
are size-limited.
"""

import datetime as dt
import email.utils
import http.client
import json
import urllib.error
import urllib.parse
import urllib.request

from . import VERSION, core, measures, tasks

UA = f"witnessory-probe/{VERSION}"
TIMEOUT = 30
POLL_MIN, POLL_MAX, POLL_DEFAULT = 60, 3600, 300
GIVE_UP_DAYS = 7                          # a bundle that keeps failing is set aside after this long
MAX_ANSWER = 4 << 20                      # bytes read from any coordinator answer
MAX_TASKS_PER_POLL = 20
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class Unreachable(RuntimeError):
    """The coordinator could not be reached or answered with an error (code: the HTTP status, if any)."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class Rejected(Unreachable):
    """The coordinator refused what was sent, for good (sending it again would not help)."""


PERMANENT = {400, 409, 413}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not followed", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirect)


def check_url(url):
    """The coordinator's address, or ValueError: https, or http to this machine only."""
    u = urllib.parse.urlsplit(url or "")
    if u.scheme == "https" and u.hostname:
        return url.rstrip("/")
    if u.scheme == "http" and u.hostname in LOOPBACK:
        return url.rstrip("/")
    raise ValueError(f"the coordinator must be an https address (got {url!r})")


def clock_note(headers):
    """If the coordinator's clock differs from ours by more than 4 minutes, say so (signed requests need a
    clock within 5 minutes)."""
    try:
        theirs = email.utils.parsedate_to_datetime(headers.get("Date"))
        skew = (core.utc_now() - theirs.astimezone(dt.timezone.utc)).total_seconds()
    except (TypeError, ValueError, AttributeError):
        return ""
    return f"; this machine's clock is off by {round(skew)} seconds: fix the time" if abs(skew) > 240 else ""


class Coordinator:
    def __init__(self, base_url, probe):
        self.base = check_url(base_url)
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
            with _OPENER.open(req, timeout=TIMEOUT) as r:
                raw = r.read(MAX_ANSWER + 1)
            if len(raw) > MAX_ANSWER:
                raise Unreachable(f"{method} {path}: answer too large")
            answer = json.loads(raw or b"{}")
            if not isinstance(answer, dict):
                raise Unreachable(f"{method} {path}: malformed answer")
            return answer
        except urllib.error.HTTPError as e:
            note = clock_note(e.headers) if e.code == 401 else ""
            e.close()
            if e.code == 401:                     # the coordinator does not know this probe: enrol again
                self.probe.state["enrolled"] = False
            raise (Rejected if e.code in PERMANENT else Unreachable)(f"{method} {path}: HTTP {e.code}{note}", e.code)
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
            raise Unreachable(f"{method} {path}: {type(e).__name__}")

    def enrol(self):
        raw = core.canonical(self.probe.card)
        body = {"card_b64": core.b64(raw), "signatures": self.probe.keys.sign_all(raw)}
        return self._request("POST", "/v1/enrol", body, signed=False)

    def tasks(self, budget, measures_on, max_per_task=None):
        args = {"budget": budget, "measures": ",".join(measures_on)}
        if max_per_task is not None:
            args["max_per_task"] = max_per_task
        q = urllib.parse.urlencode(args)
        return self._request("GET", f"/v1/tasks?{q}")

    def upload(self, bid):
        return self._request("POST", "/v1/bundles", self.probe.bundle_upload(bid))

    def refuse(self, task_id, reason):
        return self._request("POST", "/v1/refusals", {"task_id": task_id, "reason": reason})


def send(probe, coordinator, bid):
    """Upload one bundle. A bundle the coordinator refuses for good, or that can no longer be read here, is set aside
    (kept on disk, listed in the state and the log). A bundle the coordinator answers with any other error goes to the
    back of the queue, so it never blocks the others or new tasks, and is set aside if it still fails after
    GIVE_UP_DAYS. Raises Unreachable only if the coordinator cannot be reached at all (no HTTP answer)."""
    try:
        coordinator.upload(bid)
    except Rejected as e:
        probe.set_aside(bid, str(e))
        return
    except Unreachable as e:
        if e.code is None:
            raise                                 # no answer at all: try again next cycle, nothing else to do now
        if probe.bundle_age_days(bid) >= GIVE_UP_DAYS:
            probe.set_aside(bid, f"still failing after {GIVE_UP_DAYS} days: {e}")
        else:
            probe.requeue(bid)
        return
    except (OSError, ValueError, KeyError, TypeError) as e:
        probe.set_aside(bid, f"unreadable here: {type(e).__name__}")
        return
    probe.mark_sent(bid)


def _task_id(env):
    t = env.get("task") if isinstance(env, dict) else None
    v = t.get("task_id") if isinstance(t, dict) else None
    return v[:64] if isinstance(v, str) else None


def cycle(probe, coordinator, stop=lambda: False):
    """One cycle. Returns {"ran", "refused", "sent", "next_poll_s"}; raises Unreachable only if the coordinator
    cannot be reached at all (the caller waits and tries again). `stop()` is checked between tasks."""
    out = {"ran": [], "refused": [], "sent": 0, "next_poll_s": POLL_DEFAULT}
    if not probe.state.get("enrolled"):
        coordinator.enrol()
        probe.state["enrolled"] = True
        probe.save_state()
    for bid in list(probe.state["unsent"]):
        send(probe, coordinator, bid)
        out["sent"] += 1
    probe.prune_daily()
    settings = probe.settings()
    budget = int(settings.get("max_targets_per_hour", 600)) - probe.hour_used()
    if settings.get("paused") or budget <= 0:
        return out
    on = [m for m in measures.MEASURES if m not in settings.get("disabled_measures", [])]
    per_task = min(int(settings.get("max_targets_per_task", 100)), tasks.MAX_TARGETS)
    answer = coordinator.tasks(budget, on, per_task)
    try:
        out["next_poll_s"] = min(max(int(answer.get("next_poll_s") or POLL_DEFAULT), POLL_MIN), POLL_MAX)
    except (TypeError, ValueError):
        pass
    envelopes = answer.get("tasks")
    if not isinstance(envelopes, list):
        envelopes = []
    for env in envelopes[:MAX_TASKS_PER_POLL]:
        if stop():
            break
        task_id = _task_id(env)
        try:
            task = tasks.check(env, settings.get("trusted_task_keys") or [], probe.probe_id, settings, probe.seen())
            budget = int(settings.get("max_targets_per_hour", 600)) - probe.hour_used()
            if len(task["targets"]) > budget:
                raise tasks.Rejected("over the host's hourly limit")
        except tasks.Rejected as e:
            probe.log({"task_id": task_id, "measure": None, "targets": [], "outcome": f"refused: {e}"})
            out["refused"].append((task_id, str(e)))
            if task_id:
                try:
                    coordinator.refuse(task_id, str(e))
                except Unreachable:
                    pass
            continue
        bid = probe.execute(task, core.sha256(core.canonical(env)))
        out["ran"].append(task["task_id"])
        try:
            send(probe, coordinator, bid)
            out["sent"] += 1
        except Unreachable:
            pass                                  # stays unsent; the next cycle sends it
    if envelopes and not out["ran"]:
        out["next_poll_s"] = POLL_DEFAULT         # everything given was refused: do not ask again at once
    return out
