"""
Tasks: checking a signed task before any of it runs (docs/PROTOCOL.md, "Tasks").

`check(envelope, ...)` returns the task (with normalised targets) or raises Rejected with a short reason. A task
is all or nothing: if any rule fails, nothing in it runs.
"""

import datetime as dt
import re

from . import core, measures, targets

MAX_TARGETS = 200                       # never more per task, whatever the host allows
MAX_VALIDITY = dt.timedelta(days=7)
CLOCK_ALLOWANCE = dt.timedelta(minutes=5)
TASK_ID = re.compile(r"^[0-9a-f]{32}$")
FIELDS = {"type", "version", "task_id", "issued_utc", "not_before_utc", "expires_utc", "probe_id", "measure",
          "targets", "params"}


class Rejected(ValueError):
    """The task is refused; the reason is short and safe to report."""


def _time(task, field):
    try:
        return core.parse_iso(task[field])
    except (KeyError, TypeError, ValueError):
        raise Rejected(f"bad {field}")


def check(envelope, trusted_keys, probe_id, settings, seen, now=None):
    """trusted_keys: [{"key_id", "public_keys": {alg: pem}}]; settings: the host's configuration;
    seen: task IDs already run. Anything unexpected in the envelope is a refusal, never an error."""
    try:
        return _check(envelope, trusted_keys, probe_id, settings, seen, now)
    except Rejected:
        raise
    except Exception:
        raise Rejected("malformed")


def _check(envelope, trusted_keys, probe_id, settings, seen, now=None):
    now = now or core.utc_now()
    if not isinstance(envelope, dict) or not isinstance(envelope.get("task"), dict):
        raise Rejected("malformed")
    task = envelope["task"]
    key_set = next((k for k in trusted_keys if k.get("key_id") == envelope.get("key_id")), None)
    if key_set is None:
        raise Rejected("untrusted key")
    if core.key_id(key_set["public_keys"]) != key_set["key_id"]:
        raise Rejected("untrusted key")
    sigs = envelope.get("signatures")
    if not isinstance(sigs, dict) or not core.verify_all(key_set["public_keys"], core.canonical(task), sigs):
        raise Rejected("bad signature")
    if set(task) != FIELDS or task["type"] != "witnessory.task" or type(task["version"]) is not int:
        raise Rejected("malformed")
    if task["version"] != 1:
        raise Rejected("malformed")
    if not isinstance(task["task_id"], str) or not TASK_ID.match(task["task_id"]):
        raise Rejected("malformed")
    issued, not_before, expires = (_time(task, f) for f in ("issued_utc", "not_before_utc", "expires_utc"))
    if not (issued <= not_before < expires) or expires - issued > MAX_VALIDITY:
        raise Rejected("bad validity")
    if now + CLOCK_ALLOWANCE < not_before:
        raise Rejected("not yet valid")
    if now - CLOCK_ALLOWANCE > expires:
        raise Rejected("expired")
    if task["task_id"] in seen:
        raise Rejected("already run")
    if task["probe_id"] not in (None, probe_id):
        raise Rejected("another probe")
    m = measures.MEASURES.get(task["measure"])
    if m is None:
        raise Rejected("unknown measure")
    if task["measure"] in settings.get("disabled_measures", []):
        raise Rejected("measure turned off by host")
    params = task["params"]
    if not isinstance(params, dict) or set(params) - set(m["params"]):
        raise Rejected("unknown parameter")
    names = task["targets"]
    limit = min(int(settings.get("max_targets_per_task", 100)), MAX_TARGETS)
    if not isinstance(names, list) or not names or len(names) > limit:
        raise Rejected("too many targets" if isinstance(names, list) and names else "no targets")
    clean = []
    for n in names:
        try:
            d = targets.normalise(n)
        except targets.Refused:
            raise Rejected("invalid target")
        if d not in clean:
            clean.append(d)
    return dict(task, targets=clean)
