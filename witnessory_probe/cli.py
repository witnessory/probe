"""
witnessory-probe: the command line.

  witnessory-probe check example.org [--ssh] [--json]   measure one site now (no setup needed)
  witnessory-probe start                                 set up this machine's probe if needed, then run
  witnessory-probe init                                  create this machine's probe (keys, identity)
  witnessory-probe run [--coordinator URL] [--once]      take tasks from the coordinator, run them, send results
  witnessory-probe me                                    this probe's credits, results and public page
  witnessory-probe status | log [-n N] | pause | resume
  witnessory-probe trust KEYSET.json                     trust a coordinator task key set

The probe's folder is ~/.witnessory-probe, or --home, or WITNESSORY_PROBE_HOME.
"""

import argparse
import json
import signal
import sys
import time
import traceback

from . import VERSION, client, core, measures, targets
from .home import Busy, Probe, shipped_defaults

SENTENCES = {
    "ready": "Connections from current browsers are protected against future quantum decryption "
             "(post-quantum key exchange).",
    "partly": "The site supports post-quantum key exchange, but browsers still get classical key exchange.",
    "not_yet": "Not yet: connections use classical key exchange only, which a future quantum computer could "
               "decrypt if recorded today.",
    "unknown": "The site could not be reached on port 443.",
}


def explain_tls(o):
    if o["outcome"] == "refused_non_public":
        return f"{o['target']}: not measured ({o.get('error')})"
    lines = [f"{o['target']}: {o['level'].replace('_', ' ')}", SENTENCES[o["level"]]]
    b = o["browser"]
    if b.get("group_name"):
        lines.append(f"Key exchange with a browser-like client: {b['group_name']} (TLS {b['tls_version']}).")
    c = o.get("certificate") or {}
    if c.get("signature_algorithm"):
        lines.append(f"Certificate: {c['signature_algorithm']} signature, {c['key_algorithm']} key"
                     + (" (post-quantum)." if c["post_quantum"] else " (classical)."))
    return "\n".join(lines + o.get("notes", []))


def explain_ssh(o):
    s = o.get("ssh") or {}
    if s.get("outcome") != "kexinit":
        return f"{o['target']} (SSH): not measured ({o.get('error') or s.get('error') or s.get('outcome')})"
    return (f"{o['target']} (SSH): a current OpenSSH client would use {s['reference_client_selects']} "
            f"({s['reference_client_class']}); the server offers {len(s['kex'] or [])} key-exchange methods.")


def cmd_check(a):
    try:
        name = targets.normalise(a.domain)
    except targets.Refused as e:
        sys.exit(f"refused: {e}")
    out = [measures.tls_pq(name)] + ([measures.ssh_kex(name)] if a.ssh else [])
    if a.json:
        print(json.dumps(out if a.ssh else out[0], indent=2, sort_keys=True))
    else:
        print(explain_tls(out[0]))
        if a.ssh:
            print(explain_ssh(out[1]))
    return 0 if not measures.failed(out[0]) else 1


def cmd_init(a):
    p = Probe(a.home)
    try:
        pid = p.init()
    except (FileExistsError, RuntimeError, Busy) as e:
        sys.exit(str(e))
    if a.coordinator:
        p.update_settings(coordinator=a.coordinator)
    print(f"probe {pid} created in {p.home}; signing with {', '.join(sorted(p.keys.private))}")
    return 0


def _probe(a):
    p = Probe(a.home)
    if not p.initialised:
        sys.exit(f"no probe in {p.home}: run `witnessory-probe init` first")
    return p


def cmd_run(a):
    p = _probe(a)
    url = a.coordinator or p.settings().get("coordinator")
    if not url:
        sys.exit("no coordinator: give --coordinator URL")
    if a.coordinator:
        p.update_settings(coordinator=a.coordinator)
    try:
        p.acquire()
    except Busy as e:
        sys.exit(str(e))
    try:
        coord = client.Coordinator(url, p)
    except ValueError as e:
        p.release()
        sys.exit(str(e))
    stop = []

    def on_signal(signum, frame):                 # finish the current step, then stop (never mid-seal)
        stop.append(signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError):
            pass
    wait = client.POLL_DEFAULT
    try:
        while not stop:
            try:
                r = client.cycle(p, coord)
                wait = r["next_poll_s"]
                print(f"{core.iso(core.utc_now())} ran {len(r['ran'])}, refused {len(r['refused'])}, "
                      f"sent {r['sent']}", flush=True)
            except client.Unreachable as e:
                print(f"{core.iso(core.utc_now())} coordinator unreachable ({e}); trying again later", flush=True)
                wait = client.POLL_DEFAULT
                if a.once:
                    return 1
            except Exception:                     # a bug must not crash-loop the host's service: log, wait, retry
                print(f"{core.iso(core.utc_now())} unexpected error; trying again later\n{traceback.format_exc()}",
                      flush=True)
                p.log({"task_id": None, "measure": None, "targets": [], "outcome": "unexpected error (see output)"})
                wait = client.POLL_DEFAULT
                if a.once:
                    return 1
            if a.once:
                return 0
            for _ in range(int(wait)):
                if stop:
                    break
                time.sleep(1)
        print(f"{core.iso(core.utc_now())} stopped", flush=True)
        return 0
    finally:
        p.release()


def cmd_start(a):
    p = Probe(a.home)
    if not p.initialised:
        try:
            print(f"probe {p.init()} created in {p.home}", flush=True)
        except (RuntimeError, Busy) as e:
            sys.exit(str(e))
        except FileExistsError:
            pass                                  # another start made it a moment ago
    a.coordinator, a.once = None, False
    return cmd_run(a)


def cmd_me(a):
    p = _probe(a)
    url = p.settings().get("coordinator")
    if not url:
        sys.exit("no coordinator set")
    try:
        me = client.Coordinator(url, p)._request("GET", "/v1/me")
    except client.Unreachable as e:
        sys.exit(f"coordinator unreachable ({e}); has this probe run yet?")
    page = shipped_defaults().get("page")
    print(f"probe      {me['probe_id']}\ncredits    {me['credits']}\nresults    {me['bundles']}\n"
          f"since      {me['enrolled_utc'][:10]}\nnetwork    {me.get('network') or '-'} ({me.get('country') or '-'})"
          + (f"\npage       {page}{me['probe_id']}" if page else ""))
    print("(the network and country are shown only to you; the public page shows results and credits)")
    return 0


def cmd_status(a):
    p = _probe(a)
    s = p.settings()
    print(json.dumps({"probe_id": p.probe_id, "version": VERSION, "home": p.home, "next_seq": p.state["seq"],
                      "unsent_bundles": len(p.state["unsent"]), "paused": s["paused"],
                      "coordinator": s["coordinator"], "trusted_task_keys": [k["key_id"] for k in
                                                                             s["trusted_task_keys"]],
                      "targets_this_hour": p.hour_used(), "max_targets_per_hour": s["max_targets_per_hour"],
                      "max_targets_per_task": s["max_targets_per_task"], "concurrency": s["concurrency"],
                      "disabled_measures": s["disabled_measures"]}, indent=2))
    return 0


def cmd_log(a):
    for e in _probe(a).read_log(a.n):
        t = ", ".join(e.get("targets") or [])
        print(f"{e['time_utc']}  {e.get('measure') or '-':8}  {e['outcome']:10}  {t[:120]}")
    return 0


def cmd_pause(a, paused):
    p = _probe(a)
    p.update_settings(paused=paused)
    print("paused: no new tasks will run" if paused else "resumed")
    return 0


def cmd_trust(a):
    p = _probe(a)
    ks = json.load(open(a.keyset, encoding="utf-8"))
    if not isinstance(ks, dict) or not ks.get("public_keys") or core.key_id(ks["public_keys"]) != ks.get("key_id"):
        sys.exit("not a key set: needs public_keys and the key_id they hash to")
    keys = [k for k in p.settings()["trusted_task_keys"] if k["key_id"] != ks["key_id"]]
    p.update_settings(trusted_task_keys=keys + [{"key_id": ks["key_id"], "public_keys": ks["public_keys"]}])
    print(f"trusting task key set {ks['key_id'][:16]}... ({', '.join(sorted(ks['public_keys']))})")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="witnessory-probe", description="The Witnessory probe")
    p.add_argument("--version", action="version", version=f"witnessory-probe {VERSION}")
    p.add_argument("--home", help="the probe's folder (default ~/.witnessory-probe)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="measure one site now")
    c.add_argument("domain")
    c.add_argument("--ssh", action="store_true", help="also measure SSH key exchange on port 22")
    c.add_argument("--json", action="store_true")
    sub.add_parser("start", help="set up this machine's probe if needed, then run")
    i = sub.add_parser("init", help="create this machine's probe")
    i.add_argument("--coordinator", help="another coordinator than the one this release names")
    sub.add_parser("me", help="this probe's credits, results and public page")
    r = sub.add_parser("run", help="take and run tasks from the coordinator")
    r.add_argument("--coordinator")
    r.add_argument("--once", action="store_true", help="one cycle, then exit")
    sub.add_parser("status")
    lg = sub.add_parser("log", help="the tasks this probe ran")
    lg.add_argument("-n", type=int, default=20)
    sub.add_parser("pause")
    sub.add_parser("resume")
    t = sub.add_parser("trust", help="trust a coordinator task key set")
    t.add_argument("keyset")
    a = p.parse_args(argv)
    return {"check": cmd_check, "init": cmd_init, "start": cmd_start, "me": cmd_me, "run": cmd_run,
            "status": cmd_status, "log": cmd_log,
            "pause": lambda a: cmd_pause(a, True), "resume": lambda a: cmd_pause(a, False),
            "trust": cmd_trust}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
