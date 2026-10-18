# The Witnessory probe protocol (version 1)

How a probe, the people who host it, and the Witnessory coordinator work together. The probe's code is open so that
anyone can check every claim on this page.

## Principles

- **Tasks are data, never code.** The probe runs only the measurement types built into its released code. A task
  can choose a type, the targets and a few bounded parameters. It cannot add a program, a command or a new
  kind of measurement. New types arrive only in a new release of the probe, which anyone can read.
- **Infrastructure, never individuals.** Targets are public domain names; the probe connects only to public
  addresses, and only on the port its measurement type names. It never measures, inspects or reports what the
  host or anyone on the host's network does.
- **The host is in charge.** Rate caps, a pause switch, per-type opt-outs, and a local log of every task.
- **Every result is evidence.** Results are sealed in signed, hash-chained bundles, so they cannot be altered or
  reordered without the change showing.

## Keys and identity

Each probe makes its own keys on first start: Ed25519 always, and ML-DSA-65 where the installed cryptography
library supports it. The probe's ID is the SHA-256 of its Ed25519 public key (DER bytes). Keys never leave the
host. A probe whose keys are lost or stolen is retired and a new one is set up; the ID is cheap, and a probe's
standing is earned again over time.

The **probe card** (`nullius.probe_card`) holds the ID, the public keys (PEM, LF line endings), the creation time
and the software version. It is the first file the probe seals (bundle 0, layer `identity`).

## Bundles

A bundle is a JSON header plus the files it names:

| Field | Meaning |
| --- | --- |
| `type`, `protocol` | `nullius.bundle`, `3` |
| `probe_id`, `seq`, `prev` | The probe, this bundle's position (from 0), and the ID of the bundle before it (`null` for 0) |
| `layer` | `identity`, or the measurement type (`tls_pq`, `ssh_kex`) |
| `status` | `ok`, `partial` (some targets could not be measured), `failed` |
| `started_utc`, `created_utc` | When the work started and when the bundle was sealed |
| `vantage` | Empty: the probe does not describe where it is. The coordinator works that out and attests it |
| `instrument` | `{"name": "witnessory-probe/<type>", "version": ...}` |
| `files` | `[{"role", "name", "sha256"}]`: each file is stored and sent by its SHA-256 |
| `task` | `{"task_id", "task_sha256"}` for work done for a task; `null` otherwise |
| `host` | Python and probe versions |

The bundle ID is the SHA-256 of the header in canonical JSON (keys sorted, no spaces, UTF-8). Each key signs
those same bytes; the signatures are kept beside the header as `<id>.<alg>.sig`.

## Tasks

A task is signed by the coordinator's task keys:

```json
{"task": {"type": "witnessory.task", "version": 1, "task_id": "<32 hex>",
          "issued_utc": "...", "not_before_utc": "...", "expires_utc": "...",
          "probe_id": "<probe id, or null for any probe>",
          "measure": "tls_pq", "targets": ["example.org", "example.net"], "params": {}},
 "key_id": "<SHA-256 of the key set>",
 "signatures": {"ed25519": "<base64>", "mldsa65": "<base64>"}}
```

The signatures are over the canonical JSON of `task`. `key_id` is the SHA-256 of the canonical JSON of
`{alg: SHA-256 of the public key's DER bytes}`. A probe trusts only the key sets in its configuration, and needs a
valid signature from **every** key in the set (both algorithms).

A probe refuses a task, and runs none of it, when:

- a signature is missing or invalid, or the key set is not trusted;
- it is not yet valid or has expired (5 minutes' clock allowance), or is valid for more than 7 days;
- it was already run (task IDs are remembered until they expire);
- it names another probe;
- the measurement type is unknown, or the host has turned it off;
- it has no targets, more than the host allows per task (default 100, never more than 1,000), a target that is
  not a valid public domain name (addresses are never accepted), or parameters the type does not define;
- it would take the host over its hourly limit (default 600 targets an hour), or the probe is paused.

A target whose name resolves to any non-public address (private, loopback, link-local, reserved) is not
contacted; it is recorded as `refused_non_public`, and the rest of the task runs.

## Measurement types

| Type | Port | What is sent and read | Result per target |
| --- | --- | --- | --- |
| `tls_pq` | 443 | Two TLS ClientHellos (one like a current browser, offering X25519MLKEM768 and X25519; one offering X25519MLKEM768 alone); only the server's first reply is read and no handshake is completed. Then one ordinary TLS connection to read the certificate's algorithms. | `level` (`ready`, `partly`, `not_yet`, `unknown`), both replies (group, TLS version, alert or error, a hash and copy of the raw reply), the certificate's signature and key algorithms |
| `ssh_kex` | 22 | The probe's identification line and a key-exchange offer; reads the server's identification line and offer, then disconnects. No key exchange, no login. | The server's identification, the key-exchange, host-key, cipher and MAC methods it offers, and what a current OpenSSH client would select |

If the bare name does not answer on port 443, `tls_pq` tries `www.<name>` once and says so.

Timeouts: 8 seconds per connection for `tls_pq`, 6 for `ssh_kex`. Targets run with at most the host's concurrency
(default 4).

## The coordinator

HTTPS, JSON. Every request after enrolment is signed: the probe sends `X-Witnessory-Probe` (its ID),
`X-Witnessory-Time` (UTC, ISO 8601) and `X-Witnessory-Signature`, an Ed25519 signature (base64) over the
canonical JSON of `{"method", "path", "time", "body_sha256"}`. The coordinator rejects times more than 5 minutes
off.

| Request | Body | Answer |
| --- | --- | --- |
| `POST /v1/enrol` (not signed as above: the card's signatures prove the keys) | `{"card_b64": <the card's canonical bytes, base64>, "signatures": {alg: base64}}` | `{"probe_id", "accepted"}` |
| `GET /v1/tasks` | — | `{"tasks": [<task envelope>, ...], "next_poll_s": <seconds>}` |
| `POST /v1/bundles` | `{"header_b64": <the header's exact bytes, base64>, "signatures": {alg: base64}, "files": {sha256: base64}}` | `{"stored": <bundle id>}` |
| `POST /v1/refusals` | `{"task_id", "reason"}` | `{"ok": true}` |

Signed things travel as their exact bytes (base64), never as JSON to be re-serialised, so a coordinator written in
any language checks exactly what was signed. Tasks are served as the coordinator received them, byte for byte.

The probe keeps every bundle until the coordinator has stored it, and sends unsent bundles first on every cycle,
so a dropped connection loses nothing. A bundle the coordinator refuses for good (HTTP 400, 409 or 413) is set
aside, kept on disk and listed in the log, so it cannot block the bundles after it. An HTTP 401 makes the probe enrol
again. `next_poll_s` is honoured within 60 to 3,600 seconds.

## What the host sees

- `witnessory-probe log` lists every task: when, the type, the targets, the outcome.
- `witnessory-probe status` shows the ID, the position in the chain, unsent bundles, caps and whether paused.
- `witnessory-probe pause` and `resume`; per-type opt-outs and caps in the configuration file.
- Removing the probe's folder removes everything it stored.
