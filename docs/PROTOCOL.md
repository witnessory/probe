# The Witnessory probe protocol (version 1)

How a probe, the people who host it, and the Witnessory coordinator work together. The probe's code is open so that
anyone can check every claim on this page. Results are recorded in Witnessory's signed record format (called
nullius; its data types are named `nullius.*`, format version 3), which the observatory's own probes use too.

## Principles

- **Tasks are data, never code.** The probe runs only the measurement types built into its released code. A task
  can choose a type and the targets. It cannot add a program, a command or a new kind of measurement. New types
  arrive only in a new release of the probe, which anyone can read.
- **Infrastructure, never individuals.** Targets are public domain names; the probe connects only to public
  addresses, and only on the port its measurement type names. It never measures, inspects or reports what the
  host or anyone on the host's network does.
- **The coordinator is trusted for delivery only.** A task runs only if the task keys signed it, and those keys are
  kept offline. Nothing the coordinator sends can make a probe connect anywhere else, run anything, or stop.
- **The host is in charge.** Rate caps, a pause switch, per-type opt-outs, and a local log of every task.
- **Every result is evidence.** Results are sealed in signed, hash-chained bundles, so they cannot be altered or
  reordered without the change showing.

## Keys and identity

Each probe makes its own keys on first start: Ed25519 and ML-DSA-65 (a probe whose cryptography library lacks
ML-DSA refuses to start and says how to fix it). The probe's ID is the SHA-256 of its Ed25519 public key (DER bytes).
Keys never leave the host. A probe whose keys are lost or stolen is retired and a new one is set up; the ID is cheap,
and a probe's standing is earned again over time.

The **probe card** (`nullius.probe_card`) holds the ID, the public keys (PEM, LF line endings), the creation time and
the software name and version. It is the first file the probe seals (bundle 0, layer `identity`).

## Bundles

A bundle is a JSON header plus the files it names:

| Field | Meaning |
| --- | --- |
| `type`, `protocol` | `nullius.bundle`, `3` |
| `probe_id`, `seq`, `prev` | The probe, this bundle's position (from 0), and the ID of the bundle before it (`null` for 0) |
| `layer` | `identity`, or the measurement type (`tls_pq`, `ssh_kex`) |
| `status` | `ok`, `partial` (some targets did not answer), `failed` (none did) |
| `started_utc`, `created_utc` | When the work started and when the bundle was sealed |
| `vantage` | Empty: the probe does not describe where it is |
| `instrument` | `{"name": "witnessory-probe/<type>", "version": ...}` |
| `files` | `[{"role", "name", "sha256"}]`: each file is stored and sent by its SHA-256 |
| `task` | `{"task_id", "task_sha256"}` for work done for a task; `null` otherwise |
| `host` | The Python and probe versions |

The bundle ID is the SHA-256 of the header in canonical JSON (keys sorted, no spaces, UTF-8). Each key signs those
same bytes; the signatures are kept beside the header as `<id>.<alg>.sig`. One observation is at most 8 KB (a larger
one keeps its hashes and counts). A result file is at most 300,000 bytes: if a task's results would be larger, copies
of servers' raw replies are dropped, largest first (their hashes stay), then the largest observations are reduced to
their target and outcome (counted in `observations_omitted`, and the bundle's status is then `partial`), so a few
oversized answers never push out the others.

A probe never signs two bundles at the same position: its position is rebuilt from the bundles on disk whenever it
starts, and a bundle sealed just before a crash is still sent.

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
`{alg: SHA-256 of the public key's DER bytes}`. A probe trusts only the key sets in its settings (a release ships
Witnessory's), and needs a valid signature from **every** key in the set.

A probe refuses a task, and runs none of it, when:

- it is malformed in any way, a signature is missing or invalid, or the key set is not trusted;
- it is not yet valid or has expired (5 minutes' clock allowance), or is valid for more than 7 days;
- it was already run (task IDs are remembered until a day after they expire);
- it names another probe;
- the measurement type is unknown, or the host has turned it off;
- it has parameters (no type defines any yet);
- it has no targets, more than the host allows per task (default 100, never more than 200), or a target that is
  not a valid public domain name: addresses, ports and names for local networks (`.local`, `.internal`, `.lan`,
  `.home.arpa` and the like) are refused;
- it would take the host over its hourly limit (default 600 targets an hour).

A target is resolved as a fully qualified name (local search domains never apply). If any address it resolves to
is not public, it is not contacted and is recorded as `refused_non_public`; the rest of the task runs. Not public:
private, loopback, link-local, shared (CGNAT), multicast and reserved addresses, the IPv6 forms that can carry an
IPv4 address (NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`, IPv4-compatible,
-mapped and -translated), and IPv6 addresses inside the host's own /64.

## Measurement types

| Type | Port | What is sent and read | Result per target |
| --- | --- | --- | --- |
| `tls_pq` | 443 | Two TLS ClientHellos (one like a current browser, offering X25519MLKEM768 and X25519; one offering X25519MLKEM768 alone), each answered by the server's first reply, after which the connection is closed. Then one ordinary TLS connection to read the certificate's algorithms (this one completes a handshake and sends nothing else). | `level` (`ready`, `partly`, `not_yet`, `unknown`), both replies (group, TLS version, alert or error, the hash of the raw reply and its first 2 KB), the certificate's signature and key algorithms |
| `ssh_kex` | 22 | The identification line `SSH-2.0-witnessory_probe https://witnessory.org/probe.html` and a key-exchange offer; the server's identification line and offer are read, then the connection is closed. No key exchange, no login. | The server's identification, the key-exchange, host-key, cipher and MAC methods it offers (at most 64 names per list; a name is printable ASCII of at most 64 characters, others are left out), and what a current OpenSSH client would select |

Each observation's `outcome` is `measured` (the server answered, however negatively: an alert or a classical group
is an answer), `no_answer` (the name has no address, or the connection timed out, was refused or reset, or the reply
could not be read) or `refused_non_public`. Only `measured` observations earn credit.

If the bare name does not answer on port 443, `tls_pq` tries `www.<name>` once and says so. A server's reply is read
up to one handshake message of 64 KB (TLS) or one packet of 35,000 bytes (SSH); anything larger is an unreadable
reply.

Timeouts: 8 seconds per connection for `tls_pq`, 6 for `ssh_kex`. Targets run with at most the host's concurrency
(default 4, never more than 16).

## The coordinator

HTTPS, JSON. The probe accepts only an https address for the coordinator (plain http only to its own machine, for
development), never follows a redirect, and reads at most 4 MB of any answer. Every request after enrolment is
signed: the probe sends `X-Witnessory-Probe` (its ID), `X-Witnessory-Time` (UTC, ISO 8601) and
`X-Witnessory-Signature`, an Ed25519 signature (base64) over the canonical JSON of
`{"method", "path", "time", "body_sha256"}`, where `path` includes the query. The coordinator rejects times more
than 5 minutes off; the probe then says if its own clock is wrong.

| Request | Body | Answer |
| --- | --- | --- |
| `POST /v1/enrol` (not signed as above: the card's signatures prove the keys) | `{"card_b64": <the card's canonical bytes, base64>, "signatures": {alg: base64}}` | `{"probe_id", "accepted"}` |
| `GET /v1/tasks?budget=<targets left this hour>&measures=<types turned on>&max_per_task=<the host's per-task cap>` | — | `{"tasks": [<task envelope>, ...], "next_poll_s": <seconds>}` |
| `POST /v1/bundles` | `{"header_b64": <the header's exact bytes, base64>, "signatures": {alg: base64}, "files": {sha256: base64}}` | `{"stored": <bundle id>}` |
| `POST /v1/refusals` | `{"task_id", "reason"}` | `{"ok": true}` |
| `GET /v1/me` | — | the probe's credits, results, start date, and the network and country the coordinator sees (shown only to the probe) |

Signed things travel as their exact bytes (base64), never as JSON to be re-serialised, so a coordinator written in
any language checks exactly what was signed. Tasks are served as the coordinator received them, byte for byte.

A probe that has used its hourly budget, or is paused, does not ask for tasks. It handles at most 20 tasks per
answer. It keeps every bundle until the coordinator has stored it and sends unsent bundles first on every cycle, so
a dropped connection loses nothing. A bundle the coordinator refuses for good (HTTP 400, 409 or 413), or that can no
longer be read on the host, is set aside, kept on disk and listed in the log, so it cannot block the bundles after
it. An HTTP 401 makes the probe enrol again. `next_poll_s` is honoured within 60 to 3,600 seconds.

A bundle the coordinator answers with any other error (a server error, say), or that gets no answer at all, goes to
the back of the queue, so it never holds up new tasks, and is set aside if it still fails after 7 days; with no answer,
the probe stops uploading for that cycle but still takes tasks. Uploads are given time in proportion to their size (at
least 20 kB a second), and a Retry-After from the coordinator is honoured, up to an hour. If every task in an answer was refused, the probe
waits the default time before asking again. A stop signal takes effect between tasks; a second one stops at once (the
chain is crash-safe).

The coordinator accepts a probe's identity bundle once, at position 0, and other bundles only for tasks it gave that
probe. It checks the Ed25519 signatures as they arrive; the core verifies both signatures and every file's hash when it
collects results, and credits a probe only for results that verify (so credits appear after collection, within about
an hour).

## What the host sees

- `witnessory-probe log` lists every task: when, the type, the targets, the outcome (the log is capped at 5 MB, one
  older log kept).
- `witnessory-probe status` shows the ID, the position in the chain, unsent bundles, caps and whether paused.
- `witnessory-probe me` shows the probe's credits, results and public page.
- `witnessory-probe pause` and `resume`; per-type opt-outs and caps in `settings.json`.
- Once a day, the files of results already stored by the coordinator and older than 30 days are deleted from the
  host; their signed headers stay, so the chain still verifies. Results set aside are kept.
- Removing the probe's folder removes everything it stored on the host. Results already sent stay in Witnessory's
  records.
