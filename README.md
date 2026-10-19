# The Witnessory probe

Measures how far the internet's infrastructure has moved to post-quantum cryptography, from wherever you run it.
Each probe adds one more network to [Witnessory](https://witnessory.org)'s view of the transition: which sites and
servers already protect their connections against future quantum computers, seen from many countries and networks
at once.

## Try it

```
pipx install witnessory-probe
witnessory-probe check example.org
witnessory-probe check example.org --ssh
```

`check` works straight away, with no account and nothing stored.

## Run it as a probe

| Where | How |
| --- | --- |
| Linux, Raspberry Pi | `sudo sh install/install.sh`: a system user, its own Python environment, a sandboxed service that starts at boot |
| Windows | `powershell -ExecutionPolicy Bypass -File install\install.ps1`: for your user, no administrator rights, runs every hour without a window |
| Docker | `docker run -d --restart unless-stopped --stop-timeout 120 -v witnessory-probe:/data ghcr.io/witnessory/probe` (a named volume; a bind-mounted folder must be writable by the image's user) |
| By hand | `witnessory-probe start` |

All need a 64-bit system and Python 3.10 or newer (the Docker image has its own). Each makes the probe's keys and
identity on first start and runs it. The probe comes set up: it knows the
Witnessory coordinator and the keys its tasks are signed with. `witnessory-probe me` shows your probe's results,
credits and its public page. Each installer removes itself with `--uninstall` (or `-Uninstall`), and `--purge` also
removes the probe's keys and results.

## What it does on your network

- **Only published measurements.** The probe runs only the measurement types in this code: a TLS key-exchange
  check on port 443 and an SSH key-exchange check on port 22. A task can choose which public sites to measure,
  never what to run. New kinds of measurement come only with a new release you can read.
- **Public servers only.** Targets are public domain names. The probe never connects to a private, local, shared or
  reserved address, to an IPv6 address that can carry one (such as NAT64), or to an address in its own IPv6 subnet;
  never to a name that resolves to any of these; and never follows a redirect from the coordinator.
- **It measures servers, not you.** It reads how servers are configured: which key exchange they choose and what
  their certificate uses. It does not look at your traffic, your devices, or anything anyone on your network does.
- **What others see.** Each server measured sees a connection from your address, as with any visit; SSH servers
  see the identification `SSH-2.0-witnessory_probe https://witnessory.org/probe.html`, so their operators can see
  what it was. Witnessory sees your probe's results and the network (provider) and country it connects from, and
  does not keep your address. Details: [HOSTING.md](HOSTING.md).
- **Light.** At most 600 sites an hour and 4 connections at a time by default; each TLS check is two short exchanges
  that stop at the server's first reply, plus one ordinary connection to read the certificate.
- **You are in charge.** `witnessory-probe pause` and `resume`; turn off a measurement type (for example SSH) or
  lower the caps in `settings.json`; `witnessory-probe log` lists every task it ran; `witnessory-probe status` shows
  the rest. Deleting the folder removes everything the probe stored on your machine.
- **Tamper-evident results.** Every result is signed with the probe's own keys (Ed25519 and ML-DSA-65) and
  chained to the one before it, so results cannot be altered or reordered without it showing.

The full rules, including exactly when a probe refuses a task: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Tests

```
python -m unittest discover -s tests
```

Set `WITNESSORY_LIVE=1` to include a live check of a public site.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
