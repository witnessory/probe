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

```
witnessory-probe init
witnessory-probe run --coordinator https://<coordinator address>
```

`init` creates the probe's keys and identity in `~/.witnessory-probe` (or `--home`). `run` takes measurement
tasks from the Witnessory coordinator, runs them, and sends back signed results.

## What it does on your network

- **Only published measurements.** The probe runs only the measurement types in this code: a TLS key-exchange
  check on port 443 and an SSH key-exchange check on port 22. A task can choose which public sites to measure,
  never what to run. New kinds of measurement come only with a new release you can read.
- **Public servers only.** Targets are public domain names. The probe never connects to an address on your own
  network or any private network, and never to a name that resolves to one.
- **Nothing about you.** It measures how servers are configured: which key exchange they choose and what their
  certificate uses. It does not look at your traffic, your devices, or anything anyone on your network does.
- **Light.** At most 600 sites an hour and 4 connections at a time by default; each check is a few small packets
  and no handshake is completed.
- **You are in charge.** `witnessory-probe pause` and `resume`; turn off a measurement type or lower the caps
  in `settings.json`; `witnessory-probe log` lists every task it ran; `witnessory-probe status` shows the rest.
  Deleting the folder removes everything.
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
