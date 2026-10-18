# Hosting a probe: what happens, and what you agree to

Running a Witnessory probe is voluntary and you can stop at any time. This page says plainly what the probe does,
what Witnessory receives, and how it is used.

## What the probe does

It measures how public servers are configured: which key exchange they choose for a current browser and for a
post-quantum-only client (port 443), what their certificate uses, and which key exchange methods their SSH service
offers (port 22). It connects only to public addresses of public domain names that Witnessory's signed tasks name,
and only within the limits you set (`docs/PROTOCOL.md` has every rule). It does not look at your traffic, your
devices or anything anyone on your network does.

## What Witnessory receives

- **Your probe's results**, signed by your probe: what each public server answered.
- **Your probe's public keys and its identity card** (an ID that is a hash of its key, the software version, the
  Python version).
- **The network your probe connects from**: Cloudflare, which runs the coordinator, tells Witnessory the network's
  number and name (for example a hosting company or internet provider) and its country. Witnessory keeps those
  to weigh results fairly ("one network, one vote") and to know where on the internet a measurement was made.
- **Not your IP address.** Your probe's address reaches Cloudflare, as with any web request, and Witnessory does
  not store it.

## What is public

Each probe has a page (`witnessory-probe me` shows its address) with its ID, start date, number of results and
credits. It never shows the network, country or address. Results are published in aggregate (for example "this
share of popular sites is ready"), never as "probe X on network Y".

## How results are used

Results feed Witnessory's public view of the internet's move to post-quantum cryptography, which is free, and
Witnessory's services, which may be paid (for example monitoring for organisations, or data for researchers). By
running a probe you allow Witnessory to use your probe's results this way. Witnessory keeps the network and
country of a probe private to Witnessory and its own processing.

## Credits

A probe earns credits for the servers it measures (only real answers count). Credits record what a probe has
contributed. They are meant to become usable for Witnessory's services, such as checking your own sites from many
networks; that is not available yet. They are not money, cannot be sold or transferred, and their use and value may
change as the service develops.

## Your part

- Run the probe only on machines and networks where you are allowed to (your own, or with permission).
- Follow the law where the probe runs. If measuring public servers could put you at risk where you are, do not run
  it.

## Stopping

`witnessory-probe pause` stops new tasks. The installers remove the probe with `--uninstall` (or `-Uninstall`), and
`--purge` also deletes its keys and results from your machine. Results already sent remain part of Witnessory's
records, which are signed and cannot be edited without it showing.

## No warranty

The probe is provided under the Apache License 2.0, without warranty (see `LICENSE`).

Questions: `security@witnessory.org`.
