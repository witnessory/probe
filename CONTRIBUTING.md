# Contributing

Thank you. The probe takes contributions of code, reviews, tests and ports to new platforms.

## Before your first contribution

Sign the Contributor License Agreement (`CLA.md`). It keeps the project able to license the code to everyone,
including under additional terms later, and gives you credit and a patent grant in return. You keep the copyright
in your work. Signing is one comment on your first pull request:

> I have read the Witnessory Contributor License Agreement (CLA.md, version 1.0) and I agree to it.

If you contribute for an employer, they may need to sign the entity version; ask.

## What a change needs

- **Tests.** Every change comes with a test that fails without it. Tests never depend on the internet: they use
  local stand-ins for servers and the coordinator (`tests/helpers.py`). `python -m unittest discover -s tests`
  passes.
- **The protocol stays the contract.** A change to what the probe sends, accepts or refuses updates
  `docs/PROTOCOL.md` in the same change.
- **New measurement types** are the most carefully reviewed change: they decide what every probe can be asked to
  do. A new type names its port, sends as little as possible, reads only what servers announce, completes no
  login or exchange it does not need, and stays within public servers.

## The line the probe does not cross

The probe observes infrastructure, never people. A contribution that records, infers or reveals anything about
its host, the people on its network, or the users of the servers it measures will not be accepted.
