# Security policy

The probe runs on other people's machines and networks. A flaw that lets anyone (including whoever runs the
coordinator) make a probe connect somewhere it should not, run anything it should not, reveal anything about its
host, accept a task it should refuse, or seal a false or altered result is exactly what we want to hear about.

## Reporting a vulnerability

Report privately; please do not open a public issue.

- **Email:** `security@witnessory.org`.
- **GitHub:** "Report a vulnerability" on this repository's Security tab (private advisory).

Include what you found, how to reproduce it, and what an attacker gains. A test case is ideal.

We aim to acknowledge within 3 working days, agree on a fix and a date within 14, and publish an advisory when the
fix ships. We credit reporters who want credit. We will not take legal action against good-faith research that
follows this policy, stays within your own systems, and does not harm probe hosts or third parties.

## In scope

- **The host's safety:** reaching private or internal addresses, running code, writing outside the probe's folder,
  exhausting the host's resources, getting around the host's limits, pause or opt-outs.
- **Tasks:** any way to make a probe accept a task not signed by every key in a trusted key set, or to run a task
  outside the rules in `docs/PROTOCOL.md`.
- **Results:** forging, altering, reordering or losing sealed results; two results at one position.
- **Privacy:** anything the probe or its installers reveal about the host beyond what `HOSTING.md` says.
- **The installers and the container image.**

## Out of scope

- What public servers answer: the probe reports it as it is.
- Denial of service against the coordinator by volume.
