# Security policy

## Reporting a vulnerability

Do not file public issues for vulnerabilities involving signing keys,
certificate validation, trust-bundle activation, state recovery, or the
Kubernetes integration. Report them privately through the
[GitHub security advisory form](https://github.com/zeisthq/zeist-pki/security/advisories/new).

Include a minimal reproduction, affected version or commit, impact assessment,
and any safe mitigation you have identified. Do not include private keys,
unredacted Secret contents, access tokens, or production endpoint details.

We will acknowledge a report, assess its impact, and coordinate a fix and
disclosure timeline with the reporter. If the repository has not enabled
private reporting, use an established private maintainer contact rather than
opening a public issue.

## Supported versions

Until the first stable release, the latest `v0.1.x` release and the current
default branch are supported. Security fixes will be released as soon as a
validated mitigation is available.

## Security-sensitive deployment material

`zeist-pki` issuer-state stores contain private root keys. They require:

- encryption at rest in the chosen state store;
- strict, separate access control from certificate consumers;
- encrypted backups with access logging and tested restoration; and
- an incident procedure for a lost or compromised root key.

Consumer outputs contain leaf private keys and public trust bundles, but never
issuer private keys. Treat leaf keys as sensitive and do not put PEM material
in command output, logs, metrics, Events, or status objects.

See the [threat model](docs/threat-model.md) and
[backup and recovery guide](docs/backup-and-recovery.md) for the operational
security model.
