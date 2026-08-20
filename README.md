# zeist-pki

`zeist-pki` is a small private PKI lifecycle manager for cloud-native systems.

Creating certificates is straightforward. Operating them safely is harder:
services need certificates renewed before expiry, trust roots rotated without
downtime, old and new trust overlapped during migration, and evidence that the
services using that trust actually activated the new generation.

`zeist-pki` is for platforms that own a small, fixed set of internal TLS and
mTLS relationships. It issues and renews their certificates, discovers changes
to their identities, and makes root rollover a deliberate, replay-safe
operation instead of a shell-script event.

## What it does

- Issues ECDSA P-256 private roots and profile-constrained leaves.
- Renews leaves before expiry and reissues them when canonical identities
  change.
- Performs staged root rollover with dual trust, activation evidence, and a
  minimum overlap period.
- Persists durable state before external effects and fences concurrent runs.
- Refuses to silently mint a replacement root when issuer state is missing but
  managed output still exists.
- Provides a scriptable CLI, a reusable Go library, and a Kubernetes
  integration.

The core issuance and rotation packages do not depend on Kubernetes. Kubernetes
is a production integration for storing state, coordinating execution,
discovering targets, publishing material, and verifying activation; it is not
the definition of the project.

## Why not cert-manager?

cert-manager is a strong fit for platforms that need general certificate
resources, many issuer types, public-certificate automation, or cluster-wide
certificate policy. `zeist-pki` does not attempt to replace it.

This project instead serves software that owns a few known private trust
domains and needs a narrow lifecycle guarantee: safe bootstrap, renewal,
rotation, acknowledgement, and recovery without adopting a general-purpose
certificate-management control plane. It deliberately has no CRDs, ACME,
arbitrary issuer model, service-mesh identity API, or controller framework.

## Commands

```text
zeist-pki plan    --config pki.yaml
zeist-pki apply   --config pki.yaml
zeist-pki run     --config pki.yaml
zeist-pki status  --config pki.yaml
zeist-pki verify  --config pki.yaml
zeist-pki recover --config pki.yaml \
  --domain webhook \
  --confirm-active-root-fingerprint webhook=sha256:...
```

Every command supports `--output=text|json`. `plan` is read-only; `apply`
performs one bounded reconciliation; and `run` reconciles immediately and then
every five minutes with jitter and graceful shutdown. `recover` is deliberately
explicit: it acts only on one or more named domains and requires the observed
active-root fingerprint for each selected domain. Repeat `--domain` and its
matching confirmation to recover another independent trust domain.

## Quick start

Inspect a configuration without contacting Kubernetes:

```sh
go run ./cmd/zeist-pki plan --config examples/kubernetes/pki.yaml --offline
go run ./examples/generic
```

Use `plan --offline` when no Kubernetes configuration is available or when a
deterministic fresh-bootstrap preview is wanted. It never reads Kubernetes
state, generates key material, acquires a Lease, or writes state.

The portable API is demonstrated by
[`examples/generic`](examples/generic); it requires no Kubernetes dependency.

## Library layers

- `pki` owns private-root and leaf issuance, profiles, validation, canonical
  SANs, and fingerprints.
- `rotation` owns versioned configuration and state, deterministic plans,
  replay-safe phases, and activation evidence.
- `contract/v1` defines dependency-free publication and acknowledgement wire
  values for certificate consumers.
- `integration/kubernetes` implements Kubernetes-backed state, fencing,
  discovery, publication, and verification.

Portable rotation integrations implement `StateStore`, `Locker`, `Publisher`,
`Discoverer`, and `Verifier`. The Kubernetes implementation is one adapter;
another cloud-native system can provide its own without importing Kubernetes.

Consumers can pin the contract without inheriting issuer dependencies:

```console
go get github.com/zeisthq/zeist-pki/contract/v1@v1.0.0
```

## Operations and security

Read [Configuration](docs/configuration.md) before preparing a deployment.
The [threat model](docs/threat-model.md) describes the trust boundaries and
non-goals, and the [rotation protocol](docs/rotation.md) describes the
replay-safe rollover phases. Treat issuer-state backups as high-value
signing-key material; the [backup and recovery guide](docs/backup-and-recovery.md)
documents the fail-closed recovery procedure.

Security reports are covered by [SECURITY.md](SECURITY.md), and contribution
expectations by [CONTRIBUTING.md](CONTRIBUTING.md).

Release artifacts are created only after a successful version-tag workflow;
see [Releasing](docs/releasing.md) for the generated checksums, signatures,
SBOMs, and provenance records.
