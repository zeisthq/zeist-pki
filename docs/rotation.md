# Rotation protocol

A root rollover is a durable protocol, not a certificate replacement. A domain
stores a versioned state record before every external effect. The record holds
the schema and configuration digest, phase, operation ID, active and candidate
root fingerprints, desired/published/acknowledged generations, exact target
snapshot, acknowledgement evidence, overlap deadline, and any blocked reason.
It never duplicates PEM or application credentials.

The Kubernetes state adapter stores that record with the corresponding active
and candidate issuer keys in a restricted state Secret. Consumer outputs contain
only a leaf key, leaf certificate chain, and public trust bundle.

## Phases

| Phase | Meaning |
| --- | --- |
| `Stable` | One active root is authoritative; normal leaf issuance or renewal is permitted. |
| `PublishingDualTrust` | A persisted candidate root exists and the publisher must distribute active-plus-candidate trust. |
| `AwaitingDualTrust` | Distribution completed; the exact current consumers must prove they loaded the dual bundle. |
| `ActivatingCandidateLeaves` | Candidate-signed leaves are issued and published while dual trust remains active. |
| `AwaitingCandidateActivation` | Consumers and live probes must prove they serve and trust the candidate generation. |
| `Overlap` | Both roots remain trusted until the persisted minimum-overlap deadline. |
| `RetiringActiveRoot` | Candidate-only trust is published and verified before the old root key is removed. |
| `Blocked` | Evidence or another safety condition is missing. No automatic trust retirement occurs. |

## Required rollover order

1. Create and persist a candidate root.
2. Publish a bundle with both active and candidate roots.
3. Obtain acknowledgement evidence for the dual-trust generation.
4. Issue and activate leaves signed by the candidate root.
5. Obtain live proof for those leaves and the candidate generation.
6. Hold the old and new roots for the minimum configured overlap.
7. Publish candidate-only trust and prove it is live.
8. Remove the old root private key only after the retirement proof succeeds.

A publisher reporting success means it distributed material, not that a consumer
activated it. Time alone never permits old-root retirement. If a required
consumer is absent, stale, or fails verification, the domain remains on safe
dual trust and reports `Blocked`.

`Blocked` preserves the verification-safe phase that failed. A later `apply`
persists re-entry to that same phase before retrying its evidence; it never
skips a gate or retires trust because time passed. A structurally inconsistent
state has no retry origin and remains operator-action blocked.

The target snapshot remains part of the proof throughout overlap and
retirement. If a Ready consumer appears, disappears, or changes identity after
candidate activation, the engine returns to a new active-signed dual-trust
generation and repeats the required activation proof. It never issues a
candidate-only generation to a consumer that did not participate in the
dual-trust proof.

## Replay and concurrency

One invocation acquires a per-domain fence before it reconciles. State saves
use an optimistic version as a second boundary. If a process crashes, its
successor loads the durable phase and repeats only the next idempotent action;
it does not mint an unrelated root or skip an acknowledgement gate.

If state is missing while managed outputs survive, the protocol cannot know
which root is authoritative. It therefore fails closed until an operator uses
the explicit recovery flow described in
[backup and recovery](backup-and-recovery.md).
