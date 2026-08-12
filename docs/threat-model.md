# Threat model

`zeist-pki` manages a small number of private TLS and mTLS trust domains. Its
security goal is not merely valid X.509 output: it is to ensure that a
certificate lifecycle change has a durable, attributable state and does not
remove currently required trust before live consumers have demonstrably moved
to the new generation.

## Assets

- Active and candidate root private keys.
- Issuer state, including phase, configuration digest, operation identity,
  fingerprints, acknowledgement evidence, and overlap deadline.
- Leaf private keys and the public trust bundles delivered to consumers.
- Configuration that names a trust domain, its outputs, and its discovered
  targets.
- Leases and optimistic concurrency versions that fence a rotation.
- Backup copies of issuer state and root keys.

## Trust boundaries

The issuer process is trusted with root keys. Consumers are trusted only with
their own leaf key and public trust bundle. A publisher may distribute consumer
material but must never receive issuer private keys.

For Kubernetes, the API server, encrypted Secret storage, narrowly scoped RBAC,
and the process running the Kubernetes integration are part of the trusted
control plane. A compromise of a principal that can read an issuer-state Secret
is a root-key compromise. A compromise of a consumer Secret is a leaf-key
compromise, not permission to issue certificates.

Consumer acknowledgement writers are also trusted to report the material that
their own process has activated. The verifier binds an acknowledgement Lease to
the expected Ready consumer Pod UID and, for node-local targets, also requires
the Pod to be scheduled on the selected Node with the expected UID. This
prevents a replacement Node with the same name from satisfying old evidence.
The isolated acknowledgement namespace prevents those workloads from reading
issuer state. A compromise of a consumer ServiceAccount remains a compromise
of that consumer's activation evidence and must be handled as a control-plane
incident.

Activation evidence crosses another boundary: an API write proves distribution,
not that a workload has loaded its new material. Verifiers and consumer
acknowledgements are therefore part of the rollover decision.

## Defended failure modes

| Failure or attack | Protection |
| --- | --- |
| Two invocations rotate the same domain | A per-domain lock fences work; state writes also use optimistic concurrency. |
| Process crashes between actions | State is persisted before each external effect and phases are replay-safe. |
| Stale or incomplete consumer activation | The domain remains on dual trust and enters `Blocked`; elapsed time alone cannot retire the active root. |
| Admission probe accidentally validates an active-root leaf during dual trust | The candidate webhook has a candidate-signed leaf and candidate-only trust bundle, so the dry-run admission proof requires the candidate root. |
| A webhook manager replica continues serving an old leaf under dual trust | The live Service TLS probe checks the exact published primary-leaf fingerprint, and every Ready manager replica must acknowledge its own in-memory primary-leaf swap. |
| Partial or malformed projected material | Consumers validate the whole generation and retain their last known-good in-memory TLS state. |
| Node identity / SAN inventory changes | Discovery canonicalizes inputs and binds planned leaves to the observed target snapshot. |
| State Secret is deleted while outputs remain | Automatic reconciliation fails closed and requires explicit, fingerprint-confirmed recovery. |
| Issuer key accidentally reaches a workload | Publication contracts separate issuer state from leaf-only consumer outputs. |

## Deliberate limits

`zeist-pki` v0.1 does not provide external CAs, ACME, Vault, KMS/HSM,
certificate revocation infrastructure, arbitrary issuer plugins, workload
identity, or a general Kubernetes certificate API. Root private keys are
software keys and must be protected by the deployment environment.

The project cannot make a compromised Kubernetes control plane trustworthy,
recover a root key that was never backed up, or prove behavior of an opaque
consumer that provides no verification mechanism. A compromised active root
requires the emergency procedure below rather than waiting for routine
rotation.

## Compromise response

1. Stop automated writers for the affected domain and retain evidence; do not
   delete state or outputs.
2. Restrict access to the suspected issuer-state and consumer Secrets, then
   assess whether the root key or only a leaf key was exposed.
3. If a leaf key is compromised, issue and activate a replacement leaf and
   investigate the consumer boundary.
4. If a root key is compromised, begin an emergency candidate-root rollover
   with dual trust, verified candidate leaves, and explicit acknowledgement.
   Do not retire the old root until the required evidence exists unless an
   immediate trust cutover is the documented incident decision.
5. Preserve the affected state and encrypted backups for forensics, rotate
   access credentials that could read them, and document the incident before
   resuming normal automation.

Routine expiry rollover and emergency compromise handling are intentionally
distinct operational paths.
