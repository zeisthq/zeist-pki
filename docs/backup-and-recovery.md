# Backup and recovery

Issuer-state storage is recovery material, not an implementation cache. It
contains the active root private key and, during rollover, a candidate root
private key. Losing it can prevent ordinary renewal; exposing it compromises
the trust domain.

## What to protect

Back up each domain’s authoritative state as one encrypted, access-controlled
unit. For the Kubernetes integration, this is the issuer-state Secret for the
affected trust domain containing:

- `active-ca.crt` and `active-ca.key`;
- `candidate-ca.crt` and `candidate-ca.key` only during a root rollover; and
- `state.json`, which records phase, configuration digest, fingerprints,
  generations, target evidence, acknowledgements, and the overlap deadline.

Do not rely on consumer Secrets as a root-key backup: they intentionally omit
issuer private keys. Encrypt backups independently from the Kubernetes API,
limit restore access to the PKI operator role, record access, and test a restore
in an isolated environment. Protect backups for at least as long as an active
or candidate root can authorize a leaf.

## Normal restoration

1. Pause every writer for the affected trust domain. This includes the
   `zeist-pki run` Deployment, CronJobs, CI jobs, and manual sessions.
2. Read existing outputs and state without changing them. Record the active
   root and leaf fingerprints, current phase, output generation annotations,
   and any lock holder.
3. Restore the complete issuer-state record into its original protected store.
   Do not create a replacement state Secret alongside it.
4. Run `zeist-pki plan --config pki.yaml`, review the phase and planned work,
   then run `apply` once under the normal domain fence.
5. Run `verify`, confirm live consumers have the expected generation, and only
   then restart the periodic runner.

Restoring only a root certificate, only a private key, or a `state.json` from a
different configuration is not a valid recovery. The configuration digest and
all root fingerprints must match the state being restored.

## Missing state with surviving outputs

Do not run ordinary `apply`. That condition intentionally fails closed because
minting a new root could sever existing trust.

1. Preserve the outputs and collect the observed active-root fingerprint from
   the public trust material.
2. Search encrypted backups for a complete matching issuer-state record.
3. If found, use the normal restoration procedure.
4. If no backup exists, validate every surviving output and invoke explicit
   recovery with the exact observed fingerprint. Name only the trust domains
   whose state is missing; recovery does not read or modify unselected domains:

   ```sh
   zeist-pki recover --config pki.yaml \
     --domain webhook \
     --confirm-active-root-fingerprint webhook=sha256:<webhook-root-fingerprint> \
     --domain mtls \
     --confirm-active-root-fingerprint mtls=sha256:<mtls-root-fingerprint>
   ```

5. Review the recovery plan before allowing it to write state. If the active
   private key is unavailable, recovery must schedule a safe candidate-root
   rollover; it must never claim routine leaf renewal is possible.

Inconsistent, expired, or unverifiable outputs require a controlled
rebootstrap rather than adoption. For a managed output set, recovery also
requires every domain, generation, operation, leaf-fingerprint, and
trust-bundle-fingerprint annotation to agree with the material it observes.
An entirely unannotated legacy set can be adopted as one explicit migration;
a mixed annotated/unannotated set cannot.

## Root-key loss or compromise

If the active private key is lost but the public root remains active, restore a
complete backup if possible. Otherwise use explicit recovery to establish a
candidate root, publish dual trust, prove activation, and roll leaves before
retiring the old root.

If the key may be compromised, follow the emergency procedure in the
[threat model](threat-model.md). The recovery workflow protects availability;
it is not a substitute for incident response or a revocation system.

## Recovery rules

- Never paste PEM into tickets, terminal history, logs, metrics, or status.
- Never delete an old root key merely because a time window has elapsed.
- Never force a blocked domain forward without understanding the missing
  acknowledgement or failed verifier.
- Keep the old state and outputs as forensic evidence until recovery is proven
  and the retention policy permits their removal.
