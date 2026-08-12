# Zeist integration

The Zeist integration is a Kubernetes adapter for two private platform trust
domains. It preserves the existing Secret names and data keys so consumers can
migrate from the prior OpenSSL scripts without an application-facing API
change.

## Trust domains and outputs

| Trust domain | Purpose | Consumer Secret | Data keys |
| --- | --- | --- | --- |
| Webhook | Kubernetes API server to Zeist admission webhook TLS | `zeist-engine-webhook-server-cert` | `tls.crt`, `tls.key` |
| Webhook rollover canary | Candidate-root admission activation proof only | `zeist-engine-webhook-rotation-canary-cert` | `tls.crt`, `tls.key` |
| Runner server | zeistd server TLS | `zeistd-server-tls` | `tls.crt`, `tls.key`, `ca.crt` |
| Runner client | controller-manager client mTLS | `zeistd-controller-client-tls` | `tls.crt`, `tls.key`, `ca.crt` |

The webhook root and runner root are independent. Issuer private keys stay in
restricted opaque state Secrets such as `zeist-webhook-pki-state` and
`zeist-mtls-pki-state`; consumer Secrets never contain them.

The Kubernetes publisher annotates each output with its generation, operation
identity, leaf fingerprint, and trust-bundle fingerprint. Consumers use those
values only as observability and acknowledgement evidence; certificate and key
validation remains authoritative.

## Discovery and verification

The webhook integration discovers only mutating and validating webhook
configurations whose client configuration references the exact configured
Service. It updates only `clientConfig.caBundle` and preserves every other
webhook field.

The runner server certificate contains the canonical union of `InternalIP`
values from Nodes that match:

```yaml
zeist.io/firecracker-capable: "true"
```

Each eligible Node endpoint is verified with TLS 1.3 against `/v2/status` on
port `10443`. Root rollover additionally requires consumer acknowledgement of
the exact leaf and root fingerprints after each consumer has atomically loaded
a valid projected-Secret generation.

The webhook domain likewise snapshots every currently Ready manager Pod. Each
replica must acknowledge the primary serving leaf and published trust-bundle
fingerprints only after its validated in-memory swap; an API-server probe alone
cannot retire trust while another manager replica still serves an older leaf.

For the webhook domain, a Kubernetes API-server admission request is the
activation proof; a Secret write alone is not enough. HA control planes require
successful probes through every configured API-server endpoint. The dedicated
canary webhook serves a candidate-root-signed certificate and its own
candidate-only trust bundle during rollover. The probe is a dry-run update of
one precreated, zero-capacity `SandboxPool`; the canary denies every other
request. The normal webhook Service is also probed with its exact expected
leaf fingerprint, so a still-serving active-root leaf cannot be mistaken for
candidate activation under dual trust. The production webhook leaves are not
changed until this proof succeeds.

## Deployment order

1. Apply the acknowledgement namespace/RBAC and the precreated cluster-scoped
   canary `SandboxPool`, then apply the namespace, `zeist-pki` configuration,
   ServiceAccount/RBAC, Services, and webhook configurations.
2. Run a bootstrap Job with `zeist-pki apply` to create both trust domains.
3. Deploy the Zeist manager and zeistd only after their required Secrets exist.
4. Deploy exactly one periodic `zeist-pki run` worker for renewal and Node/IP
   discovery.

In the Zeist Engine repository, the first step is intentionally explicit:
apply `config/pki-acknowledgements` and
`config/pki/canary-sandboxpool.yaml` before applying `config/cell`. The latter
file is outside the namespaced Kustomization because `SandboxPool` is cluster
scoped.

Do not remove the prior OpenSSL scripts as an authority until a fresh-cell
bootstrap, leaf renewal, and live root rollover have passed the relevant
offline and logical-cell checks. When adopting an existing deployment, install
consumer hot reload first and use guarded recovery; a missing issuer key means
the imported root needs a safe rollover.

## Minimum Kubernetes permissions

Run the issuer under a dedicated ServiceAccount. Scope its permissions to its
namespace and named state/output Secrets, per-domain Leases, eligible Nodes,
the relevant consumer Pods, acknowledgement Leases in
`acknowledgementNamespace` (or the main namespace when it is omitted), and only
the named webhook configuration resources matching the configured Services.
The admission probe additionally needs only `get` and `update` on the exact
precreated canary `SandboxPool`, and every update is server-side dry-run.
Enable
Kubernetes encryption at rest for issuer-state Secrets and maintain an
encrypted off-cluster backup.

The complete example configuration is
[`examples/zeist/pki.yaml`](../examples/zeist/pki.yaml).
