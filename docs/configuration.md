# Configuration

`zeist-pki` reads a versioned YAML configuration file. It is a CLI input, not
a Kubernetes API and not a certificate CRD. A common configuration names only
the environment-specific values that cannot be safely discovered; secure
certificate and rollover policy defaults are built in.

The current document version is `pki.zeist.io/v1alpha1`. Version 0.1 has two
built-in, independently managed domains: `webhook` and `mtls`. The top-level
configuration identifies the target namespace, optionally names the namespace
holding consumer acknowledgement Leases, and supplies profile-specific settings
for those domains. Output and issuer-state contracts are fixed by the profile,
not made arbitrary configuration.

The configuration has a small fixed catalog of trust-domain profiles:

- `webhook` issues a server-authentication leaf for an admission webhook and
  discovers the webhook configurations that reference its exact Service.
- `mtls` issues the shared server-authentication and controller
  client-authentication leaves used by a private service boundary. Its
  Kubernetes integration discovers eligible Node `InternalIP` values.

The minimal v0.1 shape is:

```yaml
apiVersion: pki.zeist.io/v1alpha1
namespace: platform-system
acknowledgementNamespace: pki-acknowledgements
webhook:
  service: platform-webhook
  secret: platform-webhook-tls
  canaryService: platform-webhook-rotation-canary
  canarySecret: platform-webhook-rotation-canary-tls
  canaryConfiguration: platform-pki-rotation-canary
mtls:
  serverSecret: platform-server-tls
  clientSecret: platform-client-tls
  nodeSelector:
    platform.example.io/private-tls: "true"
  port: 10443
```

`acknowledgementNamespace` is optional and defaults to `namespace`. It isolates
short-lived consumer acknowledgement Leases when a deployment has a dedicated
control namespace. The issuer ServiceAccount needs the corresponding narrowly
scoped Lease permissions in that namespace.

A runnable, generic version of this configuration is available at
[`examples/kubernetes/pki.yaml`](../examples/kubernetes/pki.yaml). It contains
no credentials, private keys, or product-specific resource names.

The webhook canary names are required for the included webhook rollover flow. They name a
separate TLS endpoint and a narrowly matched `ValidatingWebhookConfiguration`.
During a root rollover the normal webhook configurations receive dual trust,
while the canary configuration receives the candidate root *only*. The canary
leaf is also signed by that candidate root. This prevents the admission probe
from succeeding merely because an active-root leaf remains valid under dual
trust. `apiServerEndpoints` is optional for one API-server origin; for HA
control planes it must list every HTTPS API-server origin that must prove the
new trust.

An optional top-level `policy` map overrides the duration fields for both
built-in domains: `rootValidity`, `rootRolloverBefore`, `leafValidity`,
`leafRenewBefore`, `minimumTrustOverlap`, and `clockSkew`. Omit it to use the
safe defaults.

## Defaults

| Setting | Default |
| --- | --- |
| Root validity | 365 days |
| Begin root rollover | 90 days before root expiry |
| Leaf validity | 90 days |
| Begin leaf renewal | 30 days before leaf expiry |
| Minimum dual-trust overlap | 30 days |
| NotBefore backdating / clock skew allowance | 5 minutes |
| Key algorithm | ECDSA P-256 |

Leaf validity is always bounded by the issuing root’s validity. The command
does not expose an arbitrary issuer or arbitrary certificate-template API.

## Generic library use

[`examples/generic`](../examples/generic) issues and validates a private root
and server leaf with the portable `pki` package. A production non-Kubernetes
integration supplies `StateStore`, `Locker`, `Publisher`, `Discoverer`, and
`Verifier` to the portable `rotation` package; it does not use this
Kubernetes-specific YAML configuration.

## Kubernetes output contracts

The configuration chooses the output Secret names. The built-in profiles use
the following data keys:

| Trust domain | Secret | Data keys |
| --- | --- | --- |
| Webhook | configured `webhook.secret` | `tls.crt`, `tls.key` |
| Webhook rollover canary | configured `webhook.canarySecret` | `tls.crt`, `tls.key` |
| mTLS server | configured `mtls.serverSecret` | `tls.crt`, `tls.key`, `ca.crt` |
| mTLS client | configured `mtls.clientSecret` | `tls.crt`, `tls.key`, `ca.crt` |

The mTLS server’s SAN set is the canonical union of `InternalIP` values from
the selected Nodes. Changing that inventory causes the next reconciliation to
plan and, when applicable, publish a fresh server leaf.

The webhook and runner trust domains have independent roots. Routine leaf
renewal reuses the active root. A root rollover is a staged, stateful operation
that enters dual trust before candidate-signed leaves are activated.

## Command output

All commands accept `--output=text` (the default) or `--output=json`.
Human-readable output identifies the domain, phase, intended action, and
blocked reason. JSON is for automation. Neither format includes PEM,
credentials, or private-key material.

`plan` has no side effects: it does not generate keys, acquire a lease, or
write state. `plan --offline` also avoids reading Kubernetes state and shows
the deterministic fresh-bootstrap actions. `apply` executes one bounded
reconciliation. `run` is suitable for one dedicated Deployment or another
single scheduler; it reconciles immediately and then on its fixed five-minute
interval with jitter to avoid synchronized work.

`recover` requires one or more repeatable `--domain` flags and an exact
`--confirm-active-root-fingerprint domain=<fingerprint>` for each selected
domain. It never inspects or modifies a configured domain that was not named
by `--domain`.
