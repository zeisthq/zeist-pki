# Zeist Kubernetes example

This configuration preserves the Zeist issue #96 consumer contract:

- `zeist-engine-webhook-server-cert`: `tls.crt`, `tls.key`
- `zeistd-server-tls`: `tls.crt`, `tls.key`, `ca.crt`
- `zeistd-controller-client-tls`: `tls.crt`, `tls.key`, `ca.crt`

Use it only after applying the dedicated ServiceAccount, least-privilege RBAC,
the acknowledgement namespace, and the precreated candidate probe
`SandboxPool`, plus the encrypted Secret-storage policy described in
[the Zeist integration guide](../../docs/zeist-integration.md). On a fresh
cell, run the bootstrap command before deploying the manager or zeistd:

```sh
zeist-pki plan --offline --config examples/zeist/pki.yaml
zeist-pki apply --config examples/zeist/pki.yaml
zeist-pki verify --config examples/zeist/pki.yaml
```

Then run exactly one periodic worker:

```sh
zeist-pki run --config examples/zeist/pki.yaml
```

`run` reconciles immediately and then at its fixed five-minute interval with
jitter; it does not accept an interval override. The explicit `--offline` plan
preview does not read cluster state and therefore shows the fresh-bootstrap
actions only.

The configuration intentionally has no private keys, kubeconfig, bearer token,
or certificate data. It is a compatibility example, not a substitute for the
deployment ordering, hot-reload, and live rollover validation requirements.

If a single issuer-state Secret is lost while its outputs survive, recover only
that trust domain after validating the public root fingerprint. For example:

```sh
zeist-pki recover --config examples/zeist/pki.yaml \
  --domain mtls \
  --confirm-active-root-fingerprint mtls=sha256:<observed-root-fingerprint>
```

Do not include `webhook` unless its own state is missing and independently
validated. Recovery leaves domains not named by `--domain` untouched.
