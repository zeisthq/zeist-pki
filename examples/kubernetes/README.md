# Kubernetes example

This illustrative configuration uses the built-in `webhook` and `mtls`
profiles with generic resource names. It contains no credentials or private
keys.

Run an offline plan with:

```sh
zeist-pki plan --offline --config examples/kubernetes/pki.yaml
```

Before applying it to a cluster, replace the namespace, Service, Secret,
webhook-configuration, and Node-selector values with the exact resources owned
by your platform. Deploy the issuer with least-privilege access to only those
named resources and back up its encrypted state Secrets before production use.
