# Kubernetes example

This illustrative configuration uses the built-in `webhook`, `mtls`, and
`serviceMTLS` profiles. It uses generic resource names. It contains no
credentials or private keys.

Run an offline plan with:

```sh
zeist-pki plan --offline --config examples/kubernetes/pki.yaml
```

Before applying it, replace every namespace, Service, Secret, selector, and
webhook resource value. Use the exact resources that your platform owns.
Give the issuer access to only those resources. Back up its encrypted state
Secrets before production use.
