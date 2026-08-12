# Portable library example

Run this example from the repository root:

```sh
go run ./examples/generic
```

It creates an in-memory ECDSA P-256 private root, issues a DNS-constrained
server leaf, validates the resulting chain, and prints only public certificate
fingerprints. It does not write PEM material, use Kubernetes, or represent a
production key store.

A production integration keeps root material in a protected state store and
connects the portable rotation engine to its own `StateStore`, `Locker`,
`Publisher`, `Discoverer`, and `Verifier` adapters.
