# Contributing

Thanks for contributing to `zeist-pki`.

The project is intentionally narrow. Before proposing a new abstraction or
integration, verify that it supports the private-PKI lifecycle contract rather
than expanding the project into a general certificate-management platform.

## Development expectations

- Keep portable packages free of Kubernetes imports. Kubernetes code belongs
  under `integration/kubernetes`.
- Never log, serialize into diagnostics, or add test fixtures containing real
  private keys or credentials.
- Preserve the fail-closed boundary: missing authoritative issuer state plus
  surviving outputs must require explicit recovery, not silently create a new
  root.
- Treat a Kubernetes write as distribution, not proof of activation. Changes
  to rollover behavior must preserve acknowledgement gates and replay safety.
- Add tests for the successful path and the safety boundary changed by the
  patch. Rotation changes need crash/replay coverage where a durable write or
  external effect is introduced.

## Submitting a change

1. Open an issue or discussion for a material API, security-model, or scope
   change before implementation.
2. Keep a pull request focused and explain its trust-boundary impact.
3. Run the relevant unit, fuzz, and integration checks described by the
   repository’s development documentation.
4. Update operator documentation and examples when command behavior,
   configuration, or recovery procedures change.

Security-sensitive findings must follow [SECURITY.md](SECURITY.md), not the
ordinary issue tracker.
