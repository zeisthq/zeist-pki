# Releasing

Release artifacts are produced only by the tag-triggered GitHub Actions
workflow. This repository does not claim that binaries, images, signatures, or
attestations already exist before a successful `v*` tag release.

## Preconditions

- Tag a reviewed commit with a version beginning with `v`.
- Keep GitHub Actions enabled and allow the release workflow its declared
  `contents`, `packages`, `id-token`, `attestations`, and
  `artifact-metadata` permissions.
- Allow the repository’s `GITHUB_TOKEN` to publish to its GitHub Container
  Registry package. No registry password or long-lived signing key is stored
  in this repository.
- Use a public repository when public Sigstore transparency-log records and
  public GitHub artifact attestations are required.

The workflow derives the actual OCI digest from the image build. It does not
commit a placeholder image digest, signature, SBOM, or credential.

## Produced assets

For each tag release, the workflow builds Linux amd64/arm64 and Darwin
amd64/arm64 binary archives. It publishes:

- compressed binary archives and a SHA-256 checksums file;
- a source SPDX JSON SBOM and an OCI-image SPDX JSON SBOM;
- keyless Sigstore bundles for every release file;
- keyless Cosign signing for the pushed OCI image; and
- GitHub build-provenance attestations for release archives and the immutable
  OCI digest.

The image receives both the release tag and `latest`; deploy your platform using the
immutable digest reported by the release workflow, not the moving tag.

## Verify a release

After downloading an archive and its matching `.sigstore.json` bundle, verify
the keyless signature with the exact workflow identity and release tag:

```sh
cosign verify-blob \
  --bundle zeist-pki_<tag>_<os>_<arch>.tar.gz.sigstore.json \
  --certificate-identity \
    "https://github.com/zeisthq/zeist-pki/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  zeist-pki_<tag>_<os>_<arch>.tar.gz
```

Verify provenance for a downloaded archive with GitHub CLI:

```sh
gh attestation verify zeist-pki_<tag>_<os>_<arch>.tar.gz \
  --repo zeisthq/zeist-pki
```

For the OCI image, use the immutable `sha256:` digest reported by the workflow:

```sh
cosign verify \
  --certificate-identity \
    "https://github.com/zeisthq/zeist-pki/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/zeisthq/zeist-pki@sha256:<digest>
```

The verification identity is deliberately tag-bound. Do not substitute a branch
workflow identity or a mutable image tag.
