# Release Signing

USnPw ships SHA-256 checksum sidecars for release artifacts. CI also produces detached GPG signatures for those checksum files and signs published container images.

## GPG Signatures For Checksum Sidecars

### What CI Produces
CI signs every `*.sha256` file produced by `tools/release.py` and uploads:
- `*.sha256.asc` (detached ASCII-armored signatures)
- `usnpw-release-publickey.asc` (public key used for verification)

Artifact name:
- `UsnPw-signatures`

Workflow:
- `.github/workflows/release-artifacts.yml`

### Enable In GitHub Actions
Create repository secrets:
- `USNPW_GPG_PRIVATE_KEY`: ASCII-armored private key (exported for CI signing)
- `USNPW_GPG_PASSPHRASE`: optional (only if the key is passphrase-protected)

The release workflow fails if `USNPW_GPG_PRIVATE_KEY` is not set.

### Verify As A Consumer
1. Import the public key from the release workflow output:
   - `gpg --import usnpw-release-publickey.asc`
2. Verify the checksum signature:
   - `gpg --verify <artifact>.sha256.asc <artifact>.sha256`
3. Verify the artifact checksum:
   - Linux/macOS: `sha256sum -c <artifact>.sha256`
   - PowerShell: `Get-FileHash <artifact> -Algorithm SHA256`

## Container Image Signing (cosign keyless)

### What CI Does
CI signs the published image digest using keyless signing (GitHub Actions OIDC).

Workflow:
- `.github/workflows/container-ghcr.yml`

Notes:
- Manual `workflow_dispatch`: `sign` defaults to `true` (set `sign=false` to skip).
- Tag publishes sign by default.

### Verification Notes
Keyless verification uses the signing certificate claims (OIDC issuer and identity). Consumers should verify:
- the OIDC issuer is GitHub Actions (`https://token.actions.githubusercontent.com`)
- the certificate identity matches the expected repository/workflow

Exact verification commands depend on your environment and policy. If you need a pinned verification policy, add it to your deployment documentation and treat it as a security boundary.
