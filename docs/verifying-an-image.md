# Verifying an image

For users of the MESA images: how to check that a release image was built by
the MESA release workflow from a known commit, and how to read what is
inside it.

This applies to **release** tags (`vX.Y.Z…`). Rolling tags (`latest`, `gpu`,
…) carry no signed SBOM attestation today. (`latest` and `arm64` have only
the unsigned build provenance that Docker's build action adds by default; it
cannot be verified with the command below.)

> No release has been published yet; `mesa-cli` `v2.0.0` will be the first.
> The commands below use it as the example.

## What you need

- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.x
- `jq`, `curl`, and Docker with `buildx` (or any other tool that resolves a
  tag to a digest, such as `crane digest`)
- the GitHub Release page of the version, for example
  `https://github.com/idss-mesa/cli/releases/tag/v2.0.0`. Its notes list
  every image of the release with its digest and the commit it was built
  from.

No account and no key are needed. The images are public, and the signatures
are checked against the public [Sigstore](https://www.sigstore.dev)
infrastructure.

## 1. Pin the image by digest

A tag is a name that can, in principle, be pointed elsewhere. A digest is
the image. Take the digest from the release notes, or resolve the tag
yourself and compare it with the notes:

```bash
IMAGE=harbor.cyverse.org/vice/mesa-cli
docker buildx imagetools inspect $IMAGE:v2.0.0 --format '{{json .Manifest}}' | jq -r .digest
# sha256:…
DIGEST=sha256:…        # the value printed, which must equal the one in the release notes
```

## 2. Verify the attestation

Fill in the commit from the release notes:

```bash
COMMIT=…               # 40 characters, "built from the lock files at …" in the release notes

cosign verify-attestation --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/idss-mesa/mesa-updater/\.github/workflows/mesa-release\.yml@' \
  --certificate-github-workflow-repository idss-mesa/cli \
  --certificate-github-workflow-ref refs/heads/main \
  --certificate-github-workflow-sha $COMMIT \
  $IMAGE@$DIGEST > attestation.jsonl
```

The release notes contain this command with the values filled in.

If it succeeds, all of this is true:

| Flag | What it establishes |
|---|---|
| `--certificate-oidc-issuer` | the signature was made inside a GitHub Actions run |
| `--certificate-identity-regexp` | the job that signed was the shared MESA release workflow |
| `--certificate-github-workflow-repository` | it was running for the `idss-mesa/cli` repository |
| `--certificate-github-workflow-ref` | on the branch `main`, which only changes through reviewed pull requests |
| `--certificate-github-workflow-sha` | at exactly this commit, so the Dockerfile and lock files you can read at that commit are the ones that were built |

If any of them does not match, cosign prints an error and exits non-zero.
An image pushed by hand, or built by a workflow on another branch, fails
this check even if it carries the tag `v2.0.0`.

## 3. Read the SBOM

The attestation *is* the SBOM, wrapped in a signed envelope:

```bash
head -n 1 attestation.jsonl | jq -r .payload | base64 -d | jq .predicate > sbom.cdx.json

jq '.metadata.component' sbom.cdx.json                       # the image: name and digest
jq -r '.metadata.properties[] | "\(.name) = \(.value)"' sbom.cdx.json   # version, variant, platform, commit
jq '.components | length' sbom.cdx.json                      # how many components
jq -r '.components[] | select(.name == "numpy") | "\(.version)  \(.purl)"' sbom.cdx.json
```

The document is [CycloneDX](https://cyclonedx.org) 1.6 JSON. Almost every
component has a package URL (`purl`); a few file-level entries reported by
the scanner have none. Components that came from a lock file also carry the
hash from the lock and, where the lock records one (conda and npm packages,
pinned downloads), the download URL, and properties named `mesa:lock:*` that
say which lock file and which install location they belong to.

The same file is attached to the GitHub Release as
`mesa-cli-<tag>.cdx.json`. To check a downloaded copy:

```bash
base=https://github.com/idss-mesa/cli/releases/download/v2.0.0
curl -fsSL --remote-name-all $base/SHA256SUMS $base/release-manifest.json $base/mesa-cli-v2.0.0.cdx.json
sha256sum -c --ignore-missing SHA256SUMS
```

With the GitHub CLI and a GitHub login,
`gh release download v2.0.0 --repo idss-mesa/cli` fetches every file of the
release, and `sha256sum -c SHA256SUMS` then checks them all.

`release-manifest.json` in the same place maps every tag of the release to
its digest.

## 4. Use it

Scan the SBOM for known vulnerabilities without pulling the image, with
[grype](https://github.com/anchore/grype):

```bash
grype sbom:sbom.cdx.json
```

Compare two releases:

```bash
jq -r '.components[] | select(.purl) | .purl' old.cdx.json | sort > old.txt
jq -r '.components[] | select(.purl) | .purl' new.cdx.json | sort > new.txt
diff old.txt new.txt
```

Run exactly the verified image:

```bash
docker run --rm -p 7681:7681 $IMAGE@$DIGEST
```

## What the verification does and does not tell you

It tells you **who built the image and from what**: the MESA release
workflow, from a specific commit of a public repository, with every input
named by version and checksum in that commit, and that the listed packages
were found in the image at the locked versions.

It does not tell you that the software inside is free of defects or
vulnerabilities, and it does not cover the Ubuntu packages beyond listing
the versions that were installed: those come from the Ubuntu archive as it
was on the day of the build.
