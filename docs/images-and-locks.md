# Images, locks and SBOMs

This page describes an image repo that has been converted to lock files.
Today that is [idss-mesa/cli](https://github.com/idss-mesa/cli); the other
four follow the same pattern as they are converted
([Adding an image repo](adopting.md)).

## What is in an image repo

| Path | Role |
|---|---|
| `<context>/Dockerfile` | The CPU image. `<context>` is `bash/` in cli and `latest/` elsewhere |
| `gpu/Dockerfile`, `sandbox/Dockerfile` | The GPU layer and the sandbox lockdown layer. Each takes the image below it as `BASE_IMAGE` |
| `<context>/locks/`, `gpu/locks/`, `<context>/environment.yml` | Intent files written by people (`locks/*.in`, `locks/npm/package.json`, and the conda `environment.yml` in the context root) and the lock files generated from them, all under `locks/` |
| `relock.sh` | Regenerates every lock file from its intent file (`make relock`) |
| `VERSION` | `X.Y.Z`, the next release. Merging a change to it starts a release |
| `mesa.env` | Image name, build context, architectures, and settings for the sandbox test |
| `ci/` | The shared scripts, copied from this repo and guarded by `ci/SHARED.sha256`; plus the repo's own `pins.tsv` and `test-cpu.sh` |
| `sbom/locks.tsv`, `sbom/allow.tsv` | Which lock files make up each variant; what may be in the image without a lock entry |
| `gpu/test-gpu.sh`, `sandbox/test-sandbox.sh`, `ci/test-cpu.sh` | The tests each variant must pass before it is pushed |
| `.github/workflows/` | Thin files that call the shared workflows ([Workflows](workflows.md)) |

## How each kind of input is pinned

The Dockerfile never asks for "the newest" of anything. Each install step
reads a lock file, and the build fails if what it downloads does not match.

| Input | How it is pinned | How it is installed |
|---|---|---|
| Base image | `ARG BASE_IMAGE=repo:tag@sha256:…` in the Dockerfile | `FROM` that digest |
| Dockerfile syntax image, CUDA probe image | by digest, the same way | |
| Python packages (pip) | `*.in` lists what is wanted; `uv pip compile --generate-hashes` writes one lock per architecture with a hash for every file | `pip install --no-deps --require-hashes` |
| Conda environments | `environment.yml` is solved by the base image's own `mamba` into an explicit list of URLs with sha256, one per architecture | `mamba create --file` |
| Node packages (npm) | `package.json` and `package-lock.json` | `npm ci --ignore-scripts` |
| Single downloads (Go, GitHub CLI, AI coding tools, Node, …) | a version and a sha256 per architecture as `ARG`s in the Dockerfile; `ci/pins.tsv` lists them and says where new versions come from | downloaded, checksum verified, then unpacked |
| Tools built from source | a full commit hash | `git checkout` of that commit |
| Packages from the NVIDIA apt repository | exact package versions; the repository's keyring package by sha256 | `apt-get install name=version` |
| Ubuntu packages | **not pinned**: the archive keeps only current versions. What was installed is recorded in the SBOM | `apt-get install` |

Agents and editors that update themselves at run time have that switched off
where a switch exists, so a running container keeps matching its SBOM.

### Changing or updating an input

1. Edit the intent file (for example add a line to a `*.in` file), or change
   a version `ARG` and its checksums in the Dockerfile.
2. Run `make relock`. It needs Docker, `uv` and `crane` on `PATH`.
   `ci/install-tools.sh uv crane` installs pinned copies into `.tools/bin`,
   which `make relock` does not look in, so run
   `PATH="$PWD/.tools/bin:$PATH" make relock`. It rewrites every lock.
   For cli a full run takes about 14 minutes, most of it the conda solve.
   Running it twice in a row changes nothing unless upstream published
   something in between.
3. Open a pull request with the intent file and the regenerated locks. The
   [pull-request check](workflows.md#pull-request-check) builds from them.
4. If a released version exists, raise `VERSION` in the same pull request:
   the check refuses a change to the image under an already released
   version.

## One Dockerfile for both kinds of tags

Release images and rolling images come from the same Dockerfile and the same
install steps. The difference is only which lock files are used:

- a **release** uses the lock files committed in git;
- a **rolling** build is meant to regenerate the locks first, in its
  workspace, without committing them, so it picks up current packages
  (planned; see [Workflows](workflows.md#rolling-builds)).

## The software bill of materials

For every variant and platform the pipeline writes one CycloneDX 1.6
document, `image.cdx.json`. It is assembled from three sources:

| Source | Tool | What it knows |
|---|---|---|
| The lock files | `ci/sbom_from_locks.py` | What *should* be in the image, with the hashes and download URLs from the locks |
| A scan of the built image | [syft](https://github.com/anchore/syft) | What files and packages *are* in the image, layer by layer |
| A probe of the built image | `ci/sbom_probe.py` | What a scanner cannot see: conda's package records, and the version each pinned tool reports when run |

`ci/sbom_merge.py` combines them into the published document and stamps it
with the image's name, digest, version, variant, platform and git commit.

### The cross-check

`ci/sbom_crosscheck.py` compares the lock files with the image, in both
directions:

- **Forward (a failure stops the build):** every locked package must be in
  the image, in the locked place, at the locked version. A conda package
  must also have the locked build and checksum. A pinned tool must report
  the pinned version.
- **Reverse (a warning today):** everything the scanner finds must be
  explained by a lock entry, by a pinned tool's directory, by the pinned
  base image's own layers, or by a rule in `sbom/allow.tsv`. This catches
  software that got into the image without being declared. It will become a
  failure once every repo has been through a few releases without warnings.

Measured on the cli images: all 517 checkable lock entries of the CPU image
and all 586 of the GPU image were found as locked, and none of the roughly
2,000 components the scanner reported in each was unexplained.

The exact rules, file formats and exit codes are in
[`ci/README.md`](../ci/README.md).

### What the SBOM is attached to

The SBOM belongs to one image digest. It is published in two places:

- as an **attestation** stored next to the image in the registry, signed
  with [cosign](https://docs.sigstore.dev/cosign/) ("keyless": GitHub
  issues the running workflow a short-lived identity token, and Sigstore
  issues the signing certificate from it);
- as a file on the **GitHub Release**, together with `release-manifest.json`
  (which tag is which digest) and `SHA256SUMS`.

[Verifying an image](verifying-an-image.md) shows how to read both.
