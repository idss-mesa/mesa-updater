# ci/ — shared lock and SBOM tooling

The files in this directory are the canonical copy. Each image repo
(`idss-mesa/{cli,jupyterlab,kasm,rstudio,vscode}`) carries a byte-identical
copy in its own `ci/`, checked against `ci/SHARED.sha256` (`../sync.sh` writes
the manifest and copies the files). Workflows only call `ci/mesa-ci.sh`, so
every step also works by hand.

All Python here is **stdlib only, Python >= 3.10**, one file per tool, each
runnable as `python3 ci/<tool>.py --help`. Shell is bash with
`set -euo pipefail`, shellcheck clean. No tool reads credentials; registry
access goes through the Docker config that `docker login` wrote.

## `mesa-ci.sh` — what the workflows run

Run from an image repo's root:

```
ci/mesa-ci.sh check                  # shared files unchanged, VERSION is X.Y.Z, every lock and pin parses
VARIANT=cpu ci/mesa-ci.sh build      # local image mesa-local/<name>:<variant>-<arch>
VARIANT=cpu ci/mesa-ci.sh test       # ci/test-cpu.sh, gpu/test-gpu.sh or sandbox/test-sandbox.sh
VARIANT=cpu ci/mesa-ci.sh push       # push it as <image>:stage-<STAGE_ID>-<variant>-<arch>; digest in out/<variant>-<arch>/digest
VARIANT=cpu ci/mesa-ci.sh sbom       # syft scan, lock SBOM, probe, cross-check, merged SBOM in out/<variant>-<arch>/
```

`VARIANT` is `cpu` (default), `sandbox`, `gpu` or `gpu-sandbox`; a variant
builds FROM the local image of the one below it unless `BASE_REF` names
another. `ARCH` defaults to the machine's. `sbom` exits non-zero when the
cross-check fails and still writes the merged SBOM; `STRICT_REVERSE=1` also
fails on unexplained scanner components. `sbom` needs `syft` and `crane`
(`ci/install-tools.sh syft crane`).

`push` needs a registry login and `crane`. It writes a **staging tag**, which
nobody pulls: the tags users see are written by `release.py publish` once
every variant has passed. The tag is never read back (anyone with push access
could have moved it): the digest is the one `docker push` reports, and it is
recorded only when the manifest stored under that digest is the image that
was built and tested here (its config digest, or with the containerd image
store the manifest digest itself, is the local image ID). An image index is
refused (the build pushes one image manifest, without a provenance
attestation). `sbom` records
the pushed digest when `push` ran before it, else the local image ID. `build`
with a `BASE_REF` of the form `<image>@sha256:...` records that digest in
`out/<variant>-<arch>/base`; a release checks it.

With `CHECK_RELEASED=1`, `check` also asks `origin` whether `VERSION` already
has a git tag `vX.Y.Z`. If it has, the files under the CPU context, `gpu/`
and `sandbox/` (other than `*.md`) must be those of that tag: a change to an
image needs a new version. An unreachable `origin` is an error.

Each image repo keeps, next to its copy of `ci/`:

| File | Content |
|---|---|
| `VERSION` | `X.Y.Z`, the next (or current) release |
| `mesa.env` | `MESA_IMAGE` (registry path without tag), `MESA_CONTEXT` (CPU build context directory), `MESA_ARCHES` (e.g. `"amd64 arm64"`), `MESA_SANDBOX_PORT`, `MESA_SANDBOX_PATH`, `MESA_SANDBOX_DOCKER_ARGS` (for `sandbox/test-sandbox.sh`) |
| `ci/test-cpu.sh IMAGE` | the repo's own smoke test of the CPU image |
| `ci/pins.tsv`, `sbom/locks.tsv`, `sbom/allow.tsv` | described below |

The reusable workflow `.github/workflows/mesa-pr.yml` in this repo runs
`check`, then `build`, `test` and `sbom` for the CPU image on each
architecture and for the sandbox image on amd64, with no secrets.

## Release

A release is the set of images of one `VERSION`, each with an attested SBOM:

| Variant, arch | Tag |
|---|---|
| cpu, amd64 | `vX.Y.Z` |
| sandbox, amd64 | `vX.Y.Z-sandbox` |
| gpu, amd64 | `vX.Y.Z-gpu` |
| gpu-sandbox, amd64 | `vX.Y.Z-gpu-sandbox` |
| cpu, arm64 (repos whose `MESA_ARCHES` has it) | `vX.Y.Z-arm64` |

Merging a change to `VERSION` on `main` starts it
(`.github/workflows/mesa-release.yml`, called from each image repo's
`release.yml`). The order is fixed:

1. **guard** (`release.py guard`): the version is not released yet.
2. **build**, per architecture on a hosted runner: `build`, `test`, `push`,
   `sbom` for the CPU image, then for the sandbox image built on the pushed
   CPU digest. Each SBOM is attested to its digest right away
   (`attach_sbom.sh`, keyless).
3. **gpu** (`gpu_request.sh`): the GPU and GPU-sandbox images are built on
   gpu06, on the pushed CPU digest, by the private repo
   `idss-mesa/mesa-gpu-builder`. The job only asks for that build and waits.
4. **publish** (`release.py publish`), only when everything above passed:
   attest the GPU SBOMs, verify every attestation, write the tags, create the
   GitHub release with the SBOMs, `release-manifest.json` (tag to digest) and
   `SHA256SUMS`.

Until step 4 only staging tags and attestations of staged digests exist.

**If a run dies inside step 4**, use "Re-run failed jobs" on that run: it
finishes the same build, and every part of `publish` first looks at what is
already there. Do not use "Re-run all jobs", and do not start a new run: both
would build other digests, so `guard` refuses a version that is partly
published. Cancelling a run stops the release if `publish` has not started.

**Who may release.** Three things tie a release to what was merged:

- The attestations are signed with a certificate GitHub issues to the
  running workflow. It names the shared workflow file, the image repo, the
  branch and the commit; `publish`, the GPU builder and the command in the
  release notes all check all four. A run from another branch cannot produce
  an attestation that passes for `main`.
- The GPU builder only builds a commit on `main`, on a CPU image carrying
  such an attestation from a run on `main` at that commit.
- The key that lets a workflow ask the builder for a build is a secret of the
  image repo's environment `gpu-dispatch`, which only runs on `main` can use.

These rest on `main` itself being protected (pull requests only) in the image
repos and in this repo.

**What a tag alone does not prove.** The registry credentials are secrets any
workflow run in an image repo can use, on any branch. Whoever can push a
branch there can therefore write tags in `vice/mesa-<app>` directly: move a
rolling tag, or create a `vX.Y.Z` tag before the release does. The registry's
immutability rule for `v*` stops an existing release tag from being moved,
not a new one from being created. So:

- an image is a release only together with its attestation; the command in
  the release notes checks it, and no branch run can produce one that passes;
- a `vX.Y.Z` tag created by hand makes `guard` refuse that version ("partly
  published"). A registry project admin removes the tag, or the next patch
  version is released instead;
- moving the registry credentials into an environment limited to `main`
  (with a separate registry project for test runs from branches) closes
  this; it is not done yet.

A **test run** passes a tag prefix `ci-test-<word>-`. It writes
`ci-test-<word>-vX.Y.Z*` tags and a draft GitHub release and creates no git
tag. From a branch other than `main` it must leave the GPU variants out.

GPU builds of all image repos share one runner that takes one job at a time.
The gpu job waits up to 200 minutes, queueing included; when that runs out,
"Re-run failed jobs" asks again. When the gpu job fails or is cancelled it
cancels the builder run it started. If it died before learning which run that
was, stop it by hand:
`gh run cancel <id> --repo idss-mesa/mesa-gpu-builder`.

**Known gaps.**

- Between the merge of a new `VERSION` and the appearance of its git tag (the
  length of a release, longer if it fails), a pull request that changes image
  files without raising `VERSION` passes the check. Once the tag exists,
  every pull request fails with "these image files differ from the released
  vX.Y.Z" until `VERSION` is raised. A check after each merge to `main` is
  planned with the rolling workflow.
- Keyless verification relies on the time the transparency log recorded for
  the signature. If verification starts failing after a change of Sigstore's
  default signing configuration, look at cosign's `--use-signed-timestamps`
  first.
- "Re-run all jobs" cannot finish a partly published release (see above).

### `release.py`

```
release.py plan    [--tag-prefix P] [--skip-gpu]
release.py guard   [--tag-prefix P] [--skip-gpu] --ref REF --github-repo OWNER/NAME [--github-output FILE]
release.py publish [--tag-prefix P] [--skip-gpu] --out DIR --revision SHA
                   --ref REF --github-repo OWNER/NAME --identity-regexp RE | --cosign-key cosign.pub
                   [--no-github-release]
```

Run from the image repo's root (or `--repo-root`); reads `mesa.env` and
`VERSION`. Uses `crane`, `cosign`, `gh` and `attach_sbom.sh`
(`--crane`, `--cosign`, `--gh`, `--attach` name other binaries). Exit 2 on bad
arguments or repo files, 1 when the release cannot go on.

`plan` prints the release as JSON: `image`, `name`, `version`, `release`
(the tag of the GitHub release), `test`, `arches` and `images`
(`variant`, `arch`, `tag`).

Both `guard` and `publish` refuse a real release unless `--ref` is
`refs/heads/main` and the GPU variants are included, and refuse a test run
with GPU variants from any other ref.

`guard` prints the state and, with `--github-output`, appends `state`,
`release`, `image`, `test` and `arches` (a JSON list) to that file:

| Found | Result |
|---|---|
| no tag of the release in the registry, no published GitHub release, no git tag | `state=new` |
| every tag, a published GitHub release, and its `release-manifest.json` lists exactly the digests the tags point at | `state=released`: the workflow ends without doing anything |
| every tag and a published release whose manifest differs or cannot be read | fails |
| anything in between | fails: partly published |
| test run: any of its tags exists | fails: delete them or use another prefix |

A registry or GitHub error is never read as "not there": only the registry's
`NOT_FOUND` / `MANIFEST_UNKNOWN` and GitHub's 404 count as absent.

`publish` reads `DIR/<variant>-<arch>/{digest,image.cdx.json,report.json}`
(and `base` for every variant but `cpu`) for each image of the plan and stops
before writing anything unless:

- each SBOM names this image, its own digest, this version, variant, arch and
  `--revision`, and its cross-check report has no `missing`,
  `version-mismatch` or `hash-mismatch` entry;
- each variant's `base` is the staged digest of the variant it builds on
  (sandbox and gpu on cpu, gpu-sandbox on gpu), and its layers start with
  that image's layers and add at least one;
- each digest is in the registry and is a `linux/<arch>` image;
- each release tag is absent or already points at that digest.

Then, in this order:

1. **Attestations.** For each image, `cosign verify-attestation` with the
   issuer GitHub Actions, the identity `--identity-regexp`, and the
   repository `--github-repo`, ref `--ref` and commit `--revision` of the
   signing run. An attestation counts when it verifies, is a CycloneDX
   attestation of this digest and carries exactly this SBOM.
   - One counts: nothing to do.
   - Some verify but none carries this SBOM: `attach_sbom.sh` signs this one.
   - Nothing verifies: `attach_sbom.sh --index-only` first (an earlier
     attempt may have attested and died before writing the tag cosign finds
     it by). If a CycloneDX attestation is among the referrers and still
     nothing verifies, `publish` stops rather than sign again. If none is
     attached (exit 3), `attach_sbom.sh` signs.
   After signing, the image is verified again; failing that stops everything.
2. **Tags**, only when every image verified: each tag is read again and
   written with `crane tag` if absent; a tag that meanwhile points elsewhere
   stops the run. (The registry's immutability rule for `v*` is what makes a
   written tag final; this check only makes a collision visible.)
3. **Release files** in `DIR/release/`: `<name>-<tag>.cdx.json` per image,
   `release-manifest.json`, `SHA256SUMS`, `notes.md`. An existing directory
   there is replaced only if it is an earlier release directory.
4. **GitHub release**: `gh release create` at `--revision` (a draft for a
   test run). If the release exists its files are uploaded again, and a
   draft of a real release (left by an attempt that died, or written by
   hand) is then published. A real release ends with a check that the
   release is published and its git tag is on `--revision`.

`--cosign-key` verifies with a public key and no transparency log, for tests
outside GitHub Actions (`COSIGN_KEY` and `COSIGN_SIGNING_CONFIG` make
`attach_sbom.sh` sign the same way). `--no-github-release` stops after the
release files. A real release refuses both.

### `gpu_request.sh`

```
gpu_request.sh start CPU_DIGEST          # dispatch; prints the builder's run id
gpu_request.sh wait RUN_ID MINUTES DIR   # wait; when finished, download the result into DIR
gpu_request.sh cancel RUN_ID
```

`GH_TOKEN` must be a token of the GitHub App that may start workflow runs in
`idss-mesa/mesa-gpu-builder` and nothing else (Actions: write on that one
repo). `start` sends the repo name, `GITHUB_SHA`, the CPU digest, `STAGE_ID`
and `<run id>-<attempt>`, and takes the run id from the answer to the
dispatch (falling back to the run named `<repo> <run id>-<attempt>` if the
answer has none). The builder refuses any commit that is not on `main` of one
of the five image repos and any CPU image not attested by a run on `main` at
that commit. `wait` exits 1 when the build failed or its result cannot be
downloaded; otherwise it exits 0 and writes `done=true` or `done=false` to
`GITHUB_OUTPUT`, so a workflow can wait in several steps with a fresh token
each (an App token lasts an hour). The result is the builder's
`out/<variant>-amd64/` directories for `gpu` and `gpu-sandbox`.

## Terms

| Term | Meaning |
|---|---|
| layer | One of `cpu`, `gpu`, `sandbox`: the Dockerfile that adds something (`<ctx>/Dockerfile`, `gpu/Dockerfile`, `sandbox/Dockerfile`) |
| variant | A published image: `cpu` = [cpu]; `sandbox` = [cpu, sandbox]; `gpu` = [cpu, gpu]; `gpu-sandbox` = [cpu, gpu, sandbox] (layers in build order) |
| arch | `amd64` or `arm64` |
| prefix | Absolute path in the image that a lock installs into, e.g. `/opt/mesa` |

## Inputs kept in each image repo

### `sbom/locks.tsv` — which lock files make up the image

Tab separated, `#` comments, no header. Columns:

| # | Column | Values |
|---|---|---|
| 1 | kind | `base`, `pip`, `npm`, `conda`, `pins`, `cran`, `vsix` |
| 2 | layer | `cpu`, `gpu`, `sandbox` |
| 3 | arch | `amd64`, `arm64`, or `*` |
| 4 | file | path relative to the repo root |
| 5 | prefix | install prefix, or `-` when the kind has none (`base`, `pins`) |

A variant's lock set is every row whose layer is in the variant and whose arch
matches. When two rows give the same (kind, prefix, normalised name), the row
from the later layer wins (a GPU layer may replace a CPU package).

### Lock file formats by kind

| kind | File | Component |
|---|---|---|
| `base` | A Dockerfile. Every `ARG <NAME>_IMAGE=<repo>[:<tag>]@sha256:<hex>` default is a base image. An `*_IMAGE` ARG whose default has no digest (the `BASE_IMAGE` of a GPU or sandbox layer: the image of the same release) is skipped with a note on stderr; a Dockerfile with no digest-pinned `*_IMAGE` ARG is fine and yields no component (with a note when it has no `*_IMAGE` ARG at all). A default written with `@` that is not `@sha256:<64 hex>` is an error | `pkg:oci/<last path segment>@sha256%3A<hex>?repository_url=<registry/path>&tag=<tag>`, type `container` |
| `pip` | Output of `uv pip compile --generate-hashes`: `name==version` or `name @ <url>` entries with `--hash=sha256:` continuation lines, `# via` comments | `pkg:pypi/<name>@<version>` (name normalised per PEP 503; for URL entries the version comes from the wheel/sdist file name; local version `+cu126` kept, percent-encoded) |
| `npm` | `package-lock.json`, lockfileVersion 3 | `pkg:npm/[%40scope/]<name>@<version>` for each `node_modules/...` entry. The package name is the entry's `name` field when present (lockfile aliases), else the path after the last `node_modules/`. Entries with `os` / `cpu` / `libc` lists that exclude `linux` / the arch (`x64` for amd64, `arm64`) / `glibc` are skipped (the images are glibc). `integrity` sha512 base64 becomes a hex SHA-512 hash |
| `conda` | Explicit spec: `@EXPLICIT` then one URL per line ending `#sha256:<64 hex>` or `#<32 hex md5>` | `pkg:conda/<name>@<version>?build=<build>&channel=<channel>&subdir=<subdir>&type=<conda or tar.bz2>` parsed from the URL |
| `pins` | `ci/pins.tsv` (below) | from the row's purl template |
| `cran` | TSV `name<TAB>version` | `pkg:cran/<name>@<version>` |
| `vsix` | TSV `publisher.name<TAB>version<TAB>sha256` | `pkg:generic/<publisher.name>@<version>?repository_url=open-vsx.org` plus a SHA-256 hash |

### `ci/pins.tsv` — pinned downloads declared as Dockerfile `ARG`s (per repo, not shared)

Tab separated, `#` comments, no header. Columns:

| # | Column | Meaning |
|---|---|---|
| 1 | name | component name, unique in the file |
| 2 | layer | `cpu`, `gpu`, `sandbox` |
| 3 | dockerfile | path of the Dockerfile that holds the ARGs |
| 4 | version_arg | ARG whose default is the version, e.g. `GO_VERSION` |
| 5 | hash_args | `amd64=<ARG>,arm64=<ARG>`: ARGs whose default is a SHA-256 (64 hex) or SHA-512 (128 hex) digest; the algorithm is taken from the length. `-` when there is none. |
| 6 | purl | template with `{version}`; a leading `v` in the ARG value is kept only if the template writes it |
| 7 | url | download URL template, recorded as written in the `mesa:lock:url` property; or `-` |
| 8 | path | absolute path of the installed binary or bundle directory; everything a scanner finds under it is explained by this pin; or `-` |
| 9 | probe | shell command run inside the image whose output must contain the version; or `-` |
| 10 | source | where updates come from: `github-release:<owner>/<repo>`, `github-tag:<owner>/<repo>`, `github-commit:<owner>/<repo>`, `npm-lock:<lock path>:<package>`, `apt-packages:<Packages url>:<package>`, `pypi:<package>`, `url:<manifest url>`, `manual`. This column is for the updater and is not read by the SBOM tools |

ARG defaults are read from the Dockerfile text (`ARG NAME=value`, last
definition wins); a missing ARG is an error.

### `sbom/extras.cdx.json` and `sbom/allow.tsv`

`extras.cdx.json` is a CycloneDX 1.6 document of hand-listed components no
scanner or lock sees. `allow.tsv` lists what may be in the image without a lock
entry (tab separated, `#` comments):

| # | Column | Meaning |
|---|---|---|
| 1 | rule | `path` (path prefix: covers the locations under it), `purl-type` (e.g. `deb`), or `purl` (exact purl without qualifiers, `*` allowed as the version) |
| 2 | layer | layer whose content the rule covers, or `*` |
| 3 | value | the prefix / type / purl |
| 4 | reason | free text, required |

## Tools

All tools exit 2 on bad input, and the Python tools also when an output file
cannot be written; `sbom_crosscheck.py` exits 1 when a check fails;
`sbom_probe.py` exits 1 when the image cannot be probed.

### `sbom_from_locks.py`

```
sbom_from_locks.py --repo-root DIR --variant V --arch A [--locks sbom/locks.tsv] -o locks.cdx.json
```

Writes a CycloneDX 1.6 JSON document with one component per lock entry of the
variant. Deterministic: components sorted by purl then prefix, no timestamps or
random serial numbers (the merge step adds those). Every component has `type`,
`name`, `version`, `purl`, `bom-ref` (purl plus `#<prefix>` when a prefix
exists, so the same package in two prefixes stays two components), `hashes`
when the lock has them, an `externalReferences` entry of type `distribution`
when the lock gives a URL (pip, npm, conda; never a pin, whose URL is a
template), and these properties:

| Property | Value |
|---|---|
| `mesa:lock:kind` | the kind |
| `mesa:lock:layer` | the layer |
| `mesa:lock:file` | lock file path relative to the repo root |
| `mesa:lock:prefix` | the prefix (omitted when `-`) |
| `mesa:lock:path` | pins only: column 8 (omitted when `-`) |
| `mesa:lock:probe` | pins only: column 9 (omitted when `-`) |
| `mesa:lock:url` | pins only: column 7, the template as written (omitted when `-`) |

Exit 2 on malformed input, with file and line in the message.

### `sbom_probe.py`

```
sbom_probe.py --image REF --locks-sbom locks.cdx.json -o probe.cdx.json [--docker docker]
```

Collects what scanners miss by running commands in a throwaway container of
the image (`--network none`, entrypoint overridden, no GPU):

- **conda**: every directory `<prefix>/conda-meta` in the image's file system
  except under `/proc`, `/sys` and `/dev`; each package record there becomes `pkg:conda/...` (same form as the lock) with its
  sha256/md5, URL as a `distribution` reference, and property
  `mesa:probe:prefix` = `<prefix>`.
- **pins**: for every lock component with `mesa:lock:probe`, run the command;
  emit the component again with property `mesa:probe:result` = `ok` when the
  output contains the version, else `mismatch`, plus `mesa:probe:output` (first
  200 characters). The version is compared with one leading `v` removed when
  it is followed by a digit, so `v0.19.0` and `0.19.0` both match output
  containing `0.19.0`.

Commands from `pins.tsv` are repo content reviewed in pull requests; they run
only inside the container, never on the host shell.

### `sbom_merge.py`

```
sbom_merge.py --image-sbom syft.cdx.json --locks-sbom locks.cdx.json [--probe-sbom probe.cdx.json]
              [--extras sbom/extras.cdx.json] --name harbor.cyverse.org/vice/mesa-cli --digest sha256:...
              --version v2.0.0 --variant cpu --arch amd64 --revision <git sha> --timestamp <RFC 3339> -o image.cdx.json
```

Produces the published SBOM:

- drops scanner components of type `file`;
- strips the scanner's `package-id` purl qualifier and gives every component a
  `bom-ref` unique in the document;
- merges a scanner component with a lock/probe component when they are the same
  package in the same place (purl equal after normalisation, and the scanner
  location path lies under the lock prefix): the result keeps the scanner's
  fields and gains the lock's hashes, distribution reference and `mesa:lock:*`
  properties;
- keeps lock components the scanner did not see (flagged with property
  `mesa:merge:source` = `lock-only`), probe-only and extras components;
- sets `metadata.component` to the image (type `container`, name, version =
  digest, purl `pkg:oci/...`), `metadata.timestamp` from `--timestamp`,
  `metadata.properties` `mesa:version`, `mesa:variant`, `mesa:arch`,
  `mesa:revision`, and a `serialNumber` that is a UUIDv5 of the digest and
  variant (same inputs, same document);
- keeps `dependencies` entries only for refs that still exist.

### `sbom_crosscheck.py`

```
sbom_crosscheck.py --locks-sbom locks.cdx.json --image-sbom syft.cdx.json [--probe-sbom probe.cdx.json]
                   [--base-layers base-layers.txt] [--allow sbom/allow.tsv] [--strict-reverse]
                   [--report report.json]
```

**Forward check (always a failure):** every lock component must be in the
image with the same version.

- `pip`, `npm`, `cran`: a scanner component with the same purl type and
  normalised name whose location lies under the lock prefix. Not found =
  `missing`; found with another version = `version-mismatch`.
- `conda`: a probe component in the same prefix with the same name, version
  and build, and the same sha256 when both sides have one.
- `pins`: probe result `ok`, or a scanner component of the same name and
  version under the pin's path. Versions are equal here when they are equal
  after removing one leading `v` followed by a digit from each side. A pin
  with neither a probe nor a path is reported as `unverifiable` (warning).
- `base`, `vsix`: not checked here (the Dockerfile's digest pin and the
  build's own extension assertion cover them); listed as `not-checked`.

**Reverse check (warning; failure with `--strict-reverse`):** every scanner
component (type `file` ignored) must be explained. A component is explained
when every one of its locations (`syft:location:<n>:path`) is explained; the
locations need not share a mechanism. A location is explained by:

- `lock`, one of:
  - a lock component as above: same purl type, normalised name and version,
    the location under the lock prefix;
  - a `conda` lock component of the same name and version, the location under
    its prefix. Scanners have no conda cataloger and report what conda
    installed as `pypi` (Python metadata) and `generic` (binaries) components.
    For a `pypi` component the name is normalised per PEP 503 on both sides;
    for any other type it is compared exactly; a component whose purl has a
    namespace never matches. Only lock components count, not the probe's;
  - for an `npm` component under the prefix P of an `npm` lock: the location
    is `P/package.json` (the lock's root manifest), or a `package.json` at
    least one directory below the directory of a locked package (its tests,
    examples, benchmarks). The package is read from the path, which must start
    with `P/node_modules/`: the first component after the last `node_modules/`
    (the first two when it starts with `@`) must be the name of a package of
    that lock, in any version;
- `pin`: the location is under a pin's `path`;
- `base-layer`: the location's layer (`syft:location:<n>:layerID` with the
  same `<n>`) is in `--base-layers` (one `sha256:` diff ID per line: the layers
  of the digest-pinned base);
- `allow`: a `path` rule of `allow.tsv` contains the location. A `purl` or
  `purl-type` rule covers the component and so every location.

Paths are compared by whole components (`/opt/mesa` does not contain
`/opt/mesa-evil`), and a location belongs to the longest prefix that contains
it. A location that is not an absolute path, or has an empty, `.` or `..`
component, is explained by nothing but a `purl` or `purl-type` rule. So is a
component without any location.

The status is the mechanism that explains every location (the first of
`lock`, `pin`, `base-layer`, `allow` when several do); else `mixed`, with each
location's first mechanism in `detail`; else `unexplained`, with the first
unexplained location in `detail`.

Prints a short table per category and writes the full result to `--report`
(JSON: `forward` and `reverse` lists of `{purl, prefix, status, detail}` and a
`summary` of counts). Exit 0 = pass, 1 = check failed, 2 = bad input.

Name normalisation: pypi per PEP 503 (lowercase, runs of `-_.` to `-`); npm
names compared exactly; cran exactly; conda exactly (except as above). Versions
compared as strings after percent-decoding. A `pypi` component and a conda
lock component also have the same version when the two differ only in letter
case or in `_`, `-`, `.` after the release number (`2.9.0_post0` =
`2.9.0.post0`, `+cu126_1` = `+cu126.1`); nothing else is normalised.

### `referrers_index.py` and `attach_sbom.sh`

Harbor 2.9.0 stores OCI 1.1 referrers but its referrers API answers with the
wrong content type and `artifactType`, so `cosign` and `oras` fall back to the
tag `sha256-<hex of the subject digest>` and find nothing
(`docs/harbor-referrers.md`). After attaching, the release therefore writes
that fallback tag itself.

```
referrers_index.py --subject-digest sha256:... --manifest <digest>=<file> [--manifest ...] -o index.json
```

Builds the OCI image index for the fallback tag from the referrers' own
manifests (raw bytes as fetched): each descriptor gets `mediaType`, `digest`
(must equal the SHA-256 of the file), `size`, `artifactType` (the manifest's
`artifactType`, else its `config.mediaType`) and the manifest's `annotations`.
Refuses a manifest whose `subject.digest` is not the subject.

```
attach_sbom.sh <repo>@<digest> <image.cdx.json>
attach_sbom.sh --index-only <repo>@<digest>
```

Runs `cosign attest --type cyclonedx` (keyless in CI; `COSIGN_KEY` and
`COSIGN_SIGNING_CONFIG` for offline tests), then lists the subject's referrers
from the registry, fetches each manifest with `crane`, builds the index with
`referrers_index.py` and pushes it to the fallback tag with
`oras manifest push`. The referrers already there are fetched and checked
before anything is signed, and every referrer manifest is listed once in the
index. Every run signs: a second run adds a second attestation of the same
predicate. `release.py publish` therefore verifies first and only calls this
when no attestation of the SBOM can be found.

`--index-only` signs nothing: it rewrites the fallback tag from the referrers
the registry lists (and those an existing tag lists). It repairs a run that
died between `cosign attest` and the tag. Exit 0 when a cosign attestation
of a CycloneDX SBOM is among them, 3 when none is (including when there are
no referrers at all).

### `install-tools.sh` and `tools.lock`

`tools.lock`: tab separated `name<TAB>version<TAB>arch<TAB>url<TAB>sha256<TAB>member`
(`member` = file to extract from a tar.gz, or `-` for a bare binary).
`install-tools.sh [--dest DIR] [name ...]` downloads each tool for the host
arch, verifies the SHA-256 before anything is extracted or made executable,
and installs it into `DIR` (default `./.tools/bin`). A hash mismatch is fatal
and leaves nothing behind. Every run verifies what is installed against
tools.lock without the network: a bare binary by its own hash, an archive
member by the archive kept in `DIR/.archives/`. A tool that is missing or
differs is installed again.

### `relock-lib.sh`

Sourced by each repo's own `relock.sh` (`make relock`), which is a short list
of calls, one per lock:

| Function | Writes |
|---|---|
| `base_digest DOCKERFILE ARG [--dated TAG]` | the `ARG <ARG>=repo:tag@sha256:…` default, re-resolved to the tag's current index digest. `--dated latest` writes the newest `YYYY-MM-DD` tag that has the same digest as `latest` (Jupyter Docker Stacks) |
| `pip_lock FILE.in PYVER [uv args]` | `FILE.<arch>.txt`: `uv pip compile --generate-hashes`, wheels only, per arch |
| `base_pip_constraints IMAGE PYTHON [LOCK…]` | on stdout, the package set of a lower layer, for `pip_lock … -c FILE` in a higher one |
| `npm_lock DIR NODE_VERSION` | `DIR/package-lock.json` from `DIR/package.json`, with the Node version the image ships; adds the `libc` field npm 10 leaves out, so `npm ci` skips musl binaries |
| `conda_lock ENV.yml OUT_PREFIX BASE_IMAGE` | `OUT_PREFIX.<arch>.lock`: the environment solved by the base image's own mamba, as URL + sha256 lines. The CPU level (x86-64-v3) and kernel (4.18) are fixed so the result does not depend on the machine that runs it |

Needs `docker`, `uv` and `crane` on `PATH`. Running it twice in a row gives no
diff unless upstream published something in between.

## Tests

`python3 -m unittest discover -s tests` from the repo root; fixtures under
`tests/fixtures/` are small cuts of real lock files and real scanner output.
The tests need no Docker and no network (the installer test serves fixture
files from a local HTTP server and needs `curl`).

## Checked against a real image

The pipeline was run on the cli images built from locks
(`idss-mesa/cli`, branch `feat/locked-build`, 2026-11-12):

| Variant | Lock entries confirmed in the image | Scanner components | Unexplained |
|---|---|---|---|
| cpu, amd64 | 517 of 517 checkable (337 conda, 109 npm, 57 pip, 14 pins) | 1991 | 0 |
| gpu, amd64 | 586 of 586 checkable (337 conda, 109 npm, 123 pip, 17 pins) | 2130 | 0 |

Each step takes under 6 seconds; the syft scan before it takes about 2 minutes.
