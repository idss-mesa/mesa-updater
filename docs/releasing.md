# Releasing a version

A release is the set of images of one `VERSION` of one image repo, each with
a signed SBOM, plus a GitHub Release that lists them.

| Variant | Tag |
|---|---|
| CPU, amd64 | `vX.Y.Z` |
| sandbox | `vX.Y.Z-sandbox` |
| GPU | `vX.Y.Z-gpu` |
| GPU sandbox | `vX.Y.Z-gpu-sandbox` |
| CPU, arm64 (cli) | `vX.Y.Z-arm64` |

## Choosing the version

| Change | Raise |
|---|---|
| Updated packages or base image, security fixes, no change in what the image offers | patch: `2.0.0` → `2.0.1` |
| A tool or feature added, in a way existing users will not notice breaking | minor: `2.0.1` → `2.1.0` |
| Something users rely on removed or changed incompatibly | major: `2.1.0` → `3.0.0` |

## Cutting a release

1. Open a pull request that changes `VERSION` (alone, or together with the
   image change it releases).
2. Wait for the pull-request check to pass, get the review, merge.
3. The merge starts the `release` workflow in that repo. Watch it under
   **Actions → release**. Nothing else is needed.

A release can also be started by hand: **Actions → release → Run workflow**,
on `main`, with the tag prefix left empty. That is for a `VERSION` that is
on `main` but was not released, for example after a failed run was given up.

What happens, and in what order, is described in
[Workflows](workflows.md#release). A release of cli takes roughly half an
hour for the hosted part, plus the GPU build.

When the run is green:

- the tags above exist in the registry. The pipeline never moves or
  rebuilds them; the registry rule that stops anyone else from moving a
  `v*` tag is still being set up, so until it is confirmed the attestation,
  not the tag, is the proof
  ([GitHub Apps and access](github-apps-and-access.md#limits-to-know-about));
- each image has a signed SBOM attached ([Verifying an image](verifying-an-image.md));
- the repo has a GitHub Release `vX.Y.Z`, with a git tag on the released
  commit, one SBOM file per image, `release-manifest.json` and `SHA256SUMS`.

## Test runs

A test run goes through the same workflow with a **tag prefix** and leaves
the real tags alone.

**Actions → release → Run workflow**, then:

| Field | Value |
|---|---|
| Branch | `main`, or any branch |
| Tag prefix | `ci-test-<word>-`, for example `ci-test-a-` |
| Build the GPU variants | on `main`: your choice. On any other branch: **off** (the GPU builder only builds `main`) |

It writes `ci-test-<word>-vX.Y.Z…` tags and a **draft** GitHub Release, and
creates no git tag. The attestations are real, but their certificate names
the branch the run came from, so nothing from a branch can pass for `main`.

A prefix can be used once: the run refuses to start if its tags already
exist. Test tags, their attestations and the draft release are not cleaned
up automatically; a registry administrator removes them (the order matters,
see [SBOM attestations on Harbor 2.9.0](harbor-referrers.md#deleting)).

## When a release fails

Until the `publish` job starts, a failed run has published nothing users
see: only staging tags, and attestations of staged digests.

| What happened | What to do |
|---|---|
| A build, test or cross-check failed | Fix the cause with a new pull request. The version was not released, so `VERSION` can stay the same. The next merge to `main` does not start a release unless it changes `VERSION`; start it by hand |
| The GPU job timed out (the one GPU runner was busy) | **Re-run failed jobs** |
| The run failed inside `publish` (some tags written, or no GitHub Release) | **Re-run failed jobs**. It finishes the same release with the same images |
| The run was cancelled before `publish` started | Nothing was released. Start again when ready |
| `guard` says "partly published" | A previous run wrote some tags and did not finish. Go to *that* run and **Re-run failed jobs**. If that is no longer possible, release the next patch version instead |

Two things **not** to do with a partly published release:

- **Re-run all jobs**: it would build new images with other digests, and
  `guard` stops it;
- start a new run for the same version: the same, for the same reason.

A release tag is never moved or rebuilt. If a released image turns out to be
wrong, release the next patch version.

## Doing it by hand

Every step is a script in the image repo's `ci/`, so the build half of a
release can be reproduced on any machine with Docker:

```bash
ci/install-tools.sh                     # pinned syft, cosign, oras, crane, uv, grype into .tools/bin
ci/mesa-ci.sh check
VARIANT=cpu ci/mesa-ci.sh build         # also: test, push, sbom
BASE_REF=<image>@<cpu digest> VARIANT=sandbox ci/mesa-ci.sh build
python3 ci/release.py plan              # what the release of VERSION consists of
```

`make ci-check`, `make ci-build`, `make ci-test` and `make ci-sbom` wrap the
same commands. Publishing a real release by hand is not possible, by design:
the signature must come from the release workflow running on `main`.

The arguments of every command are in [`ci/README.md`](../ci/README.md).
