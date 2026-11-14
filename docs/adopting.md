# Adding an image repo

What an image repo needs before it can use the shared pull-request check and
release. [idss-mesa/cli](https://github.com/idss-mesa/cli) is the worked
example; the pull requests that converted it are linked at the end.

The order below keeps every step small enough to review and leaves the
rolling tags working throughout.

## 1. Build from lock files

One pull request that changes how the image is built, not what is in it.

- [ ] From a checkout of this repo run `./sync.sh /path/to/image-repo`. It
      copies the shared scripts into the repo's `ci/`, among them
      `ci/relock-lib.sh` and `ci/install-tools.sh`.
- [ ] Pin the base image by digest: `ARG BASE_IMAGE=repo:tag@sha256:…`.
- [ ] For each way the Dockerfile installs software, add an intent file and
      a generated lock under `<context>/locks/` (and `gpu/locks/`), and make
      the Dockerfile install from the lock. The table in
      [Images, locks and SBOMs](images-and-locks.md#how-each-kind-of-input-is-pinned)
      lists the mechanisms.
- [ ] Give every single download a version `ARG` and a checksum `ARG` per
      architecture, and list them in `ci/pins.tsv` (format in
      [`ci/README.md`](../ci/README.md)).
- [ ] Write `relock.sh` as a short list of calls into `ci/relock-lib.sh`,
      one per lock, and add a `make relock` target. It needs Docker, `uv`
      and `crane` on `PATH`: `ci/install-tools.sh uv crane` puts pinned
      copies in `.tools/bin`. Run `PATH="$PWD/.tools/bin:$PATH" make relock`
      twice: the second run must change nothing.
- [ ] Add `sbom/locks.tsv` (which lock files make up which layer) and
      `sbom/allow.tsv` (what may be present without a lock entry, each rule
      with a reason).
- [ ] Switch off self-updating in the tools that offer it.

Check before merging: build the old and the new image and compare their
package lists. Nothing should disappear unintentionally.

## 2. Add the shared scripts and the pull-request check

- [ ] Run `./sync.sh /path/to/image-repo` again if this repo changed since
      step 1. It copies the shared files and `ci/SHARED.sha256` into the
      repo's `ci/`.
- [ ] Add `VERSION` (`2.0.0` for a repo that has never released).
- [ ] Add `mesa.env`:

  ```
  MESA_IMAGE=harbor.cyverse.org/vice/mesa-<app>
  MESA_CONTEXT=latest
  MESA_ARCHES="amd64"
  MESA_SANDBOX_PORT=<port the app listens on>
  MESA_SANDBOX_PATH=/
  MESA_SANDBOX_DOCKER_ARGS=
  ```

- [ ] Add `ci/test-cpu.sh IMAGE`: a smoke test of the CPU image that exits
      non-zero on failure (the tools answer, the application starts and
      serves on its port). `gpu/test-gpu.sh` and `sandbox/test-sandbox.sh`
      already exist in every image repo.
- [ ] Add `.github/workflows/pr.yml`:

  ```yaml
  name: pr
  on:
    pull_request:
  permissions: {}
  concurrency:
    group: pr-${{ github.event.pull_request.number }}
    cancel-in-progress: true
  jobs:
    pr:
      permissions:
        contents: read
      uses: idss-mesa/mesa-updater/.github/workflows/mesa-pr.yml@<commit of this repo>
      # with:
      #   arches: '["amd64"]'      # for a repo that does not build arm64
  ```

- [ ] Add `out/` and `.tools/` to `.gitignore`.
- [ ] Run it by hand first: `ci/install-tools.sh syft crane`, then
      `ci/mesa-ci.sh check` and `VARIANT=cpu ci/mesa-ci.sh build`, `test`,
      `sbom`; the same with `VARIANT=sandbox`, and on a GPU machine with
      `VARIANT=gpu` and `VARIANT=gpu-sandbox`.

The cross-check will name every lock entry it cannot find and every
component it cannot explain. Fix the locks or add an `allow.tsv` rule with a
reason until the forward check passes and the unexplained list is empty.

## 3. Add the release workflow

- [ ] Add `.github/workflows/release.yml`, copied from
      [cli's](https://github.com/idss-mesa/cli/blob/main/.github/workflows/release.yml)
      with the same pinned commit as `pr.yml`.
- [ ] An organisation owner prepares the repo
      ([GitHub Apps and access](github-apps-and-access.md)): the ruleset on
      `main`, the `gpu-dispatch` environment limited to `main` with the
      dispatch key and App ID, and the registry credentials.
- [ ] Do a [test run](releasing.md#test-runs) from a branch without GPU,
      then one on `main` with GPU.
- [ ] Release. `VERSION` has been on `main` since step 2, so start the first
      release by hand: **Actions → release → Run workflow** on `main`, tag
      prefix empty ([Releasing a version](releasing.md#cutting-a-release)).
      Later releases start when a pull request that changes `VERSION` is
      merged.

## 4. Afterwards

- [ ] Remove the workflows the shared ones replace, once the shared rolling
      workflow exists.
- [ ] Add the new version to the Discovery Environment and the MESA Portal
      (planned).

## Keeping up with this repo

When a shared script or workflow changes here, each image repo takes the
change with one pull request: run `./sync.sh` again and move the commit that
`pr.yml` and `release.yml` are pinned to. Both must be the same commit, and
it must be on this repo's `main`.

## The worked example

| Step | Pull request |
|---|---|
| Build from pins and lock files | [cli #9](https://github.com/idss-mesa/cli/pull/9) |
| Shared scripts and pull-request check | [cli #10](https://github.com/idss-mesa/cli/pull/10), with [mesa-updater #1](https://github.com/idss-mesa/mesa-updater/pull/1) and [#2](https://github.com/idss-mesa/mesa-updater/pull/2) |
| Release workflow | [cli #11](https://github.com/idss-mesa/cli/pull/11), with [mesa-updater #3](https://github.com/idss-mesa/mesa-updater/pull/3) |
