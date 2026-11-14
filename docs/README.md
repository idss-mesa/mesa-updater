# How the MESA images are built

MESA publishes five container images for the CyVerse Discovery Environment
(VICE apps). This documentation explains what is built, from what, by which
automation, and how anyone can check that an image is what it claims to be.

| Read | To learn |
|---|---|
| [Overview](overview.md) | The images, their variants and tags, the repositories involved, and the rules the automation follows |
| [Images, locks and SBOMs](images-and-locks.md) | What goes into an image, how every input is pinned, and how the software bill of materials is made and checked |
| [Workflows](workflows.md) | Every GitHub Actions workflow: what starts it, where it runs, what it publishes |
| [Releasing a version](releasing.md) | How a point release such as `v2.0.0` is cut, tested beforehand, and recovered if it fails |
| [GPU builds](gpu-builds.md) | Why GPU images are built on a separate, private builder and what that builder accepts |
| [GitHub Apps and access](github-apps-and-access.md) | The three GitHub Apps, the secrets, the branch rules, and who can do what |
| [Verifying an image](verifying-an-image.md) | For users: check an image's signature and read its SBOM |
| [Adding an image repo](adopting.md) | What an image repo needs before it can use the shared workflows |
| [`ci/README.md`](../ci/README.md) | Reference for every shared script: arguments, file formats, exit codes |
| [SBOM attestations on Harbor 2.9.0](harbor-referrers.md) | A registry quirk and the workaround the release uses |

## Where things stand

Last updated 2026-11-14.

| Piece | State |
|---|---|
| Builds from lock files | **cli**: done. jupyterlab, kasm, rstudio, vscode: not yet. Their Dockerfiles pin some downloads by version and checksum, but the base image is a floating tag and several installs (pip, conda and R packages, editor extensions) take the newest version |
| Pull-request check (build, test, SBOM cross-check) | **cli**: running on every pull request. Others: Dockerfile lint only |
| Release workflow | In cli. Tested end to end for the CPU, arm64 and sandbox images. The GPU part has not run yet: the GPU runner is installed but not switched on |
| First release | None yet. `mesa-cli` `v2.0.0` is the first; it needs the GPU runner |
| Weekly rolling builds | `latest` (and `arm64` for cli) rebuild every Sunday. `gpu`, `sandbox` and `gpu-sandbox` are rebuilt by hand on the GPU server. One shared workflow for all five tags is planned |
| Daily update check | Planned: a daily job that opens one pull request per repo when a pinned input has a new version |
| Versions in the Discovery Environment and the MESA Portal | Planned, after each repo's first release |

"Planned" items are described where they belong, and marked as planned, so
that these pages stay correct as they are built.
