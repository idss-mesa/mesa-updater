# mesa-updater

Shared CI for the MESA VICE images
([cli](https://github.com/idss-mesa/cli),
[jupyterlab](https://github.com/idss-mesa/jupyterlab),
[kasm](https://github.com/idss-mesa/kasm),
[rstudio](https://github.com/idss-mesa/rstudio),
[vscode](https://github.com/idss-mesa/vscode)), published at
`harbor.cyverse.org/vice/mesa-<app>`.

It holds the reusable GitHub Actions workflows that check pull requests and
cut releases, and the scripts those workflows run: lock-file helpers, SBOM
generation and cross-checking, signing, and the release logic. An image
repo calls the workflows pinned by commit and carries a copy of `ci/`. Today
that is cli; the other four follow as they are converted
([status](docs/README.md#where-things-stand)).

**Start with [docs/](docs/README.md)**: how the images are built, how a
release works, how the GPU builds are isolated, which GitHub Apps and
secrets are involved, and how to verify an image.

| Path | What |
|---|---|
| [`docs/`](docs/README.md) | The documentation |
| [`.github/workflows/mesa-pr.yml`](.github/workflows/mesa-pr.yml) | Reusable pull-request check: build, test and SBOM cross-check, no secrets |
| [`.github/workflows/mesa-release.yml`](.github/workflows/mesa-release.yml) | Reusable release: staged builds, attested SBOMs, tags last |
| [`ci/`](ci/README.md) | The scripts, with a reference for each: `mesa-ci.sh` (what the workflows run), `release.py`, `gpu_request.sh`, the SBOM tools, `attach_sbom.sh`, `relock-lib.sh`, `install-tools.sh` and `tools.lock` |
| `sync.sh` | Copies `ci/` into an image repo and maintains `ci/SHARED.sha256` |
| `tests/` | `python3 -m unittest discover -s tests` (no network, no Docker) |

Still to come: the weekly rolling workflow, the daily update check, and the
sync of versions into the Discovery Environment
([status](docs/README.md#where-things-stand)).
