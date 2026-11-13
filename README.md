# mesa-updater

Shared CI for the MESA VICE images
([cli](https://github.com/idss-mesa/cli),
[jupyterlab](https://github.com/idss-mesa/jupyterlab),
[kasm](https://github.com/idss-mesa/kasm),
[rstudio](https://github.com/idss-mesa/rstudio),
[vscode](https://github.com/idss-mesa/vscode)): lock and CycloneDX SBOM
tooling now; the reusable release, rolling and update workflows and the DE
version sync are still to come.

| Path | What |
|---|---|
| [`ci/`](ci/README.md) | Lock helpers (`relock-lib.sh`), SBOM tools (`sbom_from_locks.py`, `sbom_probe.py`, `sbom_merge.py`, `sbom_crosscheck.py`), SBOM attachment for Harbor (`attach_sbom.sh`, `referrers_index.py`), pinned tool installer (`install-tools.sh`, `tools.lock`). Each image repo carries a copy |
| [`docs/harbor-referrers.md`](docs/harbor-referrers.md) | What Harbor 2.9.0 does with SBOM attestations, and the workaround |
| `tests/` | `python3 -m unittest discover -s tests` |
