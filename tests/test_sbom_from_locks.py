"""Tests for ci/sbom_from_locks.py against tests/fixtures/locks (cuts of real lock files)."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "ci", "sbom_from_locks.py")
FIXTURE = os.path.join(HERE, "fixtures", "locks")
sys.path.insert(0, os.path.dirname(TOOL))
import sbom_from_locks  # noqa: E402

BASE_DIGEST = "29076b0b96c954a16b813cc5c4230f248711ef1d7528cb1208b82397e86a8b52"
SHA = "a" * 64


def props(comp):
    return {p["name"]: p["value"] for p in comp["properties"]}


def hashes(comp):
    return [(h["alg"], h["content"]) for h in comp.get("hashes", [])]


def kinds(doc):
    counts = {}
    for comp in doc["components"]:
        kind = props(comp)["mesa:lock:kind"]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sbom-from-locks-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.out = os.path.join(self.tmp, "locks.cdx.json")

    def run_tool(self, root=FIXTURE, variant="cpu", arch="amd64"):
        """Run main() in-process; return (exit code, stderr)."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = sbom_from_locks.main(["--repo-root", root, "--variant", variant, "--arch", arch,
                                         "-o", self.out])
        return code, err.getvalue()

    def sbom(self, root=FIXTURE, variant="cpu", arch="amd64"):
        code, err = self.run_tool(root, variant, arch)
        self.assertEqual(code, 0, err)
        with open(self.out, encoding="utf-8") as f:
            return json.load(f)

    def by_ref(self, *args, **kwargs):
        return {c["bom-ref"]: c for c in self.sbom(*args, **kwargs)["components"]}

    def repo(self, files):
        """A throwaway repo: {relative path: text}."""
        root = os.path.join(self.tmp, "repo")
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        return root

    def fixture_copy(self):
        return shutil.copytree(FIXTURE, os.path.join(self.tmp, "repo"))


class FixtureRepo(Case):
    def test_counts_per_variant_and_arch(self):
        want = {
            ("cpu", "amd64"): {"base": 1, "pip": 11, "npm": 11, "conda": 26, "pins": 7, "cran": 8, "vsix": 4},
            ("cpu", "arm64"): {"base": 1, "pip": 11, "npm": 11, "conda": 6, "pins": 7, "cran": 8, "vsix": 4},
            ("gpu", "amd64"): {"base": 1, "pip": 14, "npm": 11, "conda": 26, "pins": 8, "cran": 8, "vsix": 4},
            # the GPU pip row is amd64 only; the ollama pin has no arch
            ("gpu", "arm64"): {"base": 1, "pip": 11, "npm": 11, "conda": 6, "pins": 8, "cran": 8, "vsix": 4},
        }
        for (variant, arch), counts in want.items():
            with self.subTest(variant=variant, arch=arch):
                self.assertEqual(kinds(self.sbom(variant=variant, arch=arch)), counts)

    def test_sandbox_layer_adds_nothing_here(self):
        self.assertEqual(self.sbom(variant="sandbox"), self.sbom(variant="cpu"))
        self.assertEqual(self.sbom(variant="gpu-sandbox"), self.sbom(variant="gpu"))

    def test_document_shape(self):
        doc = self.sbom(variant="gpu")
        self.assertEqual((doc["bomFormat"], doc["specVersion"], doc["version"]), ("CycloneDX", "1.6", 1))
        self.assertNotIn("serialNumber", doc)
        self.assertNotIn("metadata", doc)
        for comp in doc["components"]:
            for field in ("type", "name", "version", "purl", "bom-ref"):
                self.assertTrue(comp[field], (field, comp))
            p = props(comp)
            self.assertEqual(list(p)[:3], ["mesa:lock:kind", "mesa:lock:layer", "mesa:lock:file"])
            self.assertTrue(os.path.isfile(os.path.join(FIXTURE, p["mesa:lock:file"])))
            prefix = p.get("mesa:lock:prefix")
            self.assertEqual(comp["bom-ref"], comp["purl"] + ("#" + prefix if prefix else ""))
            self.assertEqual(prefix is None, p["mesa:lock:kind"] in ("base", "pins"))
            for alg, content in hashes(comp):
                self.assertEqual(len(content), {"MD5": 32, "SHA-256": 64, "SHA-512": 128}[alg])
                self.assertEqual(content, content.lower())

    def test_sorted_and_bom_refs_unique(self):
        for variant, arch in (("cpu", "arm64"), ("gpu-sandbox", "amd64")):
            comps = self.sbom(variant=variant, arch=arch)["components"]
            order = [(c["purl"], props(c).get("mesa:lock:prefix", "")) for c in comps]
            self.assertEqual(order, sorted(order))
            refs = [c["bom-ref"] for c in comps]
            self.assertEqual(len(refs), len(set(refs)))

    def test_cli_is_deterministic(self):
        outputs = []
        for seed in ("1", "2"):  # separate processes with different hash seeds
            out = os.path.join(self.tmp, f"run{seed}.json")
            proc = subprocess.run(
                [sys.executable, TOOL, "--repo-root", FIXTURE, "--variant", "gpu-sandbox",
                 "--arch", "amd64", "-o", out],
                env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("72 components", proc.stderr)
            with open(out, "rb") as f:
                outputs.append(f.read())
        self.assertEqual(outputs[0], outputs[1])
        self.assertTrue(outputs[0].endswith(b"}\n"))
        self.assertNotIn(b"timestamp", outputs[0])

    def test_base_image(self):
        ref = (f"pkg:oci/minimal-notebook@sha256%3A{BASE_DIGEST}"
               "?repository_url=quay.io/jupyter/minimal-notebook&tag=2026-11-09")
        comp = self.by_ref()[ref]
        self.assertEqual((comp["type"], comp["name"], comp["version"]),
                         ("container", "quay.io/jupyter/minimal-notebook", "sha256:" + BASE_DIGEST))
        self.assertEqual(props(comp), {"mesa:lock:kind": "base", "mesa:lock:layer": "cpu",
                                       "mesa:lock:file": "bash/Dockerfile"})

    def test_base_row_skips_an_unpinned_image_arg(self):
        # As in the real gpu/Dockerfile: BASE_IMAGE is the CPU image of the same release (no
        # digest), CUDA_PROBE_IMAGE is a digest-pinned build stage.
        root = self.fixture_copy()
        with open(os.path.join(root, "sbom", "locks.tsv"), "a", encoding="utf-8") as f:
            f.write("base\tgpu\t*\tgpu/Dockerfile\t-\n")
        code, err = self.run_tool(root)
        self.assertEqual((code, err.count("\n")), (0, 1), err)  # the row is not part of the cpu variant
        probe_image = ("pkg:oci/ubuntu@sha256%3A2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5"
                       "?repository_url=ubuntu&tag=24.04")
        for variant, arch in (("gpu", "amd64"), ("gpu-sandbox", "arm64")):
            with self.subTest(variant=variant):
                code, err = self.run_tool(root, variant=variant, arch=arch)
                self.assertEqual(code, 0, err)
                self.assertIn("sbom_from_locks: gpu/Dockerfile:4: note: ARG BASE_IMAGE="
                              "harbor.cyverse.org/vice/mesa-cli:latest has no digest and is not recorded\n", err)
                with open(self.out, encoding="utf-8") as f:
                    base = {c["bom-ref"]: props(c) for c in json.load(f)["components"]
                            if props(c)["mesa:lock:kind"] == "base"}
                self.assertEqual({ref: p["mesa:lock:layer"] for ref, p in base.items()}, {
                    f"pkg:oci/minimal-notebook@sha256%3A{BASE_DIGEST}"
                    "?repository_url=quay.io/jupyter/minimal-notebook&tag=2026-11-09": "cpu",
                    probe_image: "gpu"})
                self.assertEqual(base[probe_image]["mesa:lock:file"], "gpu/Dockerfile")

    def test_pip_entries(self):
        comps = self.by_ref()
        comp = comps["pkg:pypi/python-irodsclient@3.3.0#/opt/mesa"]
        self.assertEqual((comp["type"], comp["name"], comp["version"]),
                         ("library", "python-irodsclient", "3.3.0"))
        self.assertEqual(len(hashes(comp)), 2)
        self.assertNotIn("externalReferences", comp)
        self.assertEqual(props(comp), {
            "mesa:lock:kind": "pip", "mesa:lock:layer": "cpu",
            "mesa:lock:file": "sbom/pip/mesa-venv.amd64.txt", "mesa:lock:prefix": "/opt/mesa"})
        # 'name @ url' entry: version from the wheel file name, URL kept
        comp = comps["pkg:pypi/mesa-ducklake@0.2.0#/opt/mesa"]
        self.assertEqual(comp["version"], "0.2.0")
        self.assertEqual(hashes(comp), [
            ("SHA-256", "7d5ca86d820cbd18635075372f967a9496f9b671fb1189897bafd71647042788")])
        self.assertEqual(comp["externalReferences"], [{
            "type": "distribution",
            "url": "https://github.com/idss-mesa/mesa-ducklake/releases/download/v0.2.0/"
                   "mesa_ducklake-0.2.0-py3-none-any.whl"}])
        # the same package in two prefixes stays two components
        self.assertIn("pkg:pypi/certifi@2026.10.23#/opt/mesa", comps)
        self.assertIn("pkg:pypi/certifi@2026.10.23#/opt/conda", comps)

    def test_pip_arch_rows(self):
        self.assertEqual(props(self.by_ref(arch="arm64")["pkg:pypi/pyjwt@2.15.1#/opt/mesa"])
                         ["mesa:lock:file"], "sbom/pip/mesa-venv.arm64.txt")

    def test_gpu_layer_overrides_cpu_package_in_same_prefix(self):
        cpu, gpu = self.by_ref(variant="cpu"), self.by_ref(variant="gpu")
        self.assertEqual(props(cpu["pkg:pypi/urllib3@2.8.0#/opt/conda"])["mesa:lock:layer"], "cpu")
        self.assertNotIn("pkg:pypi/urllib3@2.8.0#/opt/conda", gpu)
        self.assertEqual(props(gpu["pkg:pypi/urllib3@2.7.0#/opt/conda"]), {
            "mesa:lock:kind": "pip", "mesa:lock:layer": "gpu",
            "mesa:lock:file": "sbom/pip/gpu-conda-base.amd64.txt", "mesa:lock:prefix": "/opt/conda"})
        # other prefixes and packages the GPU lock does not name are untouched
        self.assertIn("pkg:pypi/urllib3@2.8.0#/opt/mesa", gpu)
        self.assertEqual(props(gpu["pkg:pypi/certifi@2026.10.23#/opt/conda"])["mesa:lock:layer"], "cpu")
        self.assertIn("pkg:conda/urllib3@2.5.0?build=pyhd8ed1ab_0&channel=conda-forge&subdir=noarch"
                      "&type=conda#/opt/conda/envs/geospatial", gpu)
        # no GPU row for arm64, so the CPU package stays
        self.assertIn("pkg:pypi/urllib3@2.8.0#/opt/conda", self.by_ref(variant="gpu", arch="arm64"))

    def test_pip_local_version_is_percent_encoded(self):
        comp = self.by_ref(variant="gpu")["pkg:pypi/torch@2.14.0%2Bcu126#/opt/conda"]
        self.assertEqual((comp["name"], comp["version"]), ("torch", "2.14.0+cu126"))
        self.assertEqual(len(hashes(comp)), 24)
        self.assertEqual({alg for alg, _ in hashes(comp)}, {"SHA-256"})

    def test_npm_platform_filter_and_names(self):
        prefix = "#/opt/mesa-agent-clis"
        common = {"pkg:npm/%40anthropic-ai/claude-code@2.1.310", "pkg:npm/%40openai/codex@0.164.0",
                  "pkg:npm/%40the-next-ai/ai-gateway@1.0.21", "pkg:npm/ajv@8.20.0",
                  # nested node_modules: both versions, named by the last path part
                  "pkg:npm/fast-uri@3.1.9", "pkg:npm/fast-uri@4.2.3",
                  "pkg:npm/undici@6.29.1", "pkg:npm/undici@7.30.2"}
        per_arch = {
            # the lock has no libc field, so the musl build passes the os/cpu filter;
            # codex-linux-* is an alias: the lock's 'name' is the real package
            "amd64": {"pkg:npm/%40anthropic-ai/claude-code-linux-x64@2.1.310",
                      "pkg:npm/%40anthropic-ai/claude-code-linux-x64-musl@2.1.310",
                      "pkg:npm/%40openai/codex@0.164.0-linux-x64"},
            "arm64": {"pkg:npm/%40anthropic-ai/claude-code-linux-arm64@2.1.310",
                      "pkg:npm/%40anthropic-ai/claude-code-linux-arm64-musl@2.1.310",
                      "pkg:npm/%40openai/codex@0.164.0-linux-arm64"},
        }
        for arch, extra in per_arch.items():
            with self.subTest(arch=arch):
                comps = self.by_ref(arch=arch)
                npm = {r for r, c in comps.items() if props(c)["mesa:lock:kind"] == "npm"}
                self.assertEqual(npm, {p + prefix for p in common | extra})
                self.assertFalse([c for c in comps.values() if c["name"] == "mesa-agent-clis"])
        comp = self.by_ref()["pkg:npm/undici@7.30.2" + prefix]
        self.assertEqual(hashes(comp), [(
            "SHA-512", "98bc8f4271f053168cfeb89d7a82bff8a2fc0da0092d197868109f997e38e1a0"
                       "922e721aa26a8f2ed3517b68dd09872c939c19cd7ac32100bc65e60d44063220")])
        self.assertEqual(comp["externalReferences"][0]["url"],
                         "https://registry.npmjs.org/undici/-/undici-7.30.2.tgz")
        comp = self.by_ref()["pkg:npm/%40openai/codex@0.164.0-linux-x64" + prefix]
        self.assertEqual((comp["name"], comp["version"]), ("@openai/codex", "0.164.0-linux-x64"))

    def test_conda_explicit_lock(self):
        comps = self.by_ref()
        tail = "#/opt/conda/envs/geospatial"

        def conda(name, version, build, subdir, ctype="conda"):
            return comps[f"pkg:conda/{name}@{version}?build={build}&channel=conda-forge"
                         f"&subdir={subdir}&type={ctype}{tail}"]

        comp = conda("python", "3.10.22", "h267e890_0_cpython", "linux-64")
        self.assertEqual(hashes(comp), [
            ("SHA-256", "819fa140a71ab005c448bf164eb182f91610b50f0bffca5b0b94cb6773c5e2f4")])
        self.assertEqual(comp["externalReferences"][0]["url"], "https://conda.anaconda.org/conda-forge/"
                         "linux-64/python-3.10.22-h267e890_0_cpython.conda")
        # dashes and underscores in names and builds, .tar.bz2, and an md5-only line
        conda("_x86_64-microarch-level", "4", "3_x86_64_v4", "noarch")
        conda("python-pdal", "3.5.3", "np2py310hb764e7b_2", "linux-64")
        conda("fonts-conda-ecosystem", "1", "0", "noarch", "tar.bz2")
        conda("font-ttf-dejavu-sans-mono", "2.37", "hab24e00_0", "noarch", "tar.bz2")
        self.assertEqual(hashes(conda("tzdata", "2026e", "h5d301ff_0", "noarch")),
                         [("MD5", "abccc3810d2b97e570dee487f2b46e38")])
        arm = [c for c in self.sbom(arch="arm64")["components"] if c["purl"].startswith("pkg:conda/numpy@")]
        self.assertEqual([c["purl"] for c in arm], [
            "pkg:conda/numpy@2.2.6?build=py310h6e5608f_0&channel=conda-forge&subdir=linux-aarch64&type=conda"])

    def test_pins(self):
        amd, arm = self.by_ref(), self.by_ref(arch="arm64")
        tini = amd["pkg:github/krallin/tini@v0.19.0"]  # the template writes the 'v'
        self.assertEqual((tini["type"], tini["name"], tini["version"]), ("application", "tini", "v0.19.0"))
        self.assertEqual(hashes(tini), [
            ("SHA-256", "93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c")])
        self.assertEqual(hashes(arm["pkg:github/krallin/tini@v0.19.0"]), [
            ("SHA-256", "07952557df20bfd2a95f9bef198b445e006171969499a1d361bd9e6f8e5e0e81")])
        # the URL template is not an IRI: a property, recorded as written, and no reference
        self.assertFalse([c["name"] for c in amd.values()
                          if props(c)["mesa:lock:kind"] == "pins" and "externalReferences" in c])
        self.assertEqual(props(tini), {
            "mesa:lock:kind": "pins", "mesa:lock:layer": "cpu", "mesa:lock:file": "ci/pins.tsv",
            "mesa:lock:path": "/usr/bin/tini", "mesa:lock:probe": "tini --version",
            "mesa:lock:url": "https://github.com/krallin/tini/releases/download/v{version}/tini-{arch}"})
        # ARG GOCMD_VERSION=v0.12.5 and a template without 'v'
        self.assertEqual(amd["pkg:generic/gocmd@0.12.5"]["version"], "0.12.5")
        self.assertEqual(hashes(amd["pkg:github/tsl0922/ttyd@1.7.7"]), [
            ("SHA-256", "8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55")])
        goose = amd["pkg:github/block/goose@v1.56.0"]  # '-' for hashes, url, path and probe
        self.assertEqual(sorted(goose), ["bom-ref", "name", "properties", "purl", "type", "version"])
        self.assertEqual(len(props(goose)), 3)
        claude = amd["pkg:npm/%40anthropic-ai/claude-code@2.1.310"]
        self.assertEqual(props(claude)["mesa:lock:path"],
                         "/home/jovyan/.npm-global/lib/node_modules/@anthropic-ai/claude-code")
        self.assertFalse({"mesa:lock:probe", "mesa:lock:url"} & set(props(claude)))

    def test_pin_layer_comes_from_pins_tsv(self):
        ref = "pkg:github/ollama/ollama@v0.40.11"
        self.assertNotIn(ref, self.by_ref(variant="cpu"))
        self.assertNotIn(ref, self.by_ref(variant="sandbox"))
        ollama = self.by_ref(variant="gpu-sandbox")[ref]
        self.assertEqual(props(ollama)["mesa:lock:layer"], "gpu")
        self.assertEqual(hashes(ollama), [
            ("SHA-256", "7bedab90dd122661be78798e9f0edf37fccf0cccf2699d2c58ea1a3afdc04b6d")])
        self.assertNotIn("hashes", self.by_ref(variant="gpu", arch="arm64")[ref])  # amd64=... only

    def test_cran_and_vsix(self):
        comps = self.by_ref()
        comp = comps["pkg:cran/data.table@1.18.6.1#/usr/local/lib/R/site-library"]
        self.assertEqual((comp["name"], comp["version"]), ("data.table", "1.18.6.1"))
        self.assertNotIn("hashes", comp)
        self.assertIn("pkg:cran/sf@1.1-3#/usr/local/lib/R/site-library", comps)
        comp = comps["pkg:generic/ms-python.python@2026.4.0?repository_url=open-vsx.org"
                     "#/config/.local/share/code-server/extensions"]
        self.assertEqual((comp["name"], comp["version"]), ("ms-python.python", "2026.4.0"))
        self.assertEqual(hashes(comp), [
            ("SHA-256", "232aeafb01f069824fdd92d3e628c1c442bbcfa1d3cc945ff97076340bb2b4a6")])


class EdgeCases(Case):
    def test_pep503_names_and_override_across_spellings(self):
        root = self.repo({
            "sbom/locks.tsv": "pip\tcpu\t*\tcpu.txt\t/opt/venv/\npip\tgpu\t*\tgpu.txt\t/opt/venv\n",
            "cpu.txt": "Typing_Extensions==4.16.0\nruamel.yaml==0.18.6\nFoo__Bar.baz==1.0\n",
            "gpu.txt": "foo-bar-baz==2.0\n",
        })
        self.assertEqual(sorted(self.by_ref(root)), [
            "pkg:pypi/foo-bar-baz@1.0#/opt/venv", "pkg:pypi/ruamel-yaml@0.18.6#/opt/venv",
            "pkg:pypi/typing-extensions@4.16.0#/opt/venv"])
        self.assertEqual(sorted(self.by_ref(root, variant="gpu")), [
            "pkg:pypi/foo-bar-baz@2.0#/opt/venv", "pkg:pypi/ruamel-yaml@0.18.6#/opt/venv",
            "pkg:pypi/typing-extensions@4.16.0#/opt/venv"])

    def test_pip_syntax_variants(self):
        root = self.repo({
            "sbom/locks.tsv": "pip\tcpu\t*\treq.txt\t/opt/venv\n",
            "req.txt": (
                "# This file was autogenerated by uv\n"
                "--index-url https://pypi.org/simple\n"
                "--extra-index-url https://download.pytorch.org/whl/cu126\n"
                f"uvicorn[standard]==0.54.0 ; python_version >= '3.10' --hash=sha256:{SHA} --hash=sha256:{'b' * 64}\n"
                "    # via mcp\n"
                "epoch==1!2.0\n"
                "torch @ https://download.pytorch.org/whl/cu126/torch-2.14.0%2Bcu126-cp313-cp313-"
                f"manylinux_2_28_x86_64.whl#sha256={SHA}\n"
                "sdist @ https://example.org/dl/sdist-1.2.3.tar.gz \\\n"
                f"    --hash=sha256:{SHA}\n"
                "nohash==3.0\n"),
        })
        comps = self.by_ref(root)
        self.assertEqual(sorted(comps), [
            "pkg:pypi/epoch@1%212.0#/opt/venv", "pkg:pypi/nohash@3.0#/opt/venv",
            "pkg:pypi/sdist@1.2.3#/opt/venv", "pkg:pypi/torch@2.14.0%2Bcu126#/opt/venv",
            "pkg:pypi/uvicorn@0.54.0#/opt/venv"])
        self.assertEqual(hashes(comps["pkg:pypi/uvicorn@0.54.0#/opt/venv"]),
                         [("SHA-256", SHA), ("SHA-256", "b" * 64)])
        self.assertEqual(comps["pkg:pypi/torch@2.14.0%2Bcu126#/opt/venv"]["version"], "2.14.0+cu126")
        self.assertEqual(hashes(comps["pkg:pypi/sdist@1.2.3#/opt/venv"]), [("SHA-256", SHA)])
        self.assertNotIn("hashes", comps["pkg:pypi/nohash@3.0#/opt/venv"])

    def npm_fixture(self, edit):
        root = self.fixture_copy()
        path = os.path.join(root, "sbom", "npm", "package-lock.json")
        with open(path, encoding="utf-8") as f:
            lock = json.load(f)
        edit(lock["packages"])
        with open(path, "w", encoding="utf-8") as f:
            json.dump(lock, f, indent=2)
        return {r: c for r, c in self.by_ref(root).items() if props(c)["mesa:lock:kind"] == "npm"}

    def test_npm_link_workspace_and_missing_integrity(self):
        def edit(packages):
            packages["node_modules/linked"] = {"resolved": "packages/linked", "link": True}
            packages["packages/linked"] = {"name": "linked", "version": "9.9.9"}
            del packages["node_modules/ajv"]["integrity"]
            packages["node_modules/@scope/deep/node_modules/@other/leaf"] = {"version": "1.0.0+build.5"}

        npm = self.npm_fixture(edit)
        self.assertEqual(len(npm), 12)
        self.assertFalse([r for r in npm if "linked" in r])
        self.assertNotIn("hashes", npm["pkg:npm/ajv@8.20.0#/opt/mesa-agent-clis"])
        leaf = npm["pkg:npm/%40other/leaf@1.0.0%2Bbuild.5#/opt/mesa-agent-clis"]
        self.assertEqual((leaf["name"], leaf["version"]), ("@other/leaf", "1.0.0+build.5"))
        self.assertNotIn("externalReferences", leaf)

    def test_npm_libc_and_negated_platforms(self):
        def edit(packages):
            packages["node_modules/@anthropic-ai/claude-code-linux-x64-musl"]["libc"] = ["musl"]
            packages["node_modules/@anthropic-ai/claude-code-linux-x64"]["libc"] = ["glibc"]
            packages["node_modules/not-windows"] = {"version": "1.0.0", "os": ["!win32"]}
            packages["node_modules/not-linux"] = {"version": "1.0.0", "os": ["!linux"]}
            packages["node_modules/not-x64"] = {"version": "1.0.0", "cpu": ["!x64", "!ia32"]}

        npm = self.npm_fixture(edit)
        names = {c["name"] for c in npm.values()}
        self.assertIn("@anthropic-ai/claude-code-linux-x64", names)
        self.assertNotIn("@anthropic-ai/claude-code-linux-x64-musl", names)
        self.assertIn("not-windows", names)
        self.assertFalse(names & {"not-linux", "not-x64"})

    def test_npm_same_package_at_two_paths_is_one_component(self):
        def edit(packages):
            packages["node_modules/ajv/node_modules/undici"] = dict(packages["node_modules/undici"])

        self.assertEqual(len(self.npm_fixture(edit)), 11)

    def test_later_row_wins_within_a_layer(self):
        root = self.repo({
            "sbom/locks.tsv": "cran\tcpu\t*\ta.tsv\t/r\ncran\tcpu\t*\tb.tsv\t/r\n",
            "a.tsv": "sf\t1.1-3\nterra\t1.9-50\n", "b.tsv": "# newer sf\nsf\t1.2-0\n",
        })
        comps = self.by_ref(root)
        self.assertEqual(sorted(comps), ["pkg:cran/sf@1.2-0#/r", "pkg:cran/terra@1.9-50#/r"])
        self.assertEqual(props(comps["pkg:cran/sf@1.2-0#/r"])["mesa:lock:file"], "b.tsv")

    def test_pins_file_listed_for_two_layers_gives_no_duplicates(self):
        root = self.fixture_copy()
        with open(os.path.join(root, "sbom", "locks.tsv"), "a", encoding="utf-8") as f:
            f.write("pins\tgpu\t*\tci/pins.tsv\t-\n")
        self.assertEqual(self.sbom(root, variant="gpu"), self.sbom(variant="gpu"))

    def test_base_image_forms(self):
        root = self.repo({
            "sbom/locks.tsv": "base\tcpu\t*\tDockerfile\t-\n",
            "Dockerfile": (f'ARG BASE_IMAGE="localhost:5000/Team/Img@sha256:{SHA}"\n'
                           f"ARG BUILDER_IMAGE=golang:1.27@sha256:{'b' * 64}\n"
                           "ARG BASE_IMAGE\nARG OTHER=ubuntu:24.04\nFROM ${BASE_IMAGE}\n"),
        })
        self.assertEqual(sorted(self.by_ref(root)), [
            f"pkg:oci/golang@sha256%3A{'b' * 64}?repository_url=golang&tag=1.27",
            f"pkg:oci/img@sha256%3A{SHA}?repository_url=localhost:5000/Team/Img"])

    def test_base_row_without_a_pinned_image_gives_no_component(self):
        note = "sbom_from_locks: sandbox/Dockerfile:%d: note: %s\n"
        unpinned = "ARG BASE_IMAGE=harbor.cyverse.org/vice/mesa-cli:latest"
        cases = {
            # the real gpu and sandbox layers: built on the image of the same release
            "only an unpinned image": (f"# c\n{unpinned}\nFROM ${{BASE_IMAGE}}\nARG BASE_IMAGE\n", [],
                                       [note % (2, unpinned + " has no digest and is not recorded")]),
            "several unpinned images": (f"{unpinned}\nARG BUILDER_IMAGE=golang:1.27\n", [], [
                note % (1, unpinned + " has no digest and is not recorded"),
                note % (2, "ARG BUILDER_IMAGE=golang:1.27 has no digest and is not recorded")]),
            "a pinned and an unpinned image": (
                f"{unpinned}\nARG PROBE_IMAGE=ubuntu:24.04@sha256:{SHA}\n",
                [f"pkg:oci/ubuntu@sha256%3A{SHA}?repository_url=ubuntu&tag=24.04"],
                [note % (1, unpinned + " has no digest and is not recorded")]),
            "no image ARG": ("FROM scratch\nARG TOOL_VERSION=1\n", [],
                             [note % (1, "no *_IMAGE ARG: no base image is recorded")]),
        }
        for name, (dockerfile, refs, notes) in cases.items():
            with self.subTest(name):
                shutil.rmtree(os.path.join(self.tmp, "repo"), ignore_errors=True)
                root = self.repo({"sbom/locks.tsv": "base\tsandbox\t*\tsandbox/Dockerfile\t-\n",
                                  "sandbox/Dockerfile": dockerfile})
                code, err = self.run_tool(root, variant="sandbox")
                self.assertEqual(code, 0, err)
                self.assertEqual(err.splitlines(True)[:-1], notes)  # then the summary line
                with open(self.out, encoding="utf-8") as f:
                    self.assertEqual([c["bom-ref"] for c in json.load(f)["components"]], refs)

    def test_pin_hash_is_sha256_or_sha512_by_length(self):
        sha512 = "0123456789abcdef" * 8
        root = self.repo({
            "sbom/locks.tsv": "pins\tcpu\t*\tci/pins.tsv\t-\n",
            "ci/pins.tsv": "tool\tcpu\tDockerfile\tTOOL_VERSION\tamd64=TOOL_SHA512_AMD64,arm64=TOOL_SHA256_ARM64"
                           "\tpkg:generic/tool@{version}\t-\t-\t-\tmanual\n",
            "Dockerfile": f"ARG TOOL_VERSION=1.0\nARG TOOL_SHA512_AMD64={sha512}\nARG TOOL_SHA256_ARM64={SHA}\n",
        })
        self.assertEqual(hashes(self.by_ref(root)["pkg:generic/tool@1.0"]), [("SHA-512", sha512)])
        self.assertEqual(hashes(self.by_ref(root, arch="arm64")["pkg:generic/tool@1.0"]), [("SHA-256", SHA)])

    def test_each_layer_of_a_variant_in_build_order(self):
        # cpu < gpu < sandbox: the later layer's row replaces the package, a layer that is
        # not in the variant is ignored
        root = self.repo({
            "sbom/locks.tsv": ("cran\tsandbox\t*\ts.tsv\t/r\ncran\tgpu\t*\tg.tsv\t/r\n"
                               "cran\tcpu\t*\tc.tsv\t/r\n"),
            "c.tsv": "sf\t1.0\nterra\t1.9-50\n", "g.tsv": "sf\t2.0\ncuda\t13.4\n",
            "s.tsv": "sf\t3.0+sbx\nbwrap\t0.11\n",
        })
        want = {
            "cpu": {"sf": ("1.0", "cpu"), "terra": ("1.9-50", "cpu")},
            "sandbox": {"sf": ("3.0+sbx", "sandbox"), "terra": ("1.9-50", "cpu"), "bwrap": ("0.11", "sandbox")},
            "gpu": {"sf": ("2.0", "gpu"), "terra": ("1.9-50", "cpu"), "cuda": ("13.4", "gpu")},
            "gpu-sandbox": {"sf": ("3.0+sbx", "sandbox"), "terra": ("1.9-50", "cpu"), "cuda": ("13.4", "gpu"),
                            "bwrap": ("0.11", "sandbox")},
        }
        for variant, packages in want.items():
            with self.subTest(variant):
                got = {c["name"]: (c["version"], props(c)["mesa:lock:layer"])
                       for c in self.sbom(root, variant=variant)["components"]}
                self.assertEqual(got, packages)

    def test_pin_path_is_normalised_like_a_prefix(self):
        root = self.fixture_copy()
        pins = os.path.join(root, "ci", "pins.tsv")
        with open(pins, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("\t/usr/local/go\t", text)
        with open(pins, "w", encoding="utf-8") as f:
            f.write(text.replace("\t/usr/local/go\t", "\t/usr/local/go/\t"))
        self.assertEqual(props(self.by_ref(root)["pkg:generic/go@1.27.3"])["mesa:lock:path"], "/usr/local/go")
        self.assertEqual(self.sbom(root), self.sbom())

    def test_symlinked_lock_file_inside_the_repo(self):
        root = self.repo({"sbom/locks.tsv": "cran\tcpu\t*\tsbom/cran.tsv\t/r\n", "locks/cran.tsv": "sf\t1.1-3\n"})
        os.symlink("../locks/cran.tsv", os.path.join(root, "sbom", "cran.tsv"))
        self.assertEqual(list(self.by_ref(root)), ["pkg:cran/sf@1.1-3#/r"])

    def test_arg_last_definition_wins(self):
        root = self.repo({
            "sbom/locks.tsv": "pins\tcpu\t*\tci/pins.tsv\t-\n",
            "ci/pins.tsv": "tool\tcpu\tDockerfile\tTOOL_VERSION\t-\tpkg:generic/tool@{version}\t-\t-\t-\tmanual\n",
            "Dockerfile": "ARG TOOL_VERSION=1.0\nFROM scratch\narg TOOL_VERSION=2.0+b1 OTHER=x\n",
        })
        comp = self.by_ref(root)["pkg:generic/tool@2.0%2Bb1"]
        self.assertEqual(comp["version"], "2.0+b1")


class MalformedInput(Case):
    """Every case exits 2, names file:line, and writes no output."""

    PIN = "tool\tcpu\tDockerfile\tTOOL_VERSION\tamd64=TOOL_SHA256\tpkg:generic/tool@{version}\t-\t/usr/bin/tool\t-\tmanual\n"
    DOCKERFILE = f"FROM scratch\nARG TOOL_VERSION=1.0\nARG TOOL_SHA256={SHA}\n"
    CONDA_URL = "https://conda.anaconda.org/conda-forge/noarch/tzdata-2026e-h5d301ff_0.conda"

    def assert_rejected(self, files, where, variant="cpu"):
        shutil.rmtree(os.path.join(self.tmp, "repo"), ignore_errors=True)
        code, err = self.run_tool(self.repo(files), variant=variant)
        self.assertEqual(code, 2, err)
        self.assertTrue(err.startswith("sbom_from_locks: " + where + ": "), err)
        self.assertEqual(err.count("\n"), 1, err)
        self.assertFalse(os.path.exists(self.out))

    def test_locks_tsv(self):
        ok = "cran\tcpu\t*\tcran.tsv\t/r\n"
        cases = {
            "spaces instead of tabs": "cran cpu * cran.tsv /r\n",
            "four columns": "cran\tcpu\t*\tcran.tsv\n",
            "unknown kind": "gem\tcpu\t*\tcran.tsv\t/r\n",
            "unknown layer": "cran\tbase\t*\tcran.tsv\t/r\n",
            "unknown arch": "cran\tcpu\tx86_64\tcran.tsv\t/r\n",
            "relative prefix": "cran\tcpu\t*\tcran.tsv\tr\n",
            "missing prefix": "cran\tcpu\t*\tcran.tsv\t-\n",
            "prefix on base": "base\tcpu\t*\tDockerfile\t/\n",
            "absolute file": "cran\tcpu\t*\t/etc/passwd\t/r\n",
            "file outside the repo": "cran\tcpu\t*\t../cran.tsv\t/r\n",
            "file outside the repo, hidden": "cran\tcpu\t*\ta/../../cran.tsv\t/r\n",
            "missing lock file": "cran\tcpu\t*\tnope.tsv\t/r\n",
            "empty column": "cran\tcpu\t*\t\t/r\n",
        }
        for name, row in cases.items():
            with self.subTest(name):
                self.assert_rejected({"sbom/locks.tsv": "# comment\n" + ok + row, "cran.tsv": "sf\t1.1-3\n",
                                      "Dockerfile": self.DOCKERFILE}, "sbom/locks.tsv:3")
        with self.subTest("no locks.tsv"):
            self.assert_rejected({"cran.tsv": "sf\t1.1-3\n"}, "sbom/locks.tsv:1")

    def test_rows_of_other_layers_and_arches_are_validated_too(self):
        self.assert_rejected({"sbom/locks.tsv": "cran\tcpu\t*\tcran.tsv\t/r\ngem\tgpu\tarm64\tx\t/r\n",
                              "cran.tsv": "sf\t1.1-3\n"}, "sbom/locks.tsv:2")

    def test_pip(self):
        cases = {
            "hash before requirement": (f"    --hash=sha256:{SHA}\n", 1),
            "not a pin": ("requests>=2\n", 1),
            "short hash": ("requests==2.34.2 \\\n    --hash=sha256:abc123\n", 2),
            "unknown algorithm": (f"requests==2.34.2 --hash=crc32:{SHA}\n", 1),
            "trailing junk": ("requests==2.34.2 extra\n", 1),
            "vcs url has no version": ("ok==1.0\nmesa-mcp @ git+https://github.com/idss-mesa/mesa-mcp@v0.2.0\n", 2),
            "editable": ("-e ./src\n", 1),
        }
        for name, (text, line) in cases.items():
            with self.subTest(name):
                self.assert_rejected({"sbom/locks.tsv": "pip\tcpu\t*\treq.txt\t/v\n", "req.txt": text},
                                     f"req.txt:{line}")

    def test_lock_file_that_is_a_symlink_out_of_the_repo(self):
        outside = os.path.join(self.tmp, "outside.txt")
        with open(outside, "w", encoding="utf-8") as f:
            f.write("API_TOKEN=abc123secret\n")
        for target in (outside, "../../outside.txt", "/proc/self/environ"):
            with self.subTest(target):
                files = {"sbom/locks.tsv": "# c\npip\tcpu\t*\tsbom/pip.txt\t/opt/mesa\n"}
                shutil.rmtree(os.path.join(self.tmp, "repo"), ignore_errors=True)
                root = self.repo(files)
                os.symlink(target, os.path.join(root, "sbom", "pip.txt"))
                code, err = self.run_tool(root)
                self.assertEqual(code, 2, err)
                self.assertEqual(err, "sbom_from_locks: sbom/locks.tsv:2: file 'sbom/pip.txt' is not a path "
                                      "inside the repo\n")
                self.assertFalse(os.path.exists(self.out))

    def test_quoted_file_content_is_one_short_printable_line(self):
        long_line = "x" * 500
        cases = {
            "pip line": ({"sbom/locks.tsv": "pip\tcpu\t*\treq.txt\t/v\n",
                          "req.txt": "SECRET=\x1b[2K\x00hunter2 " + long_line + "\n"}, "req.txt:1"),
            "npm key": ({"sbom/locks.tsv": "npm\tcpu\t*\tpackage-lock.json\t/n\n",
                         "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
                             "node_modules/a\n::error::forged " + long_line: {}}})}, "package-lock.json:1"),
            "ARG value": ({"sbom/locks.tsv": "pins\tcpu\t*\tci/pins.tsv\t-\n", "ci/pins.tsv": self.PIN,
                           "Dockerfile": self.DOCKERFILE.replace(SHA, long_line)}, "ci/pins.tsv:1"),
        }
        for name, (files, where) in cases.items():
            with self.subTest(name):
                self.assert_rejected(files, where)
                _, err = self.run_tool(os.path.join(self.tmp, "repo"))
                self.assertTrue(err.rstrip("\n").isprintable(), err)
                self.assertNotIn("x" * 81, err)
                self.assertLess(len(err), 300)

    def test_npm(self):
        entry = '{\n "lockfileVersion": 3,\n "packages": {\n  "": {},\n  "node_modules/a": %s\n }\n}\n'
        cases = {
            "invalid json": ('{\n "lockfileVersion": 3,\n "packages": {,}\n}\n', 3),
            "lockfileVersion 2": ('{"lockfileVersion": 2, "packages": {}}\n', 1),
            "no packages": ('{"lockfileVersion": 3}\n', 1),
            "not an object": ("[]\n", 1),
            "no version": (entry % '{"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}', 5),
            "entry is a string": (entry % '"1.0.0"', 5),
            "bad base64": (entry % '{"version": "1.0.0", "integrity": "sha512-!!!"}', 5),
            "truncated digest": (entry % '{"version": "1.0.0", "integrity": "sha512-AAAA"}', 5),
            "unknown algorithm": (entry % '{"version": "1.0.0", "integrity": "crc32-AAAA"}', 5),
            # wrong JSON types: npm never writes these, a hand-edited or hostile lock can
            "name is a number": (entry % '{"version": "1", "name": 5}', 5),
            "name is a list": (entry % '{"version": "1", "name": ["x"]}', 5),
            "os is a number": (entry % '{"version": "1", "os": 7}', 5),
            "number in the os list": (entry % '{"version": "1", "os": [1]}', 5),
            "cpu is an object": (entry % '{"version": "1", "cpu": {"a": 1}}', 5),
            "number in the cpu list": (entry % '{"version": "1", "cpu": [5]}', 5),
            "number in the libc list": (entry % '{"version": "1", "libc": [1]}', 5),
            "resolved is a number": (entry % '{"version": "1", "resolved": 5}', 5),
            "resolved is an object": (entry % '{"version": "1", "resolved": {"x": 1}}', 5),
            "integrity is a list": (entry % '{"version": "1", "integrity": ["sha512-AAAA"]}', 5),
            "nested too deeply": ("[" * 100000 + "]" * 100000, 1),
        }
        for name, (text, line) in cases.items():
            with self.subTest(name):
                self.assert_rejected({"sbom/locks.tsv": "npm\tcpu\t*\tpackage-lock.json\t/n\n",
                                      "package-lock.json": text}, f"package-lock.json:{line}")

    def test_conda(self):
        cases = {
            "no @EXPLICIT": (f"{self.CONDA_URL}#sha256:{SHA}\n", 1),
            "environment.yml": ("name: geospatial\ndependencies:\n  - gdal\n", 1),
            "only comments": ("# platform: linux-64\n", 1),
            "no hash": (f"@EXPLICIT\n{self.CONDA_URL}\n", 2),
            "short sha256": (f"@EXPLICIT\n{self.CONDA_URL}#sha256:abc\n", 2),
            "md5 with a sha256 label": (f"@EXPLICIT\n{self.CONDA_URL}#sha256:{'a' * 32}\n", 2),
            "not a package file": (f"@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/noarch/repodata.json#sha256:{SHA}\n", 2),
            "no build": (f"# c\n@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/noarch/tzdata-2026e.conda#sha256:{SHA}\n", 3),
            "no channel": (f"@EXPLICIT\nhttps://example.org/tzdata-2026e-h5d301ff_0.conda#sha256:{SHA}\n", 2),
        }
        for name, (text, line) in cases.items():
            with self.subTest(name):
                self.assert_rejected({"sbom/locks.tsv": "conda\tcpu\t*\tenv.lock\t/c\n", "env.lock": text},
                                     f"env.lock:{line}")

    def test_base(self):
        cases = {
            "short digest": ("ARG BASE_IMAGE=quay.io/jupyter/minimal-notebook@sha256:abc\n", 1),
            "short digest next to an unpinned image": ("ARG A_IMAGE=a:1\nARG B_IMAGE=b:1@sha256:abc\n", 2),
            "short digest next to a pinned image": (f"ARG A_IMAGE=a@sha256:{SHA}\nARG B_IMAGE=b:1@sha256:abc\n", 2),
            "other digest algorithm": (f"ARG A_IMAGE=a@sha256:{SHA}\nARG B_IMAGE=b@sha512:{SHA * 2}\n", 2),
            "unbalanced quote": ('ARG BASE_IMAGE="quay.io/x\n', 1),
        }
        for name, (text, line) in cases.items():
            with self.subTest(name):
                self.assert_rejected({"sbom/locks.tsv": "base\tcpu\t*\tDockerfile\t-\n", "Dockerfile": text},
                                     f"Dockerfile:{line}")

    def test_pins(self):
        pin, good = self.PIN, self.DOCKERFILE
        cases = {  # rows after one comment line, the Dockerfile, the line that is wrong
            "nine columns": (pin.rsplit("\t", 1)[0] + "\n", good, 2),
            "unknown layer": (pin.replace("\tcpu\t", "\tall\t"), good, 2),
            "missing version ARG": (pin, good.replace("TOOL_VERSION", "TOOLS_VERSION"), 2),
            "version ARG without default": (pin, good.replace("TOOL_VERSION=1.0", "TOOL_VERSION"), 2),
            "missing hash ARG": (pin, good.replace("TOOL_SHA256", "TOOL_SHA512"), 2),
            "hash ARG is not a sha256": (pin, good.replace(SHA, "abc"), 2),
            "hash ARG is a sha384": (pin, good.replace(SHA, "a" * 96), 2),
            "hash ARG is one digit short of a sha512": (pin, good.replace(SHA, "a" * 127), 2),
            "hash ARG is upper case": (pin, good.replace(SHA, "A" * 128), 2),
            "bad hash_args": (pin.replace("amd64=TOOL_SHA256", "x86_64=TOOL_SHA256"), good, 2),
            "purl without {version}": (pin.replace("@{version}", "@1.0"), good, 2),
            "purl is not a purl": (pin.replace("pkg:generic/tool", "tool"), good, 2),
            "relative path": (pin.replace("/usr/bin/tool", "bin/tool"), good, 2),
            "missing Dockerfile": (pin.replace("\tDockerfile\t", "\tgpu/Dockerfile\t"), good, 2),
            "Dockerfile outside the repo": (pin.replace("\tDockerfile\t", "\t../Dockerfile\t"), good, 2),
            "absolute Dockerfile": (pin.replace("\tDockerfile\t", "\t/etc/os-release\t"), good, 2),
            "duplicate name": (pin + pin.replace("{version}", "{version}?a=b"), good, 3),
            "duplicate purl": (pin + pin.replace("tool\t", "tool2\t", 1), good, 3),
        }
        for name, (rows, dockerfile, line) in cases.items():
            with self.subTest(name):
                self.assert_rejected({"sbom/locks.tsv": "pins\tcpu\t*\tci/pins.tsv\t-\n",
                                      "ci/pins.tsv": "# pins\n" + rows, "Dockerfile": dockerfile},
                                     f"ci/pins.tsv:{line}")

    def test_pin_of_another_layer_is_still_validated(self):
        self.assert_rejected({"sbom/locks.tsv": "pins\tcpu\t*\tci/pins.tsv\t-\n",
                              "ci/pins.tsv": self.PIN.replace("\tcpu\t", "\tgpu\t"),
                              "Dockerfile": "FROM scratch\n"}, "ci/pins.tsv:1")

    def test_cran_and_vsix(self):
        cases = {
            "cran": ("sf\t1.1-3\nterra 1.9-50\n", 2),
            "vsix": (f"ms-python.python\t2026.4.0\t{SHA}\nms-python.debugpy\t2026.6.0\tabc\n", 2),
        }
        for kind, (text, line) in cases.items():
            with self.subTest(kind):
                self.assert_rejected({"sbom/locks.tsv": f"{kind}\tcpu\t*\tlock.tsv\t/p\n", "lock.tsv": text},
                                     f"lock.tsv:{line}")
        with self.subTest("vsix id"):
            self.assert_rejected({"sbom/locks.tsv": "vsix\tcpu\t*\tlock.tsv\t/p\n",
                                  "lock.tsv": f"python\t2026.4.0\t{SHA}\n"}, "lock.tsv:1")

    def test_pin_dockerfile_outside_the_repo_is_not_read(self):
        # the same file as an absolute path and through '..': neither may reach the SBOM
        outside = os.path.join(self.tmp, "host.env")
        with open(outside, "w", encoding="utf-8") as f:
            f.write("ARG TOOL_VERSION=1.2.3-topsecret\n")
        for dockerfile in (outside, "../host.env"):
            with self.subTest(dockerfile):
                self.assert_rejected({
                    "sbom/locks.tsv": "pins\tcpu\t*\tci/pins.tsv\t-\n",
                    "ci/pins.tsv": f"tool\tcpu\t{dockerfile}\tTOOL_VERSION\t-\tpkg:generic/tool@{{version}}"
                                   "\t-\t-\t-\tmanual\n"}, "ci/pins.tsv:1")

    def test_unwritable_output(self):
        self.out = os.path.join(self.tmp, "no-such-dir", "locks.cdx.json")
        proc = subprocess.run([sys.executable, TOOL, "--repo-root", FIXTURE, "--variant", "cpu", "--arch", "amd64",
                               "-o", self.out], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stderr, f"sbom_from_locks: {self.out}: No such file or directory\n")

    def test_cli_arguments(self):
        for args in (["--variant", "cuda", "--arch", "amd64"], ["--variant", "cpu", "--arch", "x86_64"],
                     ["--variant", "cpu"]):
            with self.subTest(args=args):
                proc = subprocess.run([sys.executable, TOOL, "--repo-root", FIXTURE, "-o", self.out] + args,
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertFalse(os.path.exists(self.out))
        proc = subprocess.run([sys.executable, TOOL, "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--repo-root", proc.stdout)


if __name__ == "__main__":
    unittest.main()
