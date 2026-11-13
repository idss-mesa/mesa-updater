"""mesa-ci.sh: the `push` step with stub docker and crane, and the released-version check with real git.

Nothing is contacted: `origin` is a bare repository in a temporary directory.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "mesa-ci.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "locks"   # a miniature image repo: bash/, gpu/, sbom/, ci/pins.tsv
IMAGE = "registry.test/vice/mesa-cli"
ID = "sha256:" + "1" * 64        # local image ID
DIGEST = "sha256:" + "2" * 64    # what docker reports for the push
OTHER = "sha256:" + "3" * 64

STUBS = {
    "docker": r"""#!/usr/bin/env bash
set -euo pipefail
{ printf 'docker'; printf '\t%s' "$@"; printf '\n'; } >>"$STUB_STATE/calls.log"
case "$1 $2" in
  "image inspect") cat "$STUB_STATE/id" ;;
  tag\ *) ;;
  push\ *)
    echo "The push refers to repository [${2%:*}]"
    echo "5f70bf18a086: Pushed"
    cat "$STUB_STATE/push.out"
    ;;
  *) exit 64 ;;
esac
""",
    "crane": r"""#!/usr/bin/env bash
set -euo pipefail
{ printf 'crane'; printf '\t%s' "$@"; printf '\n'; } >>"$STUB_STATE/calls.log"
[[ $1 == manifest ]] || exit 64
# Content-addressed only: a tag could have been moved by someone else.
[[ $2 == *@sha256:* ]] || { echo "asked for a tag: $2" >&2; exit 64; }
cat "$STUB_STATE/manifest.json"
""",
}


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false",
                           "-c", "protocol.file.allow=always", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class MesaCiTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.repo, self.state, self.bin = self.tmp / "repo", self.tmp / "state", self.tmp / "bin"
        shutil.copytree(FIXTURE, self.repo)
        self.state.mkdir()
        self.bin.mkdir()
        (self.repo / "mesa.env").write_text(f'MESA_IMAGE={IMAGE}\nMESA_CONTEXT=bash\nMESA_ARCHES="amd64 arm64"\n')
        (self.repo / "VERSION").write_text("2.0.0\n")
        (self.repo / "sandbox").mkdir()
        (self.repo / "sandbox" / "Dockerfile").write_text("ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
        (self.repo / "README.md").write_text("docs\n")

    def run_ci(self, *args, cwd=None, **env):
        full = {k: v for k, v in os.environ.items()
                if k not in ("VARIANT", "ARCH", "OUT", "STAGE_ID", "DIGEST", "BASE_REF", "CHECK_RELEASED")}
        full.update(PATH=f"{self.bin}:{full['PATH']}", STUB_STATE=str(self.state),
                    GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="protocol.file.allow", GIT_CONFIG_VALUE_0="always")
        full.update(env)
        return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True, env=full, cwd=cwd or self.repo)


class PushTest(MesaCiTest):
    def setUp(self):
        super().setUp()
        for name, body in STUBS.items():
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        (self.state / "id").write_text(ID + "\n")
        self.pushed(DIGEST)
        self.manifest({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                       "config": {"digest": ID, "size": 1}, "layers": []})

    def pushed(self, digest):
        (self.state / "push.out").write_text(f"stage-run7-cpu-amd64: digest: {digest} size: 17021\n" if digest else "")

    def manifest(self, doc):
        (self.state / "manifest.json").write_text(json.dumps(doc))

    def push(self, **env):
        return self.run_ci("push", VARIANT="cpu", ARCH="amd64", STAGE_ID="run7", **env)

    def calls(self):
        log = self.state / "calls.log"
        return [line.split("\t") for line in log.read_text().splitlines()] if log.exists() else []

    def recorded(self):
        path = self.repo / "out" / "cpu-amd64" / "digest"
        return path.read_text() if path.exists() else None

    def test_records_the_digest_docker_reports(self):
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recorded(), DIGEST + "\n")
        stage = f"{IMAGE}:stage-run7-cpu-amd64"
        self.assertIn(f"push: {stage} {DIGEST}", result.stdout)
        self.assertEqual([c for c in self.calls() if c[1] in ("tag", "push")],
                         [["docker", "tag", "mesa-local/mesa-cli:cpu-amd64", stage], ["docker", "push", stage]])
        self.assertEqual([c for c in self.calls() if c[0] == "crane"], [["crane", "manifest", f"{IMAGE}@{DIGEST}"]],
                         "the registry is only asked by digest, never for the tag")

    def test_image_id_is_the_manifest_digest(self):
        """The containerd image store: the image ID is the manifest digest."""
        (self.state / "id").write_text(DIGEST + "\n")
        self.manifest({"schemaVersion": 2, "config": {"digest": OTHER}, "layers": []})
        self.assertEqual(self.push().returncode, 0)
        self.assertEqual(self.recorded(), DIGEST + "\n")

    def test_refuses_a_manifest_that_is_not_the_local_image(self):
        self.manifest({"schemaVersion": 2, "config": {"digest": OTHER}, "layers": []})
        result = self.push()
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"{IMAGE}@{DIGEST} is not the image that was built and tested here ({ID})", result.stderr)
        self.assertIsNone(self.recorded())

    def test_refuses_an_index(self):
        self.manifest({"schemaVersion": 2, "manifests": [{"digest": ID}], "config": {"digest": ID}})
        result = self.push()
        self.assertEqual(result.returncode, 1)
        self.assertIn("is an image index", result.stderr)
        self.assertIsNone(self.recorded())

    def test_push_without_a_digest(self):
        for digest in (None, "sha256:abc"):
            with self.subTest(digest=digest):
                self.pushed(digest)
                result = self.push()
                self.assertEqual(result.returncode, 1)
                self.assertIn("did not report a digest", result.stderr)
                self.assertIsNone(self.recorded())

    def test_failed_push(self):
        (self.bin / "docker").write_text(STUBS["docker"].replace('push\\ *)', 'push\\ *) echo denied >&2; exit 1 ;;\n  never)'))
        result = self.push()
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(self.recorded())


class ReleasedCheckTest(MesaCiTest):
    def setUp(self):
        super().setUp()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "first")
        (self.repo / "NOTES").write_text("more history\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "second")
        self.origin = self.tmp / "origin.git"
        git(self.tmp, "clone", "-q", "--bare", str(self.repo), str(self.origin))
        git(self.repo, "remote", "add", "origin", f"file://{self.origin}")

    def release(self, annotated=False):
        git(self.origin, "tag", *(["-a", "-m", "release"] if annotated else []), "v2.0.0", "main")

    def change(self, path, text="changed\n"):
        with open(self.repo / path, "a") as f:
            f.write(text)
        git(self.repo, "commit", "-q", "-am", f"change {path}")

    def check(self, cwd=None, **env):
        return self.run_ci("check", cwd=cwd, CHECK_RELEASED="1", **env)

    def test_not_released(self):
        self.change("bash/Dockerfile")
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERSION 2.0.0 is not released yet", result.stdout)

    def test_released_and_unchanged(self):
        for annotated in (False, True):
            with self.subTest(annotated=annotated):
                git(self.origin, "tag", "-d", "v2.0.0") if annotated else None
                self.release(annotated)
                self.change("README.md")            # documentation is not the image
                result = self.check()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("the image files are those of the released v2.0.0", result.stdout)

    def test_released_and_changed(self):
        self.release()
        for path in ("bash/Dockerfile", "gpu/Dockerfile", "sandbox/Dockerfile"):
            with self.subTest(path):
                self.change(path)
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(path, result.stderr)
                self.assertIn("differ from the released v2.0.0: raise VERSION", result.stderr)
                git(self.repo, "reset", "-q", "--hard", "HEAD^")

    def test_raising_the_version_passes(self):
        self.release()
        self.change("bash/Dockerfile")
        (self.repo / "VERSION").write_text("2.0.1\n")
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERSION 2.0.1 is not released yet", result.stdout)

    def test_only_when_asked(self):
        self.release()
        self.change("bash/Dockerfile")
        result = self.run_ci("check")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unreachable_origin_is_an_error(self):
        self.release()
        git(self.repo, "remote", "set-url", "origin", f"file://{self.tmp}/nowhere.git")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot list the tags of origin", result.stderr)

    def test_a_full_clone_stays_full(self):
        self.release()
        self.change("README.md")
        before = git(self.repo, "rev-list", "--count", "HEAD")
        self.assertEqual(self.check().returncode, 0)
        self.assertEqual(git(self.repo, "rev-parse", "--is-shallow-repository"), "false")
        self.assertEqual(git(self.repo, "rev-list", "--count", "HEAD"), before)

    def test_shallow_checkout_as_in_ci(self):
        self.release()
        self.change("bash/Dockerfile")
        git(self.repo, "push", "-q", "origin", "main")
        shallow = self.tmp / "shallow"
        git(self.tmp, "clone", "-q", "--depth", "1", f"file://{self.origin}", str(shallow))
        result = self.check(cwd=shallow)
        self.assertEqual(result.returncode, 1)
        self.assertIn("bash/Dockerfile", result.stderr)
        self.assertEqual(git(shallow, "rev-list", "--count", "HEAD"), "1", "still one commit deep")


if __name__ == "__main__":
    unittest.main()
