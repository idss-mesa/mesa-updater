"""release.py with stand-ins for crane, cosign, gh and attach_sbom.sh: nothing is contacted."""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "release.py"
FAKE = ROOT / "tests" / "fixtures" / "release" / "fake_tool.py"
IMAGE = "registry.test/vice/mesa-cli"
REPO = "idss-mesa/cli"
MAIN = "refs/heads/main"
REVISION = "54cc21202c8c12fa2b6f10abe7eea203811791ae"
IDENTITY = r"^https://github\.com/idss-mesa/mesa-updater/\.github/workflows/mesa-release\.yml@"
TOOLS = ("crane", "cosign", "gh", "attach_sbom.sh")
BASE_LAYERS = {"amd64": ["sha256:" + "a" * 64], "arm64": ["sha256:" + "b" * 64]}
ALL = [("cpu", "amd64", "v2.0.0"), ("sandbox", "amd64", "v2.0.0-sandbox"), ("gpu", "amd64", "v2.0.0-gpu"),
       ("gpu-sandbox", "amd64", "v2.0.0-gpu-sandbox"), ("cpu", "arm64", "v2.0.0-arm64")]
PARENT = {"sandbox": "cpu", "gpu": "cpu", "gpu-sandbox": "gpu"}
PREFIX = "ci-test-a-"


def digest_of(variant, arch):
    return "sha256:" + hashlib.sha256(f"{variant}-{arch}".encode()).hexdigest()


def layers_of(variant, arch):
    """A variant's layers: those of the variant it builds on, plus one of its own."""
    below = layers_of(PARENT[variant], arch) if variant in PARENT else BASE_LAYERS[arch]
    return below + ["sha256:" + hashlib.sha256(f"layer-{variant}-{arch}".encode()).hexdigest()]


def verify_argv(variant, arch, ref=MAIN):
    """The one keyless verification command release.py may run for an image."""
    return ["verify-attestation", "--type", "cyclonedx",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--certificate-identity-regexp", IDENTITY,
            "--certificate-github-workflow-repository", REPO,
            "--certificate-github-workflow-ref", ref,
            "--certificate-github-workflow-sha", REVISION,
            f"{IMAGE}@{digest_of(variant, arch)}"]


class ReleaseTest(unittest.TestCase):
    release = "v2.0.0"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.root, self.state, self.bin, self.out = (self.tmp / n for n in ("repo", "state", "bin", "out"))
        for d in (self.root, self.state, self.bin, self.out):
            d.mkdir()
        self.write_repo()
        for name in TOOLS:
            tool = self.bin / name
            tool.write_text("#!" + sys.executable + "\n" + FAKE.read_text())
            tool.chmod(0o755)
        self.registry = {"image": IMAGE, "tags": {}, "images": {}}
        self.gh = {"repo": REPO, "release": self.release}

    def write_repo(self, version="2.0.0", arches="amd64 arm64", image=IMAGE):
        (self.root / "VERSION").write_text(version + "\n")
        (self.root / "mesa.env").write_text(f'# settings\nMESA_IMAGE={image}\nMESA_CONTEXT=bash\nMESA_ARCHES="{arches}"\n')

    def stage(self, images=ALL, version="v2.0.0", revision=REVISION):
        """What the build jobs leave behind: pushed images, and digest, base, SBOM and report per variant."""
        for variant, arch, _ in images:
            digest = digest_of(variant, arch)
            self.registry["images"][digest] = {"os": "linux", "architecture": arch,
                                               "rootfs": {"type": "layers", "diff_ids": layers_of(variant, arch)}}
            d = self.out / f"{variant}-{arch}"
            d.mkdir(exist_ok=True)
            (d / "digest").write_text(digest + "\n")
            if variant in PARENT:
                (d / "base").write_text(digest_of(PARENT[variant], arch) + "\n")
            sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                    "metadata": {"component": {"type": "container", "name": IMAGE, "version": digest},
                                 "properties": [{"name": "mesa:version", "value": version},
                                                {"name": "mesa:variant", "value": variant},
                                                {"name": "mesa:arch", "value": arch},
                                                {"name": "mesa:revision", "value": revision}]},
                    "components": [{"type": "library", "name": f"pkg-{variant}", "version": "1"}]}
            (d / "image.cdx.json").write_text(json.dumps(sbom))
            (d / "report.json").write_text(json.dumps({"summary": {"forward": {"ok": 3, "not-checked": 1}}}))

    def edit(self, key, name, change):
        path = self.out / key / name
        doc = json.loads(path.read_text())
        change(doc)
        path.write_text(json.dumps(doc))

    def env(self):
        return dict(os.environ, FAKE_STATE=str(self.state))

    def call(self, command, *args, tools=True):
        (self.state / "registry.json").write_text(json.dumps(self.registry))
        (self.state / "gh.json").write_text(json.dumps(self.gh))
        argv = [sys.executable, str(SCRIPT), command, "--repo-root", str(self.root), *args]
        if tools:
            argv += ["--crane", str(self.bin / "crane"), "--gh", str(self.bin / "gh")]
            if command == "publish":
                argv += ["--cosign", str(self.bin / "cosign"), "--attach", str(self.bin / "attach_sbom.sh")]
        result = subprocess.run(argv, capture_output=True, text=True, env=self.env(), cwd=self.tmp)
        self.registry = json.loads((self.state / "registry.json").read_text())
        self.gh = json.loads((self.state / "gh.json").read_text())
        self.assertNotIn("asked for the wrong thing", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def guard(self, *args, ref=MAIN):
        return self.call("guard", "--ref", ref, "--github-repo", REPO, *args)

    def publish(self, *args, ref=MAIN):
        return self.call("publish", "--out", str(self.out), "--ref", ref, "--revision", REVISION,
                         "--github-repo", REPO, "--identity-regexp", IDENTITY, *args)

    def attach(self, variant, arch, *options):
        """Run the fake attach_sbom.sh as an earlier attempt would have."""
        ref = f"{IMAGE}@{digest_of(variant, arch)}"
        return subprocess.run([str(self.bin / "attach_sbom.sh"), *options, ref,
                               str(self.out / f"{variant}-{arch}" / "image.cdx.json")], env=self.env(), check=False,
                              stderr=subprocess.DEVNULL)

    def forget_calls(self):
        (self.state / "log").unlink()

    def calls(self, tool=None, verb=None):
        log = self.state / "log"
        rows = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return [r for r in rows if (tool is None or r[0] == tool) and (verb is None or r[1:1 + len(verb)] == verb)]

    def signings(self):
        return [r for r in self.calls("attach_sbom.sh") if r[1] != "--index-only"]

    def writes(self):
        """Calls that change the registry or GitHub."""
        return (self.calls("crane", ["tag"]) + self.calls("attach_sbom.sh")
                + [r for r in self.calls("gh", ["release"]) if r[2] in ("create", "upload", "edit")])

    def assertFails(self, result, message, status=1):
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertIn(message, result.stderr)

    def tag_all(self):
        self.registry["tags"] = {tag: digest_of(variant, arch) for variant, arch, tag in ALL}


class PlanTest(ReleaseTest):
    def plan(self, *args):
        result = self.call("plan", *args, tools=False)
        return result, (json.loads(result.stdout) if result.returncode == 0 else None)

    def test_all_variants(self):
        result, plan = self.plan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(i["variant"], i["arch"], i["tag"]) for i in plan["images"]], ALL)
        self.assertEqual((plan["image"], plan["name"], plan["release"], plan["test"], plan["arches"]),
                         (IMAGE, "mesa-cli", "v2.0.0", False, ["amd64", "arm64"]))

    def test_one_architecture(self):
        self.write_repo(arches="amd64")
        _, plan = self.plan()
        self.assertEqual([i["tag"] for i in plan["images"]],
                         ["v2.0.0", "v2.0.0-sandbox", "v2.0.0-gpu", "v2.0.0-gpu-sandbox"])

    def test_test_prefix_and_skip_gpu(self):
        _, plan = self.plan("--tag-prefix", "ci-test-a1-b-", "--skip-gpu")
        self.assertEqual([i["tag"] for i in plan["images"]],
                         ["ci-test-a1-b-v2.0.0", "ci-test-a1-b-v2.0.0-sandbox", "ci-test-a1-b-v2.0.0-arm64"])
        self.assertTrue(plan["test"])

    def test_bad_prefix(self):
        for prefix in ("v", "ci-test", "ci-test-", "ci-test--", "ci-test-a", "ci-test-A-", "ci-test-a_b-", "rc-",
                       "ci-test-a-\n", "xci-test-a-"):
            with self.subTest(prefix=prefix):
                result, _ = self.plan("--tag-prefix", prefix)
                self.assertFails(result, "tag prefix", 2)

    def test_bad_version(self):
        for version in ("2.0", "v2.0.0", "2.0.0-rc1", "02.0.0", ""):
            with self.subTest(version=version):
                self.write_repo(version=version)
                result, _ = self.plan()
                self.assertFails(result, "VERSION must be X.Y.Z", 2)

    def test_bad_mesa_env(self):
        for arches, image in (("amd64 riscv64", IMAGE), ("", IMAGE), ("amd64 amd64", IMAGE),
                              ("amd64", "registry.test/vice/mesa-cli:latest"), ("amd64", "")):
            with self.subTest(arches=arches, image=image):
                self.write_repo(arches=arches, image=image)
                result, _ = self.plan()
                self.assertFails(result, "mesa.env", 2)

    def test_missing_files(self):
        (self.root / "VERSION").unlink()
        result, _ = self.plan()
        self.assertFails(result, "VERSION", 2)


class GuardTest(ReleaseTest):
    def outputs(self):
        path = self.tmp / "outputs"
        return dict(line.split("=", 1) for line in path.read_text().splitlines()) if path.exists() else {}

    def guard(self, *args, **kw):
        return super().guard("--github-output", str(self.tmp / "outputs"), *args, **kw)

    def released(self):
        self.tag_all()
        self.gh.update(published=True, git_tag=REVISION,
                       manifest={"images": [{"tag": t, "digest": digest_of(v, a)} for v, a, t in ALL]})

    def test_new(self):
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.outputs(), {"state": "new", "release": "v2.0.0", "image": IMAGE, "test": "false",
                                          "arches": '["amd64", "arm64"]'})
        self.assertEqual(self.writes(), [])
        self.assertEqual([r[2] for r in self.calls("crane", ["digest"])], [f"{IMAGE}:{t}" for _, _, t in ALL])

    def test_released(self):
        self.released()
        result = self.guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.outputs()["state"], "released")

    def test_published_with_other_digests(self):
        self.released()
        images = self.gh["manifest"]["images"]
        other = [dict(i) for i in images]
        other[2]["digest"] = "sha256:" + "0" * 64
        for manifest in ({"images": other}, {"images": images[:4]}, {"unexpected": 1}):
            with self.subTest(manifest=manifest):
                self.gh["manifest"] = manifest
                self.assertFails(self.guard(), "does not match the tags")
        self.assertEqual(self.outputs(), {})

    def test_published_but_the_manifest_cannot_be_read(self):
        self.released()
        self.gh["manifest"] = None
        self.assertFails(self.guard(), "reading release-manifest.json")
        self.assertEqual(self.outputs(), {})

    def test_partly_published(self):
        cases = {
            "one tag": ({"v2.0.0-sandbox": digest_of("sandbox", "amd64")}, {}),
            "all tags, no release": (None, {}),
            "release without tags": ({}, {"published": True, "git_tag": REVISION}),
            "git tag only": ({}, {"git_tag": REVISION}),
            "release, some tags": ({"v2.0.0": digest_of("cpu", "amd64")}, {"published": True, "git_tag": REVISION}),
        }
        for name, (tags, gh) in cases.items():
            with self.subTest(name):
                if tags is None:
                    self.tag_all()
                else:
                    self.registry["tags"] = tags
                self.gh = {"repo": REPO, "release": "v2.0.0", **gh}
                result = self.guard()
                self.assertFails(result, "partly published")
                self.assertIn("Re-run failed jobs", result.stderr)
        self.assertEqual(self.outputs(), {})

    def test_real_release_needs_main_and_gpu(self):
        for ref in ("refs/heads/feature", "refs/tags/main", "refs/heads/main2", "refs/heads/main/x", "main", ""):
            with self.subTest(ref=ref):
                self.assertFails(self.guard(ref=ref), "only be released from refs/heads/main")
        self.assertFails(self.guard("--skip-gpu"), "needs its GPU variants")
        self.assertEqual(self.calls(), [], "refused before anything is looked up")

    def test_test_run_from_a_branch(self):
        self.gh["release"] = PREFIX + "v2.0.0"
        result = self.guard("--tag-prefix", PREFIX, "--skip-gpu", ref="refs/heads/feature")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.outputs()["state"], "new")
        self.assertEqual(self.outputs()["release"], PREFIX + "v2.0.0")
        self.assertEqual(self.outputs()["test"], "true")
        self.assertEqual(self.calls("gh"), [], "a test run does not look at GitHub releases")

    def test_gpu_builds_only_from_main(self):
        for ref in ("refs/heads/feature", "refs/heads/main2", "refs/heads/main/x", "refs/tags/main", "main"):
            with self.subTest(ref=ref):
                self.assertFails(self.guard("--tag-prefix", PREFIX, ref=ref),
                                 "the GPU builder only builds commits on main")
        self.assertEqual(self.calls(), [])
        result = self.guard("--tag-prefix", PREFIX)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_test_tags_in_the_way(self):
        self.registry["tags"] = {PREFIX + "v2.0.0-arm64": digest_of("cpu", "arm64")}
        self.assertFails(self.guard("--tag-prefix", PREFIX), "test tags already exist")

    def test_a_registry_error_is_not_a_free_tag(self):
        (self.state / "fail").write_text("crane digest\n")
        self.assertFails(self.guard(), "crane digest")
        self.assertEqual(self.outputs(), {})

    def test_a_github_error_is_not_a_missing_release(self):
        (self.state / "fail").write_text("gh api\n")
        self.assertFails(self.guard(), "gh api")
        self.assertEqual(self.outputs(), {})

    def test_bad_github_repo(self):
        self.assertFails(self.call("guard", "--ref", MAIN, "--github-repo", "cli"), "OWNER/NAME", 2)


class PublishTest(ReleaseTest):
    def setUp(self):
        super().setUp()
        self.stage()

    def release_dir(self):
        return self.out / "release"

    def test_publishes(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.registry["tags"], {tag: digest_of(v, a) for v, a, tag in ALL})
        # Order: every SBOM attested before the first tag, tags before the GitHub release.
        order = [("sign" if r[0] == "attach_sbom.sh" else r[1]) for r in self.calls()
                 if (r[0] == "attach_sbom.sh" and r[1] != "--index-only") or r[1] == "tag"
                 or r[1:3] == ["release", "create"]]
        self.assertEqual(order, ["sign"] * 5 + ["tag"] * 5 + ["release"])
        self.assertEqual([r[1:] for r in self.signings()],
                         [[f"{IMAGE}@{digest_of(v, a)}", str(self.out / f"{v}-{a}" / "image.cdx.json")]
                          for v, a, _ in ALL])
        self.assertEqual([r[1:] for r in self.calls("crane", ["tag"])],
                         [["tag", f"{IMAGE}@{digest_of(v, a)}", t] for v, a, t in ALL])

    def test_every_verification_names_the_workflow_repo_branch_and_commit(self):
        self.assertEqual(self.publish().returncode, 0)
        verifications = [r[1:] for r in self.calls("cosign")]
        self.assertEqual(len(verifications), 10, "each image: once before attaching, once after")
        for variant, arch, _ in ALL:
            self.assertEqual(verifications.count(verify_argv(variant, arch)), 2)

    def test_release_files(self):
        self.assertEqual(self.publish().returncode, 0)
        d = self.release_dir()
        sboms = [f"mesa-cli-{tag}.cdx.json" for _, _, tag in ALL]
        self.assertEqual(sorted(p.name for p in d.iterdir()),
                         sorted(sboms + ["release-manifest.json", "SHA256SUMS", "notes.md"]))
        manifest = json.loads((d / "release-manifest.json").read_text())
        self.assertEqual((manifest["image"], manifest["release"], manifest["version"], manifest["revision"]),
                         (IMAGE, "v2.0.0", "2.0.0", REVISION))
        self.assertEqual([(i["variant"], i["arch"], i["tag"], i["digest"]) for i in manifest["images"]],
                         [(v, a, t, digest_of(v, a)) for v, a, t in ALL])
        for entry, (variant, arch, _) in zip(manifest["images"], ALL):
            copied = (d / entry["sbom"]).read_bytes()
            self.assertEqual(copied, (self.out / f"{variant}-{arch}" / "image.cdx.json").read_bytes())
            self.assertEqual(entry["sbom_sha256"], hashlib.sha256(copied).hexdigest())
        sums = dict(reversed(line.split("  ")) for line in (d / "SHA256SUMS").read_text().splitlines())
        self.assertEqual(sorted(sums), sorted(sboms + ["release-manifest.json"]))
        for name, value in sums.items():
            self.assertEqual(value, hashlib.sha256((d / name).read_bytes()).hexdigest())
        notes = (d / "notes.md").read_text()
        self.assertIn(f"`{IMAGE}:v2.0.0-gpu-sandbox`", notes)
        # The command a user is told to run is the one publish itself ran.
        shown = notes.split("```")[1].replace("\\\n", " ").split()
        self.assertEqual(shown, ["cosign"] + [a if a != IDENTITY else f"'{IDENTITY}'" for a in verify_argv("cpu", "amd64")])

    def test_github_release(self):
        self.assertEqual(self.publish().returncode, 0)
        create = self.calls("gh", ["release", "create"])[0]
        d = self.release_dir()
        self.assertEqual(create[3:11], ["v2.0.0", "--repo", REPO, "--target", REVISION, "--title", "mesa-cli v2.0.0",
                                        "--notes-file"])
        self.assertEqual(create[11], str(d / "notes.md"))
        self.assertNotIn("--draft", create)
        self.assertNotIn("--prerelease", create)
        self.assertEqual(sorted(create[12:]), sorted(str(p) for p in d.iterdir() if p.name != "notes.md"))
        self.assertEqual((self.gh["published"], self.gh["git_tag"]), (True, REVISION))

    def test_second_run_changes_nothing(self):
        self.assertEqual(self.publish().returncode, 0)
        self.forget_calls()
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("attach_sbom.sh"), [], "verified attestations are not attached again")
        self.assertEqual(self.calls("crane", ["tag"]), [], "tags that already point at the digest are left alone")
        self.assertEqual(self.calls("gh", ["release", "create"]), [])
        upload = self.calls("gh", ["release", "upload"])[0]
        self.assertEqual(upload[3:7], ["v2.0.0", "--repo", REPO, "--clobber"])
        d = self.release_dir()
        self.assertEqual(sorted(upload[7:]), sorted(str(p) for p in d.iterdir() if p.name != "notes.md"))
        self.assertEqual(self.calls("gh", ["release", "edit"]), [])

    def test_resumes_after_a_partial_publish(self):
        """Two images attested and one tagged by a run that then died."""
        for variant in ("cpu", "sandbox"):
            self.attach(variant, "amd64")
        self.forget_calls()
        self.registry["tags"] = {"v2.0.0": digest_of("cpu", "amd64")}
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.signings()), 3)
        self.assertEqual(sorted(r[3] for r in self.calls("crane", ["tag"])),
                         sorted(t for _, _, t in ALL if t != "v2.0.0"))
        self.assertEqual(self.registry["tags"], {tag: digest_of(v, a) for v, a, tag in ALL})

    def test_a_tag_does_not_stand_in_for_an_attestation(self):
        self.tag_all()
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.signings()), 5, "already tagged images are attested all the same")

    def test_test_run(self):
        self.gh["release"] = PREFIX + "v2.0.0"
        result = self.publish("--tag-prefix", PREFIX, "--skip-gpu", ref="refs/heads/feature")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(self.registry["tags"]),
                         [PREFIX + "v2.0.0", PREFIX + "v2.0.0-arm64", PREFIX + "v2.0.0-sandbox"])
        create = self.calls("gh", ["release", "create"])[0]
        self.assertEqual(create[3], PREFIX + "v2.0.0")
        self.assertIn("--draft", create)
        self.assertIn("--prerelease", create)
        self.assertEqual(self.calls("cosign")[0][1:], verify_argv("cpu", "amd64", ref="refs/heads/feature"))
        self.assertEqual(self.calls("gh", ["api"]), [], "a draft is not looked up as a published release")
        # A second test run finds its draft and leaves it a draft.
        self.forget_calls()
        result = self.publish("--tag-prefix", PREFIX, "--skip-gpu", ref="refs/heads/feature")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls("gh", ["release", "upload"])), 1)
        self.assertEqual(self.calls("gh", ["release", "edit"]) + self.calls("gh", ["release", "create"]), [])

    def test_test_run_without_github_release(self):
        result = self.publish("--tag-prefix", PREFIX, "--no-github-release")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("gh"), [])
        self.assertEqual(len(self.registry["tags"]), 5)

    def test_offline_key(self):
        result = self.call("publish", "--out", str(self.out), "--revision", REVISION, "--tag-prefix", PREFIX,
                           "--cosign-key", "cosign.pub")
        self.assertEqual(result.returncode, 0, result.stderr)
        for call, (variant, arch, _) in zip(self.calls("cosign")[::2], ALL):
            self.assertEqual(call[1:], ["verify-attestation", "--type", "cyclonedx", "--key", "cosign.pub",
                                        "--insecure-ignore-tlog", f"{IMAGE}@{digest_of(variant, arch)}"])
        self.assertEqual(self.calls("gh"), [], "no GitHub repo given: no GitHub release")
        self.assertTrue((self.release_dir() / "release-manifest.json").exists())
        self.assertIn("--key <public key>", (self.release_dir() / "notes.md").read_text())

    def test_a_real_release_is_never_cut_short(self):
        self.assertFails(self.publish("--skip-gpu"), "needs its GPU variants")
        self.assertFails(self.publish("--cosign-key", "cosign.pub"), "real release")
        self.assertFails(self.publish("--no-github-release"), "real release")
        self.assertFails(self.call("publish", "--out", str(self.out), "--revision", REVISION, "--cosign-key", "k"),
                         "real release")
        for ref in ("refs/heads/feature", "refs/heads/main2", "refs/tags/main"):
            self.assertFails(self.publish(ref=ref), "only be released from refs/heads/main")
        for ref in ("refs/heads/feature", "refs/heads/main2"):
            self.assertFails(self.publish("--tag-prefix", PREFIX, ref=ref),
                             "the GPU builder only builds commits on main")
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.registry["tags"], {})

    def test_bad_arguments(self):
        base = ["publish", "--out", str(self.out), "--github-repo", REPO]
        self.assertFails(self.call(*base, "--revision", "54cc212", "--ref", MAIN, "--identity-regexp", IDENTITY),
                         "full commit SHA", 2)
        self.assertFails(self.call(*base, "--revision", REVISION, "--ref", MAIN), "--identity-regexp", 2)
        self.assertFails(self.call(*base, "--revision", REVISION, "--identity-regexp", IDENTITY), "--ref", 2)
        self.assertEqual(self.writes(), [])

    # ---- the GitHub release ----

    def test_a_leftover_draft_is_filled_and_published(self):
        self.gh["draft"] = True
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("gh", ["release", "create"]), [])
        self.assertEqual(len(self.calls("gh", ["release", "upload"])), 1)
        edit = self.calls("gh", ["release", "edit"])[0]
        self.assertEqual(edit[3:], ["v2.0.0", "--repo", REPO, "--draft=false", "--target", REVISION,
                                    "--title", "mesa-cli v2.0.0", "--notes-file", str(self.release_dir() / "notes.md")])
        self.assertEqual((self.gh["published"], self.gh["git_tag"]), (True, REVISION))

    def test_fails_when_the_github_release_is_not_made(self):
        for call in ("gh release create", "gh release upload", "gh release edit"):
            with self.subTest(call):
                self.gh = {"repo": REPO, "release": "v2.0.0", "draft": call != "gh release create"}
                (self.state / "fail").write_text(call + "\n")
                self.assertFails(self.publish(), call)

    def test_fails_when_the_release_ends_up_unpublished_or_on_another_commit(self):
        self.gh.update(published=True, git_tag="0" * 40)
        self.assertFails(self.publish(), "it must be on " + REVISION)
        self.gh.update(published=True, git_tag=None)
        self.assertFails(self.publish(), "the git tag v2.0.0 is missing")

    def test_fails_when_the_git_tag_was_already_on_another_commit(self):
        """`gh release create` uses an existing tag as it is."""
        for state in ({}, {"draft": True}):
            with self.subTest(state=state):
                self.gh = {"repo": REPO, "release": "v2.0.0", "git_tag": "0" * 40, **state}
                self.assertFails(self.publish(), "it must be on " + REVISION)

    def test_a_github_error_is_not_a_missing_release(self):
        (self.state / "fail").write_text("gh release view\n")
        self.assertFails(self.publish(), "gh release view")
        self.assertEqual(self.calls("gh", ["release", "create"]), [])

    def test_asks_whether_the_release_is_a_draft(self):
        self.assertEqual(self.publish().returncode, 0)
        view = self.calls("gh", ["release", "view"])[0]
        self.assertEqual(view[3:], ["v2.0.0", "--repo", REPO, "--json", "tagName,isDraft"])

    # ---- everything below must stop before anything is attested, tagged or released ----

    def refused(self, message, *args):
        self.assertFails(self.publish(*args), message)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.registry["tags"].keys() & {t for _, _, t in ALL}, self.tags_before)

    tags_before = frozenset()

    def test_missing_variant(self):
        (self.out / "gpu-amd64" / "digest").unlink()
        self.refused("gpu-amd64: no pushed digest")

    def test_bad_digest_file(self):
        (self.out / "sandbox-amd64" / "digest").write_text("latest\n")
        self.refused("not a digest")

    def test_sbom_of_another_build(self):
        changes = {
            "image digest": lambda d: d["metadata"]["component"].update(version="sha256:" + "0" * 64),
            "image name": lambda d: d["metadata"]["component"].update(name="registry.test/vice/mesa-kasm"),
            "mesa:revision": lambda d: d["metadata"]["properties"][3].update(value="0" * 40),
            "mesa:version": lambda d: d["metadata"]["properties"][0].update(value="v1.9.9"),
            "mesa:variant": lambda d: d["metadata"]["properties"][1].update(value="cpu"),
            "mesa:arch": lambda d: d["metadata"]["properties"][2].update(value="arm64"),
        }
        for field, change in changes.items():
            with self.subTest(field):
                self.stage()
                self.edit("gpu-amd64", "image.cdx.json", change)
                self.refused(f"the SBOM is for another build: {field}")

    def test_sbom_not_json(self):
        (self.out / "cpu-arm64" / "image.cdx.json").write_text("{")
        self.refused("is not JSON")

    def test_failed_crosscheck(self):
        for status in ("missing", "version-mismatch", "hash-mismatch"):
            with self.subTest(status):
                self.stage()
                self.edit("cpu-amd64", "report.json", lambda d: d["summary"]["forward"].update({status: 2}))
                self.refused("2 lock entries")
        (self.out / "cpu-amd64" / "report.json").write_text("{}")
        self.refused("no forward summary")

    def test_same_digest_twice(self):
        (self.out / "sandbox-amd64" / "digest").write_text(digest_of("cpu", "amd64") + "\n")
        self.edit("sandbox-amd64", "image.cdx.json",
                  lambda d: d["metadata"]["component"].update(version=digest_of("cpu", "amd64")))
        self.refused("same digest")

    def test_built_on_another_image_than_the_staged_one(self):
        other = "sha256:" + "9" * 64
        for variant, parent in PARENT.items():
            with self.subTest(variant):
                self.stage()
                (self.out / f"{variant}-amd64" / "base").write_text(other + "\n")
                self.refused(f"{variant} amd64 was built on {other}, but the staged {parent} image")
        self.stage()
        (self.out / "gpu-amd64" / "base").unlink()
        self.refused("gpu-amd64: the build did not record the digest it was built on")
        # gpu-sandbox on the CPU image instead of the GPU image
        self.stage()
        (self.out / "gpu-sandbox-amd64" / "base").write_text(digest_of("cpu", "amd64") + "\n")
        self.refused("gpu-sandbox amd64 was built on")

    def test_image_not_in_registry(self):
        del self.registry["images"][digest_of("gpu-sandbox", "amd64")]
        self.refused("is not in the registry")

    def test_wrong_platform(self):
        self.registry["images"][digest_of("cpu", "arm64")]["architecture"] = "amd64"
        self.refused("is a linux/amd64 image")
        self.stage()
        self.registry["images"][digest_of("cpu", "amd64")]["os"] = "windows"
        self.refused("is a windows/amd64 image")
        self.assertEqual([r[2:4] for r in self.calls("crane", ["config"])][:5],
                         [["--platform", f"linux/{a}"] for _, a, _ in ALL])

    def test_layers_are_not_those_of_the_staged_parent(self):
        own = lambda v: layers_of(v, "amd64")[-1]  # noqa: E731
        cpu, gpu = layers_of("cpu", "amd64"), layers_of("gpu", "amd64")
        cases = {
            "gpu": [cpu[0], "sha256:" + "c" * 64, own("gpu")],           # same first layer only
            "sandbox": list(cpu),                                          # adds nothing
            "gpu-sandbox": cpu + [own("gpu-sandbox")],                     # on cpu, not on gpu
        }
        for variant, layers in cases.items():
            with self.subTest(variant):
                self.stage()
                self.registry["images"][digest_of(variant, "amd64")]["rootfs"]["diff_ids"] = layers
                self.refused(f"{variant} amd64: {IMAGE}@{digest_of(variant, 'amd64')} is not built on the staged "
                             f"{PARENT[variant]} image")
        self.assertEqual(gpu[:len(cpu)], cpu)

    def test_tag_taken_by_another_image(self):
        self.registry["tags"] = {"v2.0.0-gpu": "sha256:" + "f" * 64}
        self.tags_before = frozenset(["v2.0.0-gpu"])
        self.refused("already exists with another digest")

    def test_registry_error_while_checking(self):
        (self.state / "fail").write_text("crane digest\n")
        self.refused("crane digest")

    def test_release_directory_that_is_something_else(self):
        (self.release_dir()).mkdir()
        (self.release_dir() / "precious.txt").write_text("keep")
        self.assertFails(self.publish(), "is not a release directory")
        self.assertEqual((self.release_dir() / "precious.txt").read_text(), "keep")

    # ---- failures after the checks: nothing is tagged unless every SBOM verified ----

    def nothing_released(self):
        self.assertEqual(self.registry["tags"], {})
        self.assertEqual([r for r in self.calls("gh", ["release"]) if r[2] != "view"], [])

    def test_attach_fails(self):
        (self.state / "attach.mode").write_text("fail")
        self.assertFails(self.publish(), "attach_sbom.sh")
        self.nothing_released()

    def test_attached_but_not_verifiable(self):
        for mode, message in (("none", "no matching attestations"), ("wrong", "none carries this SBOM")):
            with self.subTest(mode):
                (self.state / "attach.mode").write_text(mode)
                result = self.publish()
                self.assertFails(result, "was attached but does not verify")
                self.assertIn(message, result.stderr)
                self.nothing_released()

    def test_only_the_last_image_fails_to_verify(self):
        """Every image is verified after attaching, not just the first."""
        (self.state / "attach.skip").write_text(digest_of("cpu", "arm64") + "\n")
        result = self.publish()
        self.assertFails(result, "v2.0.0-arm64")
        self.assertIn("was attached but does not verify", result.stderr)
        self.nothing_released()

    def test_attestation_of_another_subject_or_type_does_not_count(self):
        sbom = json.loads((self.out / "cpu-amd64" / "image.cdx.json").read_text())
        hexdigest = digest_of("cpu", "amd64").split(":")[1]

        def envelope(subject, predicate_type, predicate):
            statement = {"predicateType": predicate_type, "predicate": predicate,
                         "subject": [{"name": IMAGE, "digest": {"sha256": subject}}]}
            return json.dumps({"payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n"

        (self.state / "indexed").mkdir()
        cases = {
            "another subject": envelope("0" * 64, "https://cyclonedx.org/bom", sbom),
            "another type": envelope(hexdigest, "https://spdx.dev/Document", sbom),
            "another SBOM": envelope(hexdigest, "https://cyclonedx.org/bom", {"bomFormat": "CycloneDX"}),
            "not an envelope": "{}\nnot json\n",
        }
        for name, lines in cases.items():
            with self.subTest(name):
                (self.state / "indexed" / hexdigest).write_text(lines)
                (self.state / "attach.mode").write_text("none")
                self.assertFails(self.publish(), "was attached but does not verify")
                self.assertEqual(self.signings()[0][1], f"{IMAGE}@{digest_of('cpu', 'amd64')}",
                                 "it does not count, so the SBOM is attached")
                self.forget_calls()

    def test_the_right_attestation_among_several_counts(self):
        sbom = json.loads((self.out / "cpu-amd64" / "image.cdx.json").read_text())
        hexdigest = digest_of("cpu", "amd64").split(":")[1]
        (self.state / "indexed").mkdir()
        (self.state / "pushed").mkdir()
        statement = {"predicateType": "https://cyclonedx.org/bom", "predicate": {"bomFormat": "CycloneDX"},
                     "subject": [{"name": IMAGE, "digest": {"sha256": hexdigest}}]}
        other = json.dumps({"payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n"
        statement["predicate"] = sbom
        right = json.dumps({"payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n"
        (self.state / "indexed" / hexdigest).write_text(other + right)
        self.assertEqual(self.publish().returncode, 0)
        self.assertEqual(len(self.signings()), 4, "the CPU image is not attested again")

    def test_attested_by_a_run_that_died_before_the_fallback_tag(self):
        (self.state / "attach.mode").write_text("unindexed")
        self.assertEqual(self.attach("cpu", "amd64").returncode, 1)
        (self.state / "attach.mode").write_text("ok")
        self.forget_calls()
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("attach_sbom.sh")[0][1:], ["--index-only", f"{IMAGE}@{digest_of('cpu', 'amd64')}"])
        self.assertEqual(len(self.signings()), 4, "the CPU image is found again, not signed again")
        self.assertIn("found after rewriting its index", result.stdout)
        # The look after the repair is the same full verification as every other.
        cpu = [r[1:] for r in self.calls("cosign") if r[-1].endswith(digest_of("cpu", "amd64"))]
        self.assertEqual(cpu, [verify_argv("cpu", "amd64")] * 2)

    def unindexed(self, *lines):
        """Leave referrers of the CPU image in the registry that the fallback tag does not list."""
        (self.state / "pushed").mkdir(exist_ok=True)
        (self.state / "pushed" / digest_of("cpu", "amd64").split(":")[1]).write_text("".join(lines))

    def envelope(self, predicate, predicate_type="https://cyclonedx.org/bom"):
        statement = {"predicateType": predicate_type, "predicate": predicate,
                     "subject": [{"name": IMAGE, "digest": {"sha256": digest_of("cpu", "amd64").split(":")[1]}}]}
        return json.dumps({"payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n"

    def test_repaired_index_with_only_another_sbom_is_signed(self):
        self.unindexed(self.envelope({"bomFormat": "CycloneDX", "components": []}))
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.signings()), 5, "verified, but not this SBOM: this one is attested too")

    def test_repaired_index_is_read_past_a_line_that_is_no_envelope(self):
        sbom = json.loads((self.out / "cpu-amd64" / "image.cdx.json").read_text())
        self.unindexed("not json\n", "{}\n", self.envelope(sbom))
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.signings()), 4)

    def test_a_referrer_that_is_no_attestation_does_not_block_signing(self):
        """A signature, or an SBOM some other tool attached: --index-only says 3, nothing of ours is there."""
        self.unindexed(self.envelope({"critical": {}}, "https://sigstore.dev/cosign/sign/v1"))
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.signings()), 5)

    def test_does_not_sign_again_when_what_is_attached_does_not_verify(self):
        self.attach("cpu", "amd64")
        self.forget_calls()
        (self.state / "fail").write_text("cosign verify-attestation\n")
        result = self.publish()
        self.assertFails(result, "Not signing again")
        self.assertIn("simulated failure", result.stderr)
        self.assertEqual(self.signings(), [])
        self.nothing_released()

    def test_index_repair_failure_stops(self):
        (self.state / "fail").write_text("attach_sbom.sh --index-only\n")
        self.assertFails(self.publish(), "attach_sbom.sh --index-only")
        self.assertEqual(self.signings(), [])
        self.nothing_released()

    def test_tagging_fails(self):
        (self.state / "fail").write_text("crane tag\n")
        self.assertFails(self.publish(), "crane tag")
        self.assertEqual([r for r in self.calls("gh", ["release"]) if r[2] != "view"], [])

    def test_tag_that_did_not_stick(self):
        (self.state / "tag.lost").touch()
        self.assertFails(self.publish(), "does not point at")
        self.assertEqual(self.calls("gh"), [])

    def test_tag_written_by_someone_else_meanwhile(self):
        foreign = "sha256:" + "f" * 64
        (self.state / "race.json").write_text(json.dumps({"v2.0.0-gpu": foreign}))
        result = self.publish()
        self.assertFails(result, "someone else tagged it")
        self.assertEqual(self.registry["tags"]["v2.0.0-gpu"], foreign, "the foreign tag is not overwritten")
        self.assertEqual([r for r in self.calls("gh", ["release"]) if r[2] != "view"], [])


if __name__ == "__main__":
    unittest.main()
