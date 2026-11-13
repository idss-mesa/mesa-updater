"""referrers_index.py against four real referrer manifests from Harbor 2.9.0."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "ci" / "referrers_index.py"
FIX = ROOT / "tests" / "fixtures" / "referrers"
SUBJECT = (FIX / "subject.digest").read_text().strip()
MANIFESTS = sorted(FIX.glob("m-*.json"))


def digest_of(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ReferrersIndexTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out = self.tmp / "index.json"

    def run_tool(self, pairs, subject=SUBJECT):
        cmd = [sys.executable, str(TOOL), "--subject-digest", subject, "-o", str(self.out)]
        for digest, path in pairs:
            cmd += ["--manifest", f"{digest}={path}"]
        return subprocess.run(cmd, capture_output=True, text=True)

    def real_pairs(self):
        return [("sha256:" + p.stem[2:], p) for p in MANIFESTS]

    def derived(self, source, change):
        """A copy of a real manifest with one change, and its new digest."""
        manifest = json.loads(source.read_text())
        change(manifest)
        path = self.tmp / ("derived-" + source.name)
        path.write_text(json.dumps(manifest, separators=(",", ":")))
        return digest_of(path), path

    def assert_refused(self, result, *needles):
        self.assertEqual(result.returncode, 2, result.stderr)
        for needle in needles:
            self.assertIn(needle, result.stderr)
        self.assertFalse(self.out.exists(), "no index may be written on bad input")

    def test_fixture_names_are_their_digests(self):
        self.assertEqual(len(MANIFESTS), 4)
        for digest, path in self.real_pairs():
            self.assertEqual(digest, digest_of(path))

    def test_same_descriptors_as_hand_built_index(self):
        result = self.run_tool(self.real_pairs())
        self.assertEqual(result.returncode, 0, result.stderr)
        index = json.loads(self.out.read_text())
        expected = json.loads((FIX / "index.json").read_text())
        self.assertEqual(index["schemaVersion"], 2)
        self.assertEqual(index["mediaType"], "application/vnd.oci.image.index.v1+json")
        self.assertEqual(index["manifests"], sorted(expected["manifests"], key=lambda d: d["digest"]))
        self.assertEqual(
            sorted((d["digest"], d["size"], d["artifactType"]) for d in index["manifests"]),
            sorted((d["digest"], d["size"], d["artifactType"]) for d in expected["manifests"]))
        self.assertEqual([list(d) for d in index["manifests"]],
                         [["mediaType", "digest", "size", "artifactType", "annotations"]] * 4)

    def test_corrects_what_harbor_reports(self):
        # Harbor's API gives the config media type and the artifact size.
        self.run_tool(self.real_pairs())
        ours = {d["digest"]: d for d in json.loads(self.out.read_text())["manifests"]}
        harbor = json.loads((FIX / "referrers.raw.json").read_text())["manifests"]
        self.assertEqual(set(ours), {d["digest"] for d in harbor})
        for d in harbor:
            self.assertEqual(d["artifactType"], "application/vnd.oci.empty.v1+json")
            self.assertNotEqual(ours[d["digest"]]["artifactType"], d["artifactType"])
            self.assertEqual(ours[d["digest"]]["size"], (FIX / f"m-{d['digest'][7:]}.json").stat().st_size)
            self.assertEqual(ours[d["digest"]]["annotations"], d["annotations"])

    def test_output_does_not_depend_on_argument_order(self):
        self.run_tool(self.real_pairs())
        first = self.out.read_bytes()
        self.run_tool(list(reversed(self.real_pairs())))
        self.assertEqual(self.out.read_bytes(), first)
        digests = [d["digest"] for d in json.loads(first)["manifests"]]
        self.assertEqual(digests, sorted(digests))

    def test_duplicate_digests_collapse(self):
        pairs = self.real_pairs()
        result = self.run_tool(pairs + pairs[:2])
        self.assertEqual(result.returncode, 0, result.stderr)
        digests = [d["digest"] for d in json.loads(self.out.read_text())["manifests"]]
        self.assertEqual(digests, sorted(d for d, _ in pairs))

    def test_digest_mismatch_is_refused(self):
        pairs = self.real_pairs()
        wrong = (pairs[0][0], pairs[1][1])
        self.assert_refused(self.run_tool([wrong]), str(pairs[1][1]), pairs[0][0])

    def test_modified_manifest_is_refused(self):
        digest, path = self.real_pairs()[0]
        tampered = self.tmp / "tampered.json"
        tampered.write_bytes(path.read_bytes() + b"\n")
        self.assert_refused(self.run_tool([(digest, tampered)]), str(tampered))

    def test_wrong_subject_is_refused(self):
        other = "sha256:" + "0" * 64
        self.assert_refused(self.run_tool(self.real_pairs(), subject=other), "subject is " + SUBJECT)

    def test_manifest_without_subject_is_refused(self):
        digest, path = self.derived(MANIFESTS[0], lambda m: m.pop("subject"))
        self.assert_refused(self.run_tool([(digest, path)]), "subject is None")

    def test_wrong_json_types_are_refused(self):
        cases = {
            "subject is not an object": lambda m: m.update(subject=SUBJECT),
            "subject is not an object ": lambda m: m.update(subject=[SUBJECT]),
            "digest is not a string": lambda m: m.update(subject={"digest": [SUBJECT]}),
            "config is not an object": lambda m: (m.pop("artifactType", None), m.update(config="str")),
            "mediaType is not a string": lambda m: m.update(mediaType=5),
            "artifactType is not a string": lambda m: m.update(artifactType={"a": 1}),
            "annotations is not an object": lambda m: m.update(annotations="zz"),
            "annotations is not an object of strings": lambda m: m["annotations"].update(extra=1),
        }
        for message, change in cases.items():
            with self.subTest(message):
                digest, path = self.derived(MANIFESTS[0], change)
                result = self.run_tool([(digest, path)])
                self.assert_refused(result, f"{path}: {message.strip()}")
                self.assertEqual(result.stderr.count("\n"), 1, result.stderr)  # a message, not a traceback
        path = self.tmp / "config-type.json"
        path.write_text(json.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "subject": {"digest": SUBJECT}, "config": {"mediaType": 5}}))
        self.assert_refused(self.run_tool([(digest_of(path), path)]), "mediaType is not a string")

    def test_json_nested_too_deeply(self):
        path = self.tmp / "deep.json"
        path.write_text("[" * 100000 + "]" * 100000)
        result = self.run_tool([(digest_of(path), path)])
        self.assert_refused(result, f"{path}:1: not JSON: nested too deeply")
        self.assertEqual(result.stderr.count("\n"), 1, result.stderr)

    def test_unwritable_output(self):
        self.out = self.tmp / "no-such-dir" / "index.json"
        result = self.run_tool(self.real_pairs())
        self.assertEqual((result.returncode, result.stderr),
                         (2, f"referrers_index: {self.out}: No such file or directory\n"))

    def test_artifact_type_falls_back_to_config_media_type(self):
        source = FIX / "m-6a72481ab3a5783321a42199ee2737fa6b1fc41bd861bdaa29c53a1fe5c97309.json"
        digest, path = self.derived(source, lambda m: m.pop("artifactType"))
        result = self.run_tool([(digest, path)])
        self.assertEqual(result.returncode, 0, result.stderr)
        (desc,) = json.loads(self.out.read_text())["manifests"]
        self.assertEqual(desc["artifactType"], "application/vnd.oci.empty.v1+json")
        self.assertEqual(desc["digest"], digest)

    def test_annotations_are_omitted_when_the_manifest_has_none(self):
        digest, path = self.derived(MANIFESTS[0], lambda m: m.pop("annotations"))
        self.assertEqual(self.run_tool([(digest, path)]).returncode, 0)
        (desc,) = json.loads(self.out.read_text())["manifests"]
        self.assertNotIn("annotations", desc)

    def test_malformed_json_names_file_and_line(self):
        path = self.tmp / "broken.json"
        path.write_text('{"schemaVersion": 2,\n "subject": \n')
        self.assert_refused(self.run_tool([(digest_of(path), path)]), f"{path}:3: not JSON")

    def test_missing_file_and_bad_arguments(self):
        missing = self.tmp / "absent.json"
        self.assert_refused(self.run_tool([("sha256:" + "1" * 64, missing)]), str(missing))
        self.assert_refused(self.run_tool([("md5:abc", MANIFESTS[0])]), "md5:abc")
        self.assert_refused(self.run_tool(self.real_pairs(), subject="latest"), "--subject-digest")
        cmd = [sys.executable, str(TOOL), "--subject-digest", SUBJECT, "-o", str(self.out)]
        for bad in (["--manifest", "no-equals-sign"], []):
            result = subprocess.run(cmd + bad, capture_output=True, text=True)
            self.assert_refused(result, "--manifest")


if __name__ == "__main__":
    unittest.main()
