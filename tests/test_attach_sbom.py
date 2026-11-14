"""attach_sbom.sh with stub cosign/oras/crane/curl on PATH: no registry is contacted.

The stubs log their argv and answer from a state directory filled with the
real referrer manifests and the real Harbor 2.9.0 referrers API response.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "attach_sbom.sh"
FIX = ROOT / "tests" / "fixtures" / "referrers"
SUBJECT = (FIX / "subject.digest").read_text().strip()
HEX = SUBJECT[len("sha256:"):]
REPO = "registry.test/vice/mesa-cli"
REF = f"{REPO}@{SUBJECT}"
SBOM = FIX / "sbom.cdx.json"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.c3R1Yi10b2tlbg.c2lnbmF0dXJl"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"

# Referrers of the subject, by what they are.
ORAS_SBOM = "sha256:6a72481ab3a5783321a42199ee2737fa6b1fc41bd861bdaa29c53a1fe5c97309"
ATTESTATION = "sha256:478e41ab7d5229054d9d872f4da6df65e0216494a67a6e1b7b455a5c5e962986"
ATTESTATION_2 = "sha256:4a17c2f81ee5c2f4275be3ae98661059e1b817b5c72b642ffc9120b5228a7d01"
SIGNATURE = "sha256:df45077c3481991b46b1ab235d1f8773b4620d7878217ea10eb1f4a16f537cc6"

CORRECT = {d["digest"]: d for d in json.loads((FIX / "index.json").read_text())["manifests"]}
HARBOR = {d["digest"]: d for d in json.loads((FIX / "referrers.raw.json").read_text())["manifests"]}

PRELUDE = r"""#!/usr/bin/env bash
set -euo pipefail
me=${0##*/}
{ printf '%s' "$me"; printf '\t%s' "$@"; printf '\n'; } >>"$STUB_STATE/calls.log"
if [[ ${STUB_FAIL:-} == "$me" || ${STUB_FAIL:-} == "$me ${1:-}" ]]; then
  echo "$me: simulated failure" >&2
  exit 1
fi
"""
STUBS = {
    # "Attaching" swaps in what the registry answers afterwards.
    "cosign": r"""
[[ $1 == attest ]] || exit 64
echo "COSIGN_YES=${COSIGN_YES:-}" >"$STUB_STATE/cosign.env"
cp "$STUB_STATE"/after/* "$STUB_STATE/"
""",
    "oras": r"""
case "$1 $2" in
  discover\ *) cat "$STUB_STATE/discover.json" ;;
  "manifest push") cp "${@: -1}" "$STUB_STATE/pushed.json" ;;
  *) exit 64 ;;
esac
""",
    "crane": r"""
case "$1 $2" in
  "auth token") printf 'Authorization: Bearer %s' "$STUB_TOKEN" ;;
  manifest\ *)
    file=$STUB_STATE/manifests/${2##*@sha256:}
    [[ -f $file ]] || { echo "MANIFEST_UNKNOWN: $2" >&2; exit 1; }
    cat "$file"
    ;;
  *) exit 64 ;;
esac
""",
    "curl": r"""
cat >"$STUB_STATE/curl.stdin"
while (($#)); do
  case $1 in
    --output) cp "$STUB_STATE/api.json" "$2" ;;
    --dump-header) cp "$STUB_STATE/api.headers" "$2" ;;
  esac
  shift
done
cat "$STUB_STATE/api.code"
""",
}


def discover_doc(digests):
    """`oras discover --format json` output (shape from oras 1.3.6)."""
    node = {"reference": REF, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": SUBJECT, "size": 423}
    node["referrers"] = [dict(CORRECT[d], reference=f"{REPO}@{d}", referrers=[]) for d in digests]
    return json.dumps(node, indent=2)


def api_doc(digests):
    """Harbor's referrers API response for these referrers (descriptors as Harbor sent them)."""
    return json.dumps({"schemaVersion": 2, "mediaType": INDEX_TYPE, "manifests": [HARBOR[d] for d in digests]},
                      separators=(",", ":"))


class AttachSbomTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.state = self.tmp / "state"
        self.bin = self.tmp / "bin"
        self.scratch = self.tmp / "scratch"
        for d in (self.state / "manifests", self.state / "after", self.bin, self.scratch):
            d.mkdir(parents=True)
        for name, body in STUBS.items():
            stub = self.bin / name
            stub.write_text(PRELUDE + body)
            stub.chmod(0o755)
        (self.bin / "python3").symlink_to(sys.executable)  # the script runs the interpreter under test
        for path in FIX.glob("m-*.json"):
            (self.state / "manifests" / path.stem[2:]).write_bytes(path.read_bytes())
        (self.state / "api.code").write_text("200")
        (self.state / "api.headers").write_bytes(
            b"HTTP/2 200 \r\ncontent-type: application/json; charset=utf-8\r\n\r\n")

    def registry(self, before, after, oras_before=(), oras_after=None):
        """What the referrers API (and oras) list before and after `cosign attest`."""
        (self.state / "api.json").write_text(api_doc(before))
        (self.state / "discover.json").write_text(discover_doc(oras_before))
        (self.state / "after" / "api.json").write_text(api_doc(after))
        (self.state / "after" / "discover.json").write_text(
            discover_doc(oras_before if oras_after is None else oras_after))

    def run_script(self, *args, **extra_env):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("COSIGN_", "STUB_"))}
        env.update(PATH=f"{self.bin}:{env['PATH']}", STUB_STATE=str(self.state), STUB_TOKEN=TOKEN,
                   TMPDIR=str(self.scratch))
        env.update(extra_env)
        result = subprocess.run([str(SCRIPT), *(args or (REF, str(SBOM)))],
                                capture_output=True, text=True, env=env, cwd=self.tmp)
        self.assertEqual(list(self.scratch.iterdir()), [], "temporary files are removed")
        return result

    def calls(self):
        log = self.state / "calls.log"
        return [line.split("\t") for line in log.read_text().splitlines()] if log.exists() else []

    def pushed(self):
        return json.loads((self.state / "pushed.json").read_text())

    def assert_failed_without_push(self, result, code, *needles):
        self.assertEqual(result.returncode, code, result.stderr)
        for needle in needles:
            self.assertIn(needle, result.stderr)
        self.assertNotIn(["oras", "manifest"], [c[:2] for c in self.calls()])
        self.assertFalse((self.state / "pushed.json").exists())

    def test_first_attestation_on_harbor(self):
        # Harbor lists the new referrer; oras sees none because no fallback tag exists yet.
        self.registry(before=[], after=[ATTESTATION])
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)

        listing = [
            ["oras", "discover", "--format", "json", REF],
            ["crane", "auth", "token", "-H", REPO],
            ["curl", f"https://registry.test/v2/vice/mesa-cli/referrers/{SUBJECT}"],
        ]
        calls = self.calls()
        curls = [c for c in calls if c[0] == "curl"]
        for call in curls:
            self.assertEqual(call[1:4], ["--silent", "--show-error", "--config"])
            self.assertEqual(call[4], "-", "the token reaches curl on stdin")
            self.assertEqual(call[-3:-1], ["--write-out", "%{http_code}"])
        index_file = calls[-1][-1]
        self.assertEqual(
            [c if c[0] != "curl" else ["curl", c[-1]] for c in calls],
            listing
            + [["cosign", "attest", "--type", "cyclonedx", "--predicate", str(SBOM), REF]]
            + listing
            + [["crane", "manifest", f"{REPO}@{ATTESTATION}"],
               ["oras", "manifest", "push", "--media-type", INDEX_TYPE, f"{REPO}:sha256-{HEX}", index_file]])

        self.assertEqual((self.state / "cosign.env").read_text(), "COSIGN_YES=true\n")
        self.assertEqual((self.state / "curl.stdin").read_text(), f'header = "Authorization: Bearer {TOKEN}"\n')
        self.assertNotIn(TOKEN, (self.state / "calls.log").read_text(), "the token is never in argv")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertEqual(self.pushed(), {"schemaVersion": 2, "mediaType": INDEX_TYPE,
                                         "manifests": [CORRECT[ATTESTATION]]})

    def test_index_lists_every_referrer_with_its_real_type_and_size(self):
        self.registry(before=[ORAS_SBOM, ATTESTATION_2, SIGNATURE],
                      after=[ORAS_SBOM, ATTESTATION, ATTESTATION_2, SIGNATURE])
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pushed()["manifests"], [CORRECT[d] for d in sorted(CORRECT)])
        # what was there is fetched (once) before signing, the new referrer after
        steps = [c[2].rpartition("@")[2] if c[0] == "crane" else "attest" for c in self.calls()
                 if c[:2] in (["crane", "manifest"], ["cosign", "attest"])]
        self.assertEqual(steps, sorted([ORAS_SBOM, ATTESTATION_2, SIGNATURE]) + ["attest", ATTESTATION])
        self.assertIn("lists 4 referrer(s)", result.stdout)

    def test_second_run_adds_another_attestation_and_keeps_the_first(self):
        # cosign signs again on every run (new signature, new manifest), so the index then lists
        # two attestations of the same predicate; each referrer manifest is listed once.
        self.registry(before=[], after=[ATTESTATION])
        self.assertEqual(self.run_script().returncode, 0)
        first = self.pushed()["manifests"]
        # Now the fallback tag exists: oras reads it, Harbor's API lists the same referrer.
        in_tag = [d["digest"] for d in first]
        self.registry(before=[ATTESTATION], after=[ATTESTATION, ATTESTATION_2], oras_before=in_tag)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.pushed()["manifests"], [CORRECT[ATTESTATION], CORRECT[ATTESTATION_2]])

    def test_entry_only_in_the_fallback_index_is_preserved(self):
        self.registry(before=[], after=[ATTESTATION], oras_before=[SIGNATURE])
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.pushed()["manifests"], [CORRECT[ATTESTATION], CORRECT[SIGNATURE]])

    def test_registry_without_a_referrers_api(self):
        # 404: clients keep the fallback tag themselves, so oras discover is the whole answer.
        (self.state / "api.code").write_text("404")
        self.registry(before=[], after=[], oras_before=[SIGNATURE], oras_after=[ATTESTATION, SIGNATURE])
        (self.state / "api.json").write_text('{"errors":[{"code":"NOT_FOUND"}]}')
        (self.state / "after" / "api.json").write_text('{"errors":[{"code":"NOT_FOUND"}]}')
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pushed()["manifests"], [CORRECT[ATTESTATION], CORRECT[SIGNATURE]])

    def test_key_and_signing_config_are_passed_only_when_set(self):
        self.registry(before=[], after=[ATTESTATION])
        result = self.run_script(COSIGN_KEY="/keys/cosign.key", COSIGN_SIGNING_CONFIG="/keys/signing-config.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        (attest,) = [c for c in self.calls() if c[0] == "cosign"]
        self.assertEqual(attest, ["cosign", "attest", "--type", "cyclonedx", "--predicate", str(SBOM),
                                  "--key", "/keys/cosign.key",
                                  "--signing-config", "/keys/signing-config.json", REF])
        self.assertEqual((self.state / "cosign.env").read_text(), "COSIGN_YES=true\n")

    def test_bad_arguments_touch_nothing(self):
        cases = {
            "tag instead of digest": (f"{REPO}:latest", str(SBOM)),
            "tag and digest": (f"{REPO}:latest@{SUBJECT}", str(SBOM)),
            "short digest": (f"{REPO}@sha256:{HEX[:40]}", str(SBOM)),
            "uppercase digest": (f"{REPO}@sha256:{HEX.upper()}", str(SBOM)),
            "other algorithm": (f"{REPO}@sha512:{HEX * 2}", str(SBOM)),
            "no registry": (f"mesa-cli@{SUBJECT}", str(SBOM)),
            "trailing text": (f"{REF} --insecure", str(SBOM)),
            "missing sbom": (REF, str(self.tmp / "absent.cdx.json")),
            "one argument": (REF,),
            "three arguments": (REF, str(SBOM), "extra"),
        }
        self.registry(before=[], after=[ATTESTATION])
        for label, args in cases.items():
            with self.subTest(label):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("attach_sbom:", result.stderr)
                self.assertEqual(self.calls(), [])

    def test_no_new_referrer_after_attest_is_an_error(self):
        self.registry(before=[SIGNATURE], after=[SIGNATURE])
        self.assert_failed_without_push(self.run_script(), 1, "lists no new referrer")

    def test_cosign_failure_stops_before_the_index(self):
        self.registry(before=[], after=[ATTESTATION])
        self.assert_failed_without_push(self.run_script(STUB_FAIL="cosign"), 1, "cosign: simulated failure")
        self.assertEqual([c[0] for c in self.calls()], ["oras", "crane", "curl", "cosign"])

    def test_listing_failures_stop_before_attesting(self):
        self.registry(before=[], after=[ATTESTATION])
        for label, env, needle in (
                ("oras discover fails", {"STUB_FAIL": "oras discover"}, "oras: simulated failure"),
                ("no token", {"STUB_FAIL": "crane auth"}, "crane: simulated failure"),
                ("curl fails", {"STUB_FAIL": "curl"}, "curl: simulated failure"),
                ("token is not one header line", {"STUB_TOKEN": 'x"\nurl = "https://elsewhere.test/'},
                 "unexpected output from 'crane auth token"),
        ):
            with self.subTest(label):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.assert_failed_without_push(self.run_script(**env), 1, needle)
                self.assertNotIn("cosign", [c[0] for c in self.calls()])
        self.assertNotIn("curl", [c[0] for c in self.calls()], "a malformed token never reaches curl")

    def test_api_errors_stop_before_attesting(self):
        self.registry(before=[], after=[ATTESTATION])
        (self.state / "api.code").write_text("401")
        self.assert_failed_without_push(self.run_script(), 1, "HTTP 401")
        (self.state / "api.code").write_text("200")
        (self.state / "api.headers").write_bytes(
            b'HTTP/2 200 \r\nLink: </v2/vice/mesa-cli/referrers/x?n=2>; rel="next"\r\n\r\n')
        self.assert_failed_without_push(self.run_script(), 1, "paginated")
        self.assertNotIn("cosign", [c[0] for c in self.calls()])

    def assert_stopped_before_attesting(self, result, code, *needles):
        self.assert_failed_without_push(result, code, *needles)
        self.assertNotIn("cosign", [c[0] for c in self.calls()], "nothing may be signed by a run that cannot finish")

    def test_existing_referrer_that_cannot_be_fetched_stops_before_attesting(self):
        # an entry of the fallback index whose manifest is gone, or a registry error on any of them
        self.registry(before=[ATTESTATION_2], after=[ATTESTATION, ATTESTATION_2], oras_before=[SIGNATURE])
        (self.state / "manifests" / SIGNATURE[7:]).unlink()
        self.assert_stopped_before_attesting(self.run_script(), 1, f"MANIFEST_UNKNOWN: {REPO}@{SIGNATURE}")
        (self.state / "calls.log").unlink()
        self.registry(before=[SIGNATURE], after=[SIGNATURE, ATTESTATION])
        self.assert_stopped_before_attesting(self.run_script(STUB_FAIL="crane manifest"), 1,
                                             "crane: simulated failure")

    def test_existing_referrer_the_index_refuses_stops_before_attesting(self):
        cases = {
            "no subject": (lambda m: m.pop("subject"), "subject is None"),
            "another subject": (lambda m: m["subject"].update(digest="sha256:" + "0" * 64),
                                "subject is sha256:" + "0" * 64),
            "no mediaType": (lambda m: m.pop("mediaType"), "manifest has no mediaType"),
        }
        for label, (change, needle) in cases.items():
            with self.subTest(label):
                manifest = json.loads((FIX / f"m-{SIGNATURE[7:]}.json").read_text())
                change(manifest)
                raw = json.dumps(manifest).encode()
                bad = "sha256:" + hashlib.sha256(raw).hexdigest()
                (self.state / "manifests" / bad[7:]).write_bytes(raw)
                (self.state / "calls.log").unlink(missing_ok=True)
                self.registry(before=[], after=[ATTESTATION])
                for listing in (self.state / "api.json", self.state / "after" / "api.json"):
                    doc = json.loads(listing.read_text())
                    doc["manifests"].append(dict(HARBOR[SIGNATURE], digest=bad))
                    listing.write_text(json.dumps(doc))
                self.assert_stopped_before_attesting(self.run_script(), 2, "referrers_index:", needle)

    def test_malformed_listing_before_attesting(self):
        self.registry(before=[], after=[ATTESTATION])
        (self.state / "api.json").write_text('{"manifests":[{"digest":"sha256:abc --insecure"}]}')
        self.assert_stopped_before_attesting(self.run_script(), 1, "unexpected referrer digest")

    def test_listed_referrer_that_cannot_be_fetched(self):
        self.registry(before=[], after=[ATTESTATION])
        (self.state / "manifests" / ATTESTATION[7:]).unlink()
        self.assert_failed_without_push(self.run_script(), 1, "MANIFEST_UNKNOWN")

    def test_referrer_bytes_that_do_not_match_their_digest(self):
        self.registry(before=[], after=[ATTESTATION])
        with open(self.state / "manifests" / ATTESTATION[7:], "ab") as f:
            f.write(b"\n")
        self.assert_failed_without_push(self.run_script(), 2, "referrers_index:", ATTESTATION)

    def test_malformed_listing(self):
        self.registry(before=[], after=[ATTESTATION])
        (self.state / "after" / "api.json").write_text(
            '{"manifests":[{"digest":"sha256:abc --insecure"}]}')
        self.assert_failed_without_push(self.run_script(), 1, "unexpected referrer digest")

    def test_push_failure_is_reported(self):
        self.registry(before=[], after=[ATTESTATION])
        result = self.run_script(STUB_FAIL="oras manifest")
        self.assertEqual(result.returncode, 1)
        self.assertIn("oras: simulated failure", result.stderr)

    # ---- --index-only: rewrite the fallback tag from what is attached, sign nothing ----

    def test_index_only_rewrites_the_tag_without_signing(self):
        # An earlier run attested and died before writing the tag: Harbor lists the referrers, oras none.
        self.registry(before=[ATTESTATION, SIGNATURE], after=[])
        result = self.run_script("--index-only", REF)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("cosign", [c[0] for c in self.calls()])
        self.assertEqual(self.pushed()["manifests"], [CORRECT[ATTESTATION], CORRECT[SIGNATURE]])
        self.assertEqual(self.calls()[-1][:5], ["oras", "manifest", "push", "--media-type", INDEX_TYPE])
        self.assertIn("lists 2 referrer(s)", result.stdout)

    def test_index_only_keeps_what_only_the_existing_tag_lists(self):
        self.registry(before=[ATTESTATION], after=[], oras_before=[SIGNATURE])
        result = self.run_script("--index-only", REF)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.pushed()["manifests"], [CORRECT[ATTESTATION], CORRECT[SIGNATURE]])

    def test_index_only_without_a_cyclonedx_attestation(self):
        # A signature and an SBOM attached with oras: listed in the tag, but nothing cosign could verify as ours.
        self.registry(before=[ORAS_SBOM, SIGNATURE], after=[])
        result = self.run_script("--index-only", REF)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("is a CycloneDX attestation", result.stdout)
        self.assertEqual(self.pushed()["manifests"], [CORRECT[ORAS_SBOM], CORRECT[SIGNATURE]])
        self.assertNotIn("cosign", [c[0] for c in self.calls()])

    def test_index_only_with_nothing_attached(self):
        self.registry(before=[], after=[ATTESTATION])
        result = self.run_script("--index-only", REF)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("lists no referrer", result.stdout)
        self.assertNotIn("cosign", [c[0] for c in self.calls()])
        self.assertFalse((self.state / "pushed.json").exists())

    def test_index_only_failures_are_not_exit_3(self):
        self.registry(before=[ATTESTATION], after=[])
        (self.state / "manifests" / ATTESTATION[7:]).unlink()
        self.assert_failed_without_push(self.run_script("--index-only", REF), 1, "MANIFEST_UNKNOWN")
        self.registry(before=[ATTESTATION], after=[])
        result = self.run_script("--index-only", REF, STUB_FAIL="oras discover")
        self.assertEqual(result.returncode, 1)

    def test_index_only_usage(self):
        for args in (("--index-only",), ("--index-only", REF, str(SBOM)), ("--index-only", "registry.test/x:tag")):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
