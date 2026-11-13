"""gpu_request.sh with a stub gh on PATH: GitHub is not contacted."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "gpu_request.sh"
DIGEST = "sha256:" + "ab" * 32
BUILDER = "idss-mesa/mesa-gpu-builder"
SHA = "54cc21202c8c12fa2b6f10abe7eea203811791ae"

# The stub answers only what the script may ask: calls about another repo or
# run exit 64. `gh run view` answers with the next line of view.seq (the last
# line repeats), run through the caller's own --jq expression; a line "error"
# makes that call fail. `gh run list` fails while list.errors holds a positive
# count.
GH = r"""#!/usr/bin/env bash
set -euo pipefail
{ printf 'gh'; printf '\t%s' "$@"; printf '\n'; } >>"$STUB_STATE/calls.log"
opt() { # value of option $1 among the remaining arguments
  local name=$1; shift
  while (($#)); do [[ $1 == "$name" ]] && { echo "$2"; return; }; shift; done
}
builder() { [[ $(opt --repo "$@") == idss-mesa/mesa-gpu-builder ]] || exit 64; }
case "$1 $2" in
  "api --method")
    [[ $3 == POST && $4 == repos/idss-mesa/mesa-gpu-builder/actions/workflows/build.yml/dispatches ]] || exit 64
    [[ ! -e $STUB_STATE/dispatch.fail ]] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    cat "$STUB_STATE/dispatch.json" 2>/dev/null || true
    ;;
  "run list")
    builder "$@"
    [[ $(opt --workflow "$@") == build.yml ]] || exit 64
    n=$(cat "$STUB_STATE/list.errors" 2>/dev/null || echo 0)
    if ((n > 0)); then echo $((n - 1)) >"$STUB_STATE/list.errors"; echo "HTTP 502" >&2; exit 1; fi
    cat "$STUB_STATE/runs.json"
    ;;
  "run view")
    builder "$@"
    [[ $3 == 9 ]] || exit 64
    n=$(cat "$STUB_STATE/view.n" 2>/dev/null || echo 1)
    line=$(sed -n "${n}p" "$STUB_STATE/view.seq")
    [[ -n $line ]] || line=$(tail -n 1 "$STUB_STATE/view.seq")
    echo $((n + 1)) >"$STUB_STATE/view.n"
    [[ $line != error ]] || { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
    [[ $(opt --json "$@") == status,conclusion ]] || exit 64
    jq -r "$(opt --jq "$@")" <<<"$line"
    ;;
  "run download")
    builder "$@"
    [[ $3 == 9 ]] || exit 64
    [[ ! -e $STUB_STATE/download.fail ]] || { echo "no valid artifacts found to download" >&2; exit 1; }
    touch "$STUB_STATE/downloaded"
    ;;
  "run cancel") builder "$@" ;;
  *) exit 64 ;;
esac
"""
RUNNING = '{"status": "in_progress", "conclusion": null}'
QUEUED = '{"status": "queued", "conclusion": null}'


def finished(conclusion):
    return json.dumps({"status": "completed", "conclusion": conclusion})


@unittest.skipUnless(shutil.which("jq"), "gpu_request.sh needs jq")
class GpuRequestTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.state, self.bin = self.tmp / "state", self.tmp / "bin"
        self.state.mkdir()
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(GH)
        gh.chmod(0o755)
        self.output = self.tmp / "github-output"
        self.runs([])

    def runs(self, rows):
        (self.state / "runs.json").write_text(json.dumps(rows))

    def view(self, *lines):
        (self.state / "view.seq").write_text("\n".join(lines) + "\n")

    def run_script(self, *args, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "MESA_", "STAGE_", "GH_", "GPU_"))}
        env.update(PATH=f"{self.bin}:{env['PATH']}", STUB_STATE=str(self.state), GPU_REQUEST_POLL_SECONDS="0",
                   GITHUB_REPOSITORY="idss-mesa/cli", GITHUB_SHA=SHA,
                   GITHUB_RUN_ID="43485738320", GITHUB_RUN_ATTEMPT="2", STAGE_ID="43485738320",
                   GITHUB_OUTPUT=str(self.output))
        env.update(extra)
        return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=self.tmp)

    def calls(self, *verb):
        log = self.state / "calls.log"
        rows = [line.split("\t")[1:] for line in log.read_text().splitlines()] if log.exists() else []
        return [r for r in rows if r[:len(verb)] == list(verb)]

    def done(self):
        return self.output.read_text() if self.output.exists() else ""

    # ---- start ----

    def test_start_takes_the_run_id_from_the_dispatch(self):
        (self.state / "dispatch.json").write_text(json.dumps(
            {"workflow_run_id": 9, "run_url": "https://api.github.test/x", "html_url": "https://github.test/x"}))
        result = self.run_script("start", DIGEST)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "9\n", "only the run id is printed")
        self.assertEqual(self.calls("api"), [[
            "api", "--method", "POST", f"repos/{BUILDER}/actions/workflows/build.yml/dispatches",
            "-f", "ref=main", "-F", "return_run_details=true",
            "-f", "inputs[repo]=cli", "-f", f"inputs[commit]={SHA}", "-f", f"inputs[cpu_digest]={DIGEST}",
            "-f", "inputs[stage_id]=43485738320", "-f", "inputs[request]=43485738320-2"]])
        self.assertEqual(self.calls("run"), [], "no lookup by name when the dispatch names the run")

    def test_start_finds_the_run_by_name_when_the_dispatch_does_not_say(self):
        for answer in (None, "", "{}", '{"workflow_run_id": null}', "not json", '{"workflow_run_id": "9; rm"}'):
            with self.subTest(answer=answer):
                if answer is not None:
                    (self.state / "dispatch.json").write_text(answer)
                self.runs([{"databaseId": 7, "displayTitle": "cli 43485738320-1"},
                           {"databaseId": 9, "displayTitle": "cli 43485738320-2"},
                           {"databaseId": 8, "displayTitle": "kasm 43485738320-2"}])
                result = self.run_script("start", DIGEST)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "9\n")

    def test_start_tries_the_lookup_again(self):
        (self.state / "list.errors").write_text("3")
        self.runs([{"databaseId": 9, "displayTitle": "cli 43485738320-2"}])
        result = self.run_script("start", DIGEST)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "9\n")
        self.assertEqual(len(self.calls("run", "list")), 4)

    def test_start_without_a_run(self):
        self.runs([{"databaseId": 7, "displayTitle": "cli 43485738320-1"}])
        result = self.run_script("start", DIGEST)
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not start a run named 'cli 43485738320-2'", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_start_fails_when_the_dispatch_is_refused(self):
        (self.state / "dispatch.fail").touch()
        self.runs([{"databaseId": 9, "displayTitle": "cli 43485738320-2"}])
        result = self.run_script("start", DIGEST)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.calls("run"), [])

    def test_start_refuses_a_bad_digest(self):
        for digest in ("", "latest", "sha256:abc", DIGEST + "\n-f repo=x"):
            with self.subTest(digest=digest):
                result = self.run_script("start", digest)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.calls(), [])

    def test_start_needs_its_environment(self):
        result = self.run_script("start", DIGEST, STAGE_ID="")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    # ---- wait ----

    def test_wait_finished(self):
        self.view(QUEUED, RUNNING, finished("success"))
        result = self.run_script("wait", "9", "5", "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls("run", "download"),
                         [["run", "download", "9", "--repo", BUILDER, "--name", "gpu-result", "--dir", "out"]])
        self.assertEqual(self.done(), "done=true\n")
        self.assertEqual(len(self.calls("run", "view")), 3)

    def test_wait_failed_build(self):
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral"):
            with self.subTest(conclusion):
                (self.state / "view.n").unlink(missing_ok=True)
                self.view(finished(conclusion))
                result = self.run_script("wait", "9", "5", "out")
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"ended as '{conclusion}'", result.stderr)
                self.assertEqual(self.calls("run", "download"), [])
                self.assertEqual(self.done(), "")

    def test_wait_fails_when_the_result_cannot_be_downloaded(self):
        (self.state / "download.fail").touch()
        self.view(finished("success"))
        result = self.run_script("wait", "9", "5", "out")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.done(), "")

    def test_wait_still_running(self):
        self.view(QUEUED)
        result = self.run_script("wait", "9", "0", "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.done(), "done=false\n")
        self.assertEqual(self.calls("run", "download"), [])
        self.assertIn("still 'queued'", result.stderr)

    def test_wait_counts_minutes(self):
        """Two polls one second apart fit into one minute."""
        self.view(RUNNING, RUNNING, finished("success"))
        result = self.run_script("wait", "9", "1", "out", GPU_REQUEST_POLL_SECONDS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.done(), "done=true\n")

    def test_wait_survives_failed_polls(self):
        self.view("error", "error", "error", "error", RUNNING, "error", "error", "error", "error", finished("success"))
        result = self.run_script("wait", "9", "5", "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.done(), "done=true\n")

    def test_wait_gives_up_when_github_stays_unreachable(self):
        self.view("error")
        result = self.run_script("wait", "9", "5", "out")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot read the state of run 9", result.stderr)
        self.assertEqual(len(self.calls("run", "view")), 5)
        self.assertEqual(self.done(), "")

    def test_bad_arguments(self):
        for args in (("wait", "9; rm", "5", "out"), ("wait", "9", "soon", "out"), ("wait", "9", "5"), ("cancel", "x")):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.calls(), [])
        self.assertEqual(self.run_script().returncode, 2)
        self.assertEqual(self.run_script("stop", "9").returncode, 2)

    def test_cancel(self):
        self.assertEqual(self.run_script("cancel", "9").returncode, 0)
        self.assertEqual(self.calls("run", "cancel"), [["run", "cancel", "9", "--repo", BUILDER]])


if __name__ == "__main__":
    unittest.main()
