"""Stand-in for the docker CLI, used by tests/test_sbom_probe.py.

The test copies this file next to its canned data and passes it as --docker:

  log            every invocation's argv is appended here, one JSON list per line
  no-start       if present, "docker run" fails like a missing image
  run.mode       "hang": "docker run" never answers; "flood": it writes without
                 ever ending the line (absent: a well-behaved sh)
  conda.tar      bytes written for the conda-meta exec (absent: no output)
  conda.status   exit status of the conda-meta exec (absent: 0)
  outputs.json   {command: {"out": str, "status": int, "sleep": seconds}}
"""
import json
import os
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))


def data(name):
    path = os.path.join(here, name)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


args = sys.argv[1:]
with open(os.path.join(here, "log"), "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\n")

if args[0] == "run":
    if data("no-start") is not None:
        sys.exit(125)
    mode = (data("run.mode") or b"").decode().strip()
    if mode == "flood":
        sys.stdout.write("y" * 5_000_000)
        sys.stdout.flush()
    if mode:
        time.sleep(120)
    # Behave like "sh -s" idling on stdin: answer echo, exit at end of input.
    for line in sys.stdin:
        if line.startswith("echo "):
            print(line[5:].strip(), flush=True)
    sys.exit(0)

if args[0] == "exec":
    script = args[-1]
    if "conda-meta" in script:
        sys.stderr.write("tar: Removing leading `/' from member names\n")
        sys.stdout.buffer.write(data("conda.tar") or b"")
        sys.exit(int(data("conda.status") or 0))
    spec = json.loads(data("outputs.json"))[script]
    time.sleep(spec.get("sleep", 0))
    sys.stdout.write(spec.get("out", ""))
    sys.exit(spec.get("status", 0))

sys.exit(0)  # "rm -f"
