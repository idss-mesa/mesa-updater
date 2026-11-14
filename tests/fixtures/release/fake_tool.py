"""Stand-in for crane, cosign, gh and attach_sbom.sh, used by tests/test_release.py.

The test installs this file under each of those names and points FAKE_STATE at
a directory:

  log            every invocation, one JSON list [tool, arg, ...] per line
  fail           lines "<tool> <first argument>" or "<tool> <first> <second>":
                 that call fails with an error that does not mean "not found"
  registry.json  {"image": repository, "tags": {tag: digest}, "images": {digest: image config}}
  pushed/<hex>   attestations stored in the registry for that digest
  indexed/<hex>  the ones cosign can find (listed by the fallback tag); this is
                 what `cosign verify-attestation` prints
  attach.mode    what attach_sbom.sh does when it signs: ok (default), wrong
                 (another predicate), none (attaches nothing), unindexed (dies
                 before writing the fallback tag), fail
  attach.skip    digests for which attach_sbom.sh attaches nothing
  tag.lost       `crane tag` succeeds without writing the tag
  race.json      {tag: digest} written to the registry during the first
                 attach_sbom.sh call, as if someone else tagged meanwhile
  gh.json        {"repo": OWNER/NAME, "release": tag name, "published": bool, "draft": bool,
                  "git_tag": commit or null, "manifest": {...} or null}

A call that names another registry repository, GitHub repo or release than the
state does exits 64: the code under test asked for the wrong thing. Messages
and exit codes are the ones the real tools gave on 2026-11-13 (crane 0.22.1
against Harbor 2.9.0, cosign 3.1.4, gh 2.86).
"""
import base64
import json
import os
import shutil
import sys

state = os.environ["FAKE_STATE"]
tool = os.path.basename(sys.argv[0])
args = sys.argv[1:]


def path(*names):
    return os.path.join(state, *names)


def load(name, default):
    if not os.path.exists(path(name)):
        return default
    with open(path(name), encoding="utf-8") as f:
        return json.load(f)


def save(name, value):
    with open(path(name), "w", encoding="utf-8") as f:
        json.dump(value, f)


def text(name, default=""):
    if not os.path.exists(path(name)):
        return default
    with open(path(name), encoding="utf-8") as f:
        return f.read()


def stop(message, status=1):
    sys.stderr.write(message + "\n")
    sys.exit(status)


def wrong(what):
    stop(f"fake {tool}: asked for the wrong thing: {what}", 64)


def option(name):
    return args[args.index(name) + 1] if name in args else None


with open(path("log"), "a", encoding="utf-8") as log:
    log.write(json.dumps([tool] + args) + "\n")
failing = text("fail").splitlines()
if f"{tool} {args[0]}" in failing or " ".join([tool] + args[:2]) in failing:
    # Not a "not found": for gh an HTTP error other than 404.
    stop("gh: Server Error (HTTP 502)" if tool == "gh" else f"{tool}: simulated failure: connection reset by peer")

if tool == "crane":
    registry = load("registry.json", {"image": "", "tags": {}, "images": {}})

    def split(ref):
        """(digest, None) or (None, tag) of a reference into the expected repository."""
        sep = "@" if "@" in ref else ":"
        image, _, rest = ref.rpartition(sep)
        if image != registry["image"]:
            wrong(ref)
        return (rest, None) if sep == "@" else (None, rest)

    if args[0] == "digest":
        digest, tag = split(args[1])
        found = registry["tags"].get(tag) if tag else (digest if digest in registry["images"] else None)
        if not found:
            sys.stderr.write("2026/11/13 11:56:14 HEAD request failed, falling back on GET: HEAD "
                             "https://registry.test/v2/x/manifests/y: unexpected status code 404 Not Found\n")
            stop(f"Error: GET https://registry.test/v2/x/manifests/y: NOT_FOUND: artifact {args[1]} not found")
        print(found)
    elif args[0] == "config":
        if args[1] != "--platform":
            wrong("crane config without --platform")
        # A single image's config is returned whatever platform is asked for
        # (crane only uses --platform to pick from an index).
        print(json.dumps(registry["images"][split(args[3])[0]]))
    elif args[0] == "tag":
        digest, _ = split(args[1])
        if not os.path.exists(path("tag.lost")):  # tag.lost: the registry answers but the tag is not written
            registry["tags"][args[2]] = digest
            save("registry.json", registry)
    else:
        sys.exit(64)

elif tool == "cosign":
    if args[0] != "verify-attestation":
        sys.exit(64)
    hexdigest = args[-1].split("@sha256:", 1)[1]
    lines = text(os.path.join("indexed", hexdigest), None)
    if lines is None:
        stop("Error: no matching attestations: no attestations found")
    sys.stdout.write(lines)

elif tool == "attach_sbom.sh":
    os.makedirs(path("pushed"), exist_ok=True)
    os.makedirs(path("indexed"), exist_ok=True)
    if os.path.exists(path("race.json")):  # someone else writes tags while this run attests
        registry = load("registry.json", {})
        registry["tags"].update(load("race.json", {}))
        save("registry.json", registry)
        os.remove(path("race.json"))
    if args[0] == "--index-only":
        hexdigest = args[1].split("@sha256:", 1)[1]
        if not os.path.exists(path("pushed", hexdigest)):
            print("attach_sbom: the registry lists no referrer")
            sys.exit(3)
        shutil.copyfile(path("pushed", hexdigest), path("indexed", hexdigest))
        # Exit 3 too when none of the referrers is a CycloneDX attestation.
        for line in text(os.path.join("pushed", hexdigest)).splitlines():
            try:
                statement = json.loads(base64.b64decode(json.loads(line)["payload"]))
                if statement["predicateType"] == "https://cyclonedx.org/bom":
                    sys.exit(0)
            except (ValueError, KeyError, TypeError):
                pass
        sys.exit(3)
    mode = text("attach.mode", "ok").strip()
    if args[0].split("@", 1)[1] in text("attach.skip").split():
        mode = "none"
    if mode == "fail":
        stop("attach_sbom: cosign attest failed")
    if mode != "none":
        hexdigest = args[0].split("@sha256:", 1)[1]
        with open(args[1], encoding="utf-8") as f:
            predicate = json.load(f)
        if mode == "wrong":
            predicate = {"bomFormat": "CycloneDX", "components": []}
        statement = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://cyclonedx.org/bom",
                     "subject": [{"name": args[0].split("@", 1)[0], "digest": {"sha256": hexdigest}}],
                     "predicate": predicate}
        envelope = {"payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}
        with open(path("pushed", hexdigest), "a", encoding="utf-8") as f:
            f.write(json.dumps(envelope) + "\n")
        if mode == "unindexed":
            stop("attach_sbom: oras manifest push failed")
        shutil.copyfile(path("pushed", hexdigest), path("indexed", hexdigest))

elif tool == "gh":
    gh = load("gh.json", {})
    if args[0] == "api":
        prefix = f"repos/{gh.get('repo')}/"
        if args[1] == prefix + f"releases/tags/{gh.get('release')}":
            found = {"tag_name": gh["release"], "draft": False} if gh.get("published") else None
        elif args[1] == prefix + f"git/ref/tags/{gh.get('release')}":
            found = ({"ref": f"refs/tags/{gh['release']}", "object": {"type": "commit", "sha": gh["git_tag"]}}
                     if gh.get("git_tag") else None)
        else:
            wrong(args[1])
        if found is None:
            sys.stdout.write('{"message":"Not Found","status":"404"}')
            stop("gh: Not Found (HTTP 404)")
        print(json.dumps(found))
    elif args[0] == "release":
        if args[2] != gh.get("release") or option("--repo") != gh.get("repo"):
            wrong(" ".join(args))
        exists = gh.get("published") or gh.get("draft")
        if args[1] == "download":
            if gh.get("manifest") is None:
                stop("no assets match the file pattern")
            print(json.dumps(gh["manifest"]))
        elif args[1] == "view":
            if not exists:
                stop("release not found")
            fields = {"tagName": args[2], "isDraft": not gh.get("published")}
            print(json.dumps({k: fields[k] for k in (option("--json") or "").split(",") if k in fields}))
        elif args[1] == "create":
            if exists:
                stop("HTTP 422: Validation Failed: already_exists")
            if "--draft" in args:
                gh["draft"] = True
            else:  # an existing git tag is used as it is; --target only applies to a new one
                gh.update(published=True, git_tag=gh.get("git_tag") or option("--target"))
            save("gh.json", gh)
        elif args[1] == "upload":
            if not exists:
                stop("release not found")
        elif args[1] == "edit":
            if not exists:
                stop("release not found")
            if "--draft=false" in args:
                gh.update(published=True, draft=False, git_tag=gh.get("git_tag") or option("--target"))
                save("gh.json", gh)
        else:
            sys.exit(64)
    else:
        sys.exit(64)

else:
    sys.exit(64)
