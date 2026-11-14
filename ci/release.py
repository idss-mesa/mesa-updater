#!/usr/bin/env python3
"""Plan, guard and publish a release of a MESA image (ci/README.md, "release.py").

  release.py plan    [--tag-prefix P] [--skip-gpu]
  release.py guard   [--tag-prefix P] [--skip-gpu] --ref REF --github-repo OWNER/NAME
  release.py publish [--tag-prefix P] [--skip-gpu] --ref REF --out DIR --revision SHA ...

Run from the image repo's root (or pass --repo-root). Reads mesa.env and
VERSION. Registry access goes through `crane`, `cosign` and attach_sbom.sh,
GitHub through `gh`; this file reads no credentials itself.
"""
import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# What each architecture publishes. ci/mesa-ci.sh has the same list.
VARIANTS = {"amd64": ("cpu", "sandbox", "gpu", "gpu-sandbox"), "arm64": ("cpu",)}
# The variant each one is built FROM (same architecture).
PARENT = {"sandbox": "cpu", "gpu": "cpu", "gpu-sandbox": "gpu"}
TEST_PREFIX = re.compile(r"ci-test-(?:[a-z0-9]+-)+")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
IMAGE = re.compile(r"[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+")
GITHUB_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
MAIN = "refs/heads/main"
# The statuses sbom_crosscheck.py fails on.
FORWARD_FAILURES = ("missing", "version-mismatch", "hash-mismatch")


class Fail(Exception):
    """The release cannot go on (exit 1)."""


class BadInput(Exception):
    """Bad arguments or repo files (exit 2)."""


def say(text):
    print(f"release: {text}", flush=True)


# ---- plan ---------------------------------------------------------------

def read_env(path):
    """KEY=value lines of mesa.env; the last definition of a key wins."""
    values = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise BadInput(f"{path}: {e.strerror}") from e
    for line in text.splitlines():
        m = re.fullmatch(r"([A-Z_][A-Z0-9_]*)=(.*)", line)
        if m:
            value = m.group(2)
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            values[m.group(1)] = value
    return values


def make_plan(root, prefix, skip_gpu):
    if prefix and not TEST_PREFIX.fullmatch(prefix):
        raise BadInput(f"tag prefix '{prefix}' must be empty (a real release) or look like ci-test-<word>-")
    env = read_env(root / "mesa.env")
    image, arches = env.get("MESA_IMAGE", ""), env.get("MESA_ARCHES", "").split()
    if not IMAGE.fullmatch(image):
        raise BadInput(f"mesa.env: MESA_IMAGE '{image}' is not <registry>/<repository>")
    if not arches or len(set(arches)) != len(arches) or any(a not in VARIANTS for a in arches):
        raise BadInput(f"mesa.env: MESA_ARCHES must list amd64 and/or arm64 once each, found '{' '.join(arches)}'")
    try:
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
    except OSError as e:
        raise BadInput(f"{root / 'VERSION'}: {e.strerror}") from e
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise BadInput(f"VERSION must be X.Y.Z, found '{version}'")
    release = f"{prefix}v{version}"
    images = []
    for arch in arches:
        for variant in VARIANTS[arch]:
            if skip_gpu and variant.startswith("gpu"):
                continue
            # amd64 is the platform every app runs on; other platforms are named.
            suffix = ("" if variant == "cpu" else f"-{variant}") + ("" if arch == "amd64" else f"-{arch}")
            images.append({"variant": variant, "arch": arch, "tag": release + suffix})
    return {"image": image, "name": image.rsplit("/", 1)[1], "version": version, "release": release,
            "test": bool(prefix), "arches": arches, "images": images}


# ---- tools --------------------------------------------------------------

def run(argv, what, check=True):
    """Run a tool; return (exit code, stdout). stderr goes to ours."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, text=True, check=False)
    except OSError as e:
        raise Fail(f"cannot run {argv[0]}: {e.strerror}") from e
    if check and proc.returncode != 0:
        raise Fail(f"{what} failed (exit {proc.returncode})")
    return proc.returncode, proc.stdout


def absent_or(argv, what, absent_markers):
    """Run a lookup. Return stdout, or None when the tool says the thing does not exist.

    Any other failure stops the release: "the registry did not answer" must
    never read as "the tag is free".
    """
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except OSError as e:
        raise Fail(f"cannot run {argv[0]}: {e.strerror}") from e
    if proc.returncode == 0:
        return proc.stdout
    if any(marker in proc.stderr for marker in absent_markers):
        return None
    sys.stderr.write(proc.stderr)
    raise Fail(f"{what} failed (exit {proc.returncode})")


def tag_digest(args, ref):
    """Digest a tag or digest reference resolves to, or None when it does not exist."""
    out = absent_or([args.crane, "digest", ref], f"crane digest {ref}", ("NOT_FOUND:", "MANIFEST_UNKNOWN:"))
    if out is None:
        return None
    digest = out.strip()
    if not DIGEST.fullmatch(digest):
        raise Fail(f"crane digest {ref} printed '{digest[:80]}', not a digest")
    return digest


def gh_api(args, path):
    """GET a GitHub API path as JSON, or None on 404."""
    out = absent_or([args.gh, "api", path], f"gh api {path}", ("HTTP 404",))
    return None if out is None else json.loads(out)


def published_release(args, repo, release):
    """The published (not draft) GitHub release with this tag, or None."""
    return gh_api(args, f"repos/{repo}/releases/tags/{release}")


# ---- guard --------------------------------------------------------------

def check_refs(plan, args):
    """What may run where: a real release and every GPU build come from main only."""
    release = plan["release"]
    if not plan["test"]:
        if args.ref != MAIN:
            raise Fail(f"{release} can only be released from {MAIN}, not {args.ref} "
                       "(a test run needs a ci-test- tag prefix)")
        if args.skip_gpu:
            raise Fail(f"{release} needs its GPU variants; only a test run may skip them")
    elif not args.skip_gpu and args.ref != MAIN:
        raise Fail(f"the GPU builder only builds commits on main: a test run from {args.ref} "
                   "must leave the GPU variants out (gpu: false / --skip-gpu)")


def cmd_guard(args):
    plan = make_plan(args.repo_root, args.tag_prefix, args.skip_gpu)
    image, release = plan["image"], plan["release"]
    if not GITHUB_REPO.fullmatch(args.github_repo):
        raise BadInput(f"--github-repo '{args.github_repo}' is not OWNER/NAME")
    check_refs(plan, args)

    found = {}
    for entry in plan["images"]:
        digest = tag_digest(args, f"{image}:{entry['tag']}")
        if digest:
            found[entry["tag"]] = digest
    listing = ", ".join(f"{tag} ({digest[:19]})" for tag, digest in found.items())

    state = "new"
    if plan["test"]:
        if found:
            raise Fail(f"test tags already exist in {image}: {listing}. Delete them or use another prefix")
    else:
        published = published_release(args, args.github_repo, release)
        git_tag = gh_api(args, f"repos/{args.github_repo}/git/ref/tags/{release}")
        if published and len(found) == len(plan["images"]):
            _, text = run([args.gh, "release", "download", release, "--repo", args.github_repo,
                           "--pattern", "release-manifest.json", "--output", "-"],
                          f"reading release-manifest.json of the GitHub release {release}")
            try:
                recorded = {e["tag"]: e["digest"] for e in json.loads(text)["images"]}
            except (ValueError, KeyError, TypeError):
                recorded = None
            if recorded != found:
                raise Fail(f"{release} is published, but its release-manifest.json does not match the tags in "
                           f"{image} ({listing}). This needs a person to look at it")
            state = "released"
        elif published or found or git_tag:
            parts = [f"tags in {image}: {listing}" if found else f"no tags in {image}",
                     "a GitHub release" if published else "no GitHub release",
                     "a git tag" if git_tag else "no git tag"]
            raise Fail(f"{release} is partly published ({'; '.join(parts)}). Use \"Re-run failed jobs\" on the "
                       "run that started it: that finishes the same build. A new run, or \"Re-run all jobs\", "
                       "cannot (it would build other digests, and this check stops it). If that run cannot be "
                       "finished, release the next patch version instead")

    say(f"{release}: {state}" + ("" if state == "new" else " (nothing to do)"))
    for entry in plan["images"]:
        say(f"  {image}:{entry['tag']}  {entry['variant']} {entry['arch']}")
    outputs = {"state": state, "release": release, "image": image, "test": str(plan["test"]).lower(),
               "arches": json.dumps(plan["arches"])}
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as f:
            for key, value in outputs.items():
                f.write(f"{key}={value}\n")
    return 0


# ---- publish ------------------------------------------------------------

def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise Fail(f"{what}: {path}: {e.strerror}") from e
    except ValueError as e:
        raise Fail(f"{what}: {path} is not JSON ({e})") from e


def load_staged(plan, out, revision):
    """Read out/<variant>-<arch>/ for every planned image and check it is this release's."""
    staged = []
    for entry in plan["images"]:
        key = f"{entry['variant']}-{entry['arch']}"
        directory = out / key
        try:
            digest = (directory / "digest").read_text(encoding="utf-8").strip()
        except OSError as e:
            raise Fail(f"{key}: no pushed digest ({directory / 'digest'}: {e.strerror})") from e
        if not DIGEST.fullmatch(digest):
            raise Fail(f"{key}: {directory / 'digest'} holds '{digest[:80]}', not a digest")
        sbom_path = directory / "image.cdx.json"
        sbom = load_json(sbom_path, f"{key}: SBOM")
        meta = sbom.get("metadata") if isinstance(sbom, dict) else None
        component = (meta or {}).get("component") or {}
        props = {p.get("name"): p.get("value") for p in (meta or {}).get("properties") or []}
        expected = {"image name": (component.get("name"), plan["image"]),
                    "image digest": (component.get("version"), digest),
                    "mesa:version": (props.get("mesa:version"), f"v{plan['version']}"),
                    "mesa:variant": (props.get("mesa:variant"), entry["variant"]),
                    "mesa:arch": (props.get("mesa:arch"), entry["arch"]),
                    "mesa:revision": (props.get("mesa:revision"), revision)}
        for field, (got, want) in expected.items():
            if got != want:
                raise Fail(f"{key}: the SBOM is for another build: {field} is '{got}', expected '{want}'")
        report = load_json(directory / "report.json", f"{key}: cross-check report")
        try:
            forward = report["summary"]["forward"]
            failed = sum(int(forward.get(status, 0)) for status in FORWARD_FAILURES)
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise Fail(f"{key}: {directory / 'report.json'} has no forward summary") from e
        if failed:
            raise Fail(f"{key}: the cross-check found {failed} lock entries that are not in the image as locked")
        base = None
        if entry["variant"] in PARENT:
            try:
                base = (directory / "base").read_text(encoding="utf-8").strip()
            except OSError as e:
                raise Fail(f"{key}: the build did not record the digest it was built on "
                           f"({directory / 'base'}: {e.strerror})") from e
        staged.append({**entry, "digest": digest, "sbom": sbom_path, "document": sbom, "base": base,
                       "ref": f"{plan['image']}@{digest}"})
    digests = [s["digest"] for s in staged]
    if len(set(digests)) != len(digests):
        raise Fail("two variants were staged with the same digest: " + ", ".join(sorted(digests)))
    by_variant = {(s["variant"], s["arch"]): s["digest"] for s in staged}
    for item in staged:
        below = by_variant.get((PARENT.get(item["variant"]), item["arch"]))
        if item["base"] != below:
            raise Fail(f"{item['variant']} {item['arch']} was built on {item['base']}, but the staged "
                       f"{PARENT[item['variant']]} image of this release is {below}")
    return staged


def verify_args(args):
    if args.cosign_key:
        return ["--key", args.cosign_key, "--insecure-ignore-tlog"]
    # The identity is the shared workflow file; repository, ref and commit are
    # those of the image repo's run that called it.
    return ["--certificate-oidc-issuer", OIDC_ISSUER,
            "--certificate-identity-regexp", args.identity_regexp,
            "--certificate-github-workflow-repository", args.github_repo,
            "--certificate-github-workflow-ref", args.ref,
            "--certificate-github-workflow-sha", args.revision]


def attestation(args, item):
    """What cosign finds on the image:

    "ok"          a verified CycloneDX attestation whose predicate is this SBOM
    "other"       verified attestations, none of them carrying this SBOM
    "unverified"  nothing that verifies (nothing attached, or cosign failed)
    """
    try:
        proc = subprocess.run([args.cosign, "verify-attestation", "--type", "cyclonedx", *verify_args(args),
                               item["ref"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    except OSError as e:
        raise Fail(f"cannot run {args.cosign}: {e.strerror}") from e
    if proc.returncode != 0:
        item["verify_error"] = proc.stderr.strip()[-2000:]
        return "unverified"
    hexdigest = item["digest"].split(":", 1)[1]
    for line in proc.stdout.splitlines():
        try:
            envelope = json.loads(line)
            statement = json.loads(base64.b64decode(envelope["payload"]))
            subjects = {s["digest"]["sha256"] for s in statement["subject"]}
            if (statement["predicateType"] == CYCLONEDX_PREDICATE and hexdigest in subjects
                    and statement["predicate"] == item["document"]):
                return "ok"
        except (ValueError, KeyError, TypeError):
            continue
    item["verify_error"] = "verified attestations exist, but none carries this SBOM"
    return "other"


def attest(args, item):
    """Make sure the image carries a verified attestation of its SBOM; sign only when none can exist yet."""
    label = f"{item['tag']} ({item['digest'][:19]})"
    state = attestation(args, item)
    if state == "ok":
        say(f"{label}: SBOM attestation already there and verified")
        return
    if state == "unverified":
        # An earlier attempt may have pushed an attestation and died before
        # writing the tag cosign finds it by. Rewrite that tag from what the
        # registry has (no signing) and look again. Exit 3: nothing attached.
        code, _ = run([args.attach, "--index-only", item["ref"]], "attach_sbom.sh --index-only", check=False)
        if code == 0:
            state = attestation(args, item)
            if state == "ok":
                say(f"{label}: SBOM attestation found after rewriting its index; verified")
                return
            if state == "unverified":
                sys.stderr.write(item.get("verify_error", "") + "\n")
                raise Fail(f"{label}: something is attached to {item['ref']} but nothing verifies. Not signing "
                           "again: find out why verification fails first")
        elif code != 3:
            raise Fail(f"attach_sbom.sh --index-only {item['ref']} failed (exit {code})")
    run([args.attach, item["ref"], str(item["sbom"])], f"attach_sbom.sh {item['ref']}")
    if attestation(args, item) != "ok":
        sys.stderr.write(item.get("verify_error", "") + "\n")
        raise Fail(f"{label}: the SBOM was attached but does not verify")
    say(f"{label}: SBOM attested and verified")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_release_dir(args, plan, staged, directory):
    if directory.exists():
        # Only ever a directory this function made before.
        if any(directory.iterdir()) and not (directory / "release-manifest.json").is_file():
            raise Fail(f"{directory} exists and is not a release directory; move it away")
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    images = []
    for item in staged:
        name = f"{plan['name']}-{item['tag']}.cdx.json"
        shutil.copyfile(item["sbom"], directory / name)
        images.append({"tag": item["tag"], "variant": item["variant"], "arch": item["arch"],
                       "digest": item["digest"], "sbom": name, "sbom_sha256": sha256_file(directory / name)})
    manifest = {"image": plan["image"], "release": plan["release"], "version": plan["version"],
                "revision": args.revision, "images": images}
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    names = sorted(p.name for p in directory.iterdir())
    (directory / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(directory / n)}  {n}\n" for n in names), encoding="utf-8")

    if args.cosign_key:
        check = "  --key <public key> --insecure-ignore-tlog \\\n"
    else:
        check = (f"  --certificate-oidc-issuer {OIDC_ISSUER} \\\n"
                 f"  --certificate-identity-regexp '{args.identity_regexp}' \\\n"
                 f"  --certificate-github-workflow-repository {args.github_repo} \\\n"
                 f"  --certificate-github-workflow-ref {args.ref} \\\n"
                 f"  --certificate-github-workflow-sha {args.revision} \\\n")
    rows = "\n".join(f"| `{plan['image']}:{i['tag']}` | {i['variant']} | {i['arch']} | `{i['digest']}` | `{i['sbom']}` |"
                     for i in images)
    first = staged[0]
    notes = f"""Images of {plan['release']}, built from the lock files at {args.revision}.

| Image | Variant | Platform | Digest | SBOM |
|---|---|---|---|---|
{rows}

Each SBOM (CycloneDX 1.6) is attached here and attested to its image digest in the registry.
`SHA256SUMS` covers the SBOMs and `release-manifest.json` (tag to digest).

Check an image against its attestation with [cosign](https://docs.sigstore.dev/cosign/):

```
cosign verify-attestation --type cyclonedx \\
{check}  {first['ref']}
```

The certificate names the workflow that signed, the repository and branch it ran for, and the commit above.
"""
    (directory / "notes.md").write_text(notes, encoding="utf-8")
    return [directory / n for n in names + ["SHA256SUMS"]]


def github_release(args, plan, directory, assets):
    release, repo = plan["release"], args.github_repo
    describe = ["--target", args.revision, "--title", f"{plan['name']} {release}",
                "--notes-file", str(directory / "notes.md")]
    files = [str(p) for p in assets]
    # `gh release view` also finds a draft (the tags API does not list drafts).
    out = absent_or([args.gh, "release", "view", release, "--repo", repo, "--json", "tagName,isDraft"],
                    f"gh release view {release}", ("release not found",))
    if out is None:
        draft = ["--draft", "--prerelease"] if plan["test"] else []
        run([args.gh, "release", "create", release, "--repo", repo, *describe, *draft, *files], "gh release create")
        say(f"GitHub release {release} created" + (" (draft: this is a test run)" if plan["test"] else ""))
    else:
        try:
            is_draft = bool(json.loads(out)["isDraft"])
        except (ValueError, KeyError, TypeError) as e:
            raise Fail(f"gh release view {release} did not say whether it is a draft") from e
        say(f"GitHub release {release} exists" + (" as a draft" if is_draft else "") + ": uploading its files again")
        run([args.gh, "release", "upload", release, "--repo", repo, "--clobber", *files], "gh release upload")
        if is_draft and not plan["test"]:
            # Left by an attempt that died while uploading, or written by hand.
            run([args.gh, "release", "edit", release, "--repo", repo, "--draft=false", *describe], "gh release edit")
            say(f"GitHub release {release} published")
    if plan["test"]:
        return
    # A real release is done when it is published and its git tag is on this commit.
    if published_release(args, repo, release) is None:
        raise Fail(f"the GitHub release {release} is not published")
    tag = gh_api(args, f"repos/{repo}/git/ref/tags/{release}")
    try:
        target = tag["object"]["sha"] if tag else None
    except (KeyError, TypeError):
        target = None
    if target != args.revision:
        raise Fail(f"the git tag {release} is {'missing' if target is None else 'on ' + str(target)}; "
                   f"it must be on {args.revision}")


def cmd_publish(args):
    plan = make_plan(args.repo_root, args.tag_prefix, args.skip_gpu)
    image, release = plan["image"], plan["release"]
    if not REVISION.fullmatch(args.revision):
        raise BadInput(f"--revision '{args.revision}' is not a full commit SHA")
    if args.github_repo and not GITHUB_REPO.fullmatch(args.github_repo):
        raise BadInput(f"--github-repo '{args.github_repo}' is not OWNER/NAME")
    if not args.cosign_key and not (args.identity_regexp and args.github_repo and args.ref):
        raise BadInput("publish needs --identity-regexp, --github-repo and --ref (keyless), or --cosign-key")
    if not plan["test"] and (args.cosign_key or args.no_github_release):
        raise Fail(f"{release} is a real release: it needs keyless signing and a GitHub release")
    if args.ref:
        check_refs(plan, args)

    # 1. Everything that can be checked without writing is checked first.
    staged = load_staged(plan, args.out, args.revision)
    for item in staged:
        if tag_digest(args, item["ref"]) != item["digest"]:
            raise Fail(f"{item['variant']} {item['arch']}: {item['ref']} is not in the registry")
        _, text = run([args.crane, "config", "--platform", f"linux/{item['arch']}", item["ref"]],
                      f"crane config {item['ref']}")
        try:
            config = json.loads(text)
            platform = (config["os"], config["architecture"])
            item["layers"] = [str(layer) for layer in config["rootfs"]["diff_ids"]]
        except (ValueError, KeyError, TypeError) as e:
            raise Fail(f"{item['variant']} {item['arch']}: cannot read the image config of {item['ref']}") from e
        if platform != ("linux", item["arch"]):
            raise Fail(f"{item['variant']} {item['arch']}: {item['ref']} is a {platform[0]}/{platform[1]} image")
        item["tagged"] = tag_digest(args, f"{image}:{item['tag']}")
        if item["tagged"] not in (None, item["digest"]):
            raise Fail(f"{image}:{item['tag']} already exists with another digest ({item['tagged']}); "
                       f"this build is {item['digest']}")

    # A variant must sit on the staged image below it, not on some other build.
    layers = {(item["variant"], item["arch"]): item["layers"] for item in staged}
    for item in staged:
        below = layers.get((PARENT.get(item["variant"]), item["arch"]))
        if below is not None and (len(item["layers"]) <= len(below) or item["layers"][:len(below)] != below):
            raise Fail(f"{item['variant']} {item['arch']}: {item['ref']} is not built on the staged "
                       f"{PARENT[item['variant']]} image of this release")

    # 2. Attest every SBOM to its digest, and prove it can be verified.
    for item in staged:
        attest(args, item)

    # 3. Only now do the release tags appear. Each is looked at again just
    # before it is written; the registry's own rule that v* tags cannot be
    # moved is what makes this final.
    for item in staged:
        ref = f"{image}:{item['tag']}"
        now = tag_digest(args, ref)
        if now is None:
            run([args.crane, "tag", item["ref"], item["tag"]], f"crane tag {ref}")
        elif now != item["digest"]:
            raise Fail(f"{ref} now points at {now}: someone else tagged it while this run was attesting")
    for item in staged:
        ref = f"{image}:{item['tag']}"
        if tag_digest(args, ref) != item["digest"]:
            raise Fail(f"{ref} does not point at {item['digest']} after tagging")
        say(f"{ref} -> {item['digest']}")

    # 4. Release files, then the GitHub release (which creates the git tag).
    directory = args.out / "release"
    assets = write_release_dir(args, plan, staged, directory)
    say(f"release files written to {directory}")
    if args.github_repo and not args.no_github_release:
        github_release(args, plan, directory, assets)
    elif not plan["test"]:
        raise Fail(f"{release} is tagged but has no GitHub release: run publish again with --github-repo")
    return 0


# ---- main ---------------------------------------------------------------

def main(argv=None):
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p):
        p.add_argument("--repo-root", type=Path, default=Path("."), help="image repo checkout (default .)")
        p.add_argument("--tag-prefix", default="", help="ci-test-<word>- for a test run; empty for a real release")
        p.add_argument("--skip-gpu", action="store_true", help="leave the GPU variants out (test runs only)")
        p.add_argument("--crane", default="crane")
        p.add_argument("--gh", default="gh")

    p = sub.add_parser("plan", help="print what the release consists of, as JSON")
    common(p)

    p = sub.add_parser("guard", help="decide whether the release can start: prints new or released, fails otherwise")
    common(p)
    p.add_argument("--ref", required=True, help="git ref the workflow runs on (GITHUB_REF)")
    p.add_argument("--github-repo", required=True, metavar="OWNER/NAME")
    p.add_argument("--github-output", metavar="FILE", help="append state, release, image, test, arches (GITHUB_OUTPUT)")

    p = sub.add_parser("publish", help="attest the SBOMs, write the release tags, create the GitHub release")
    common(p)
    p.add_argument("--out", type=Path, required=True, help="directory with <variant>-<arch>/{digest,image.cdx.json,report.json}")
    p.add_argument("--revision", required=True, help="commit the images were built from")
    p.add_argument("--ref", default="", help="git ref the signing workflow ran on (GITHUB_REF)")
    p.add_argument("--github-repo", metavar="OWNER/NAME", help="repo that gets the GitHub release and whose workflow signed")
    p.add_argument("--identity-regexp", help="certificate identity of the signing workflow (keyless)")
    p.add_argument("--cosign-key", metavar="FILE", help="public key, for tests without Sigstore (COSIGN_KEY signs)")
    p.add_argument("--no-github-release", action="store_true", help="test runs only: stop after writing the release files")
    p.add_argument("--cosign", default="cosign")
    p.add_argument("--attach", default=str(here / "attach_sbom.sh"))

    args = ap.parse_args(argv)
    try:
        if args.command == "plan":
            print(json.dumps(make_plan(args.repo_root, args.tag_prefix, args.skip_gpu), indent=2))
            return 0
        return cmd_guard(args) if args.command == "guard" else cmd_publish(args)
    except BadInput as e:
        print(f"release: {e}", file=sys.stderr)
        return 2
    except Fail as e:
        print(f"release: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
