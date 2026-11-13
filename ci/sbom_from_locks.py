#!/usr/bin/env python3
"""Write a CycloneDX 1.6 SBOM with one component per lock entry of an image variant.

Inputs and output are specified in ci/README.md ("Inputs kept in each image
repo" and "sbom_from_locks.py"). Stdlib only, Python >= 3.10.
"""
import argparse
import base64
import json
import os
import re
import shlex
import sys
from urllib.parse import quote, unquote, urlsplit

VARIANTS = {
    "cpu": ["cpu"],
    "sandbox": ["cpu", "sandbox"],
    "gpu": ["cpu", "gpu"],
    "gpu-sandbox": ["cpu", "gpu", "sandbox"],
}
LAYERS = ("cpu", "gpu", "sandbox")
ARCHES = ("amd64", "arm64")
NO_PREFIX_KINDS = ("base", "pins")
NPM_CPU = {"amd64": "x64", "arm64": "arm64"}
HASH_ALGS = {"md5": ("MD5", 32), "sha1": ("SHA-1", 40), "sha256": ("SHA-256", 64),
             "sha384": ("SHA-384", 96), "sha512": ("SHA-512", 128)}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
PIN_HASH_RE = re.compile(r"(?:[0-9a-f]{64}){1,2}")  # SHA-256 or SHA-512, told apart by length


def printable(text):
    return "".join(c if c.isprintable() else "?" for c in text)


def shown(text, limit=80):
    """File content quoted in an error message: the start of it is enough."""
    text = str(text)
    return text if len(text) <= limit else text[:limit] + "..."


class LockError(Exception):
    """Malformed input; the message starts with file:line and is one printable line."""

    def __init__(self, path, line, msg):
        super().__init__(printable(f"{path}:{line}: {msg}"))


def in_repo(rel):
    return not os.path.isabs(rel) and ".." not in rel.split("/")


def read_text(root, rel, ref):
    """Read a repo file; ref is the (file, line) that names it, for the error."""
    top, path = os.path.realpath(root), os.path.realpath(os.path.join(root, rel))
    # Lock files are repo content; a path or symlink that leaves the checkout
    # would put some other file of the CI host into the SBOM and the job log.
    if not in_repo(rel) or os.path.commonpath([top, path]) != top:
        raise LockError(ref[0], ref[1], f"file '{rel}' is not a path inside the repo")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as e:
        raise LockError(ref[0], ref[1], f"cannot read {rel}: {getattr(e, 'strerror', None) or e}")


def tsv_rows(text, path, ncols):
    """Yield (line number, columns) for each non-comment row."""
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) != ncols:
            raise LockError(path, n, f"expected {ncols} tab-separated columns, got {len(cols)}")
        if not all(cols):
            raise LockError(path, n, "empty column (write '-' for none)")
        yield n, cols


def enc(text):
    """Percent-encode a purl name segment or version: '@' -> %40, '+' -> %2B, ':' -> %3A."""
    return quote(text, safe="")


def make_purl(ptype, name, version, qualifiers=None):
    purl = f"pkg:{ptype}/" + "/".join(enc(s) for s in name.split("/")) + "@" + enc(version)
    if qualifiers:
        purl += "?" + "&".join(f"{k}={quote(v, safe='/:')}" for k, v in sorted(qualifiers.items()))
    return purl


def make_entry(key, name, version, purl, ctype="library", hashes=(), url=None, **extra):
    """One lock entry. key is the normalised name used by the layer-override rule."""
    return dict(key=key, name=name, version=version, purl=purl, type=ctype,
                hashes=list(hashes), url=url, **extra)


def check_hash(alg, digest, path, line):
    if alg not in HASH_ALGS or len(digest) != HASH_ALGS[alg][1]:
        raise LockError(path, line, f"bad {shown(alg)} hash '{shown(digest)}'")
    return HASH_ALGS[alg][0], digest


# --- Dockerfile ARGs (base, pins) -------------------------------------------

ARG_RE = re.compile(r"^\s*ARG\s+(.+)$", re.IGNORECASE)
IMAGE_RE = re.compile(r"(?P<repo>[^@\s]+?)(?::(?P<tag>[^:/@\s]+))?@sha256:(?P<hex>[0-9a-f]{64})")


def dockerfile_args(text, path):
    """ARG defaults as {name: (value, line)}; the last definition wins."""
    args = {}
    for n, line in enumerate(text.splitlines(), 1):
        m = ARG_RE.match(line)
        if not m:
            continue
        try:
            words = shlex.split(m.group(1))
        except ValueError as e:
            raise LockError(path, n, f"cannot parse ARG: {e}")
        for word in words:
            name, eq, value = word.partition("=")
            if eq:  # 'ARG NAME' alone re-declares, it does not change the default
                args[name] = (value, n)
    return args


def parse_base(text, row, ctx):
    entries, notes = [], []
    for name, (value, n) in dockerfile_args(text, row["file"]).items():
        if not name.endswith("_IMAGE"):
            continue
        m = IMAGE_RE.fullmatch(value)
        if not m:
            if "@" in value:  # written as a digest pin, but not a usable one
                raise LockError(row["file"], n, f"ARG {name}={shown(value)} is not pinned as "
                                "<repo>[:<tag>]@sha256:<64 hex>")
            # e.g. the BASE_IMAGE of gpu/Dockerfile: the CPU image of the same release
            notes.append((n, f"ARG {name}={shown(value)} has no digest and is not recorded"))
            continue
        repo, digest = m["repo"], "sha256:" + m["hex"]
        qualifiers = {"repository_url": repo}
        if m["tag"]:
            qualifiers["tag"] = m["tag"]
        purl = make_purl("oci", repo.rsplit("/", 1)[-1].lower(), digest, qualifiers)
        entries.append(make_entry(repo, repo, digest, purl, ctype="container"))
    # No digest-pinned image at all is fine (sandbox/Dockerfile only builds on
    # the image of the same release): the row then yields no component.
    if not entries and not notes:
        notes.append((1, "no *_IMAGE ARG: no base image is recorded"))
    for n, what in notes:
        print(printable(f"sbom_from_locks: {row['file']}:{n}: note: {what}"), file=sys.stderr)
    return entries


def parse_pins(text, row, ctx):
    entries, seen_names, seen_purls, dockerfiles = [], {}, {}, {}
    path = row["file"]
    for n, cols in tsv_rows(text, path, 10):
        name, layer, dockerfile, version_arg, hash_args, template, url, bin_path, probe, _source = cols
        if name in seen_names:
            raise LockError(path, n, f"pin '{name}' already defined on line {seen_names[name]}")
        seen_names[name] = n
        if layer not in LAYERS:
            raise LockError(path, n, f"unknown layer '{layer}'")
        if not template.startswith("pkg:") or "{version}" not in template:
            raise LockError(path, n, f"purl '{template}' is not a pkg: template with {{version}}")
        if bin_path != "-":
            if not bin_path.startswith("/"):
                raise LockError(path, n, f"path '{bin_path}' is not absolute")
            bin_path = bin_path.rstrip("/") or "/"  # like a locks.tsv prefix
        if not in_repo(dockerfile):
            raise LockError(path, n, f"dockerfile '{dockerfile}' is not a path inside the repo")
        if dockerfile not in dockerfiles:
            dockerfiles[dockerfile] = dockerfile_args(read_text(ctx["root"], dockerfile, (path, n)),
                                                      dockerfile)

        def arg(arg_name):
            value = dockerfiles[dockerfile].get(arg_name, ("", 0))[0]
            if not value:
                raise LockError(path, n, f"ARG {arg_name} has no default in {dockerfile}")
            return value

        version = arg(version_arg)
        if re.match(r"v\d", version):  # kept only where the template writes 'v{version}'
            version = version[1:]
        hashes = []
        if hash_args != "-":
            for pair in hash_args.split(","):
                arch, _, hash_arg = pair.partition("=")
                if arch not in ARCHES or not hash_arg:
                    raise LockError(path, n, f"hash_args '{hash_args}' is not amd64=<ARG>,arm64=<ARG>")
                digest = arg(hash_arg)
                if not PIN_HASH_RE.fullmatch(digest):
                    raise LockError(path, n, f"ARG {hash_arg}={shown(digest)} is not a SHA-256 "
                                    "(64 hex) or SHA-512 (128 hex) digest")
                if arch == ctx["arch"]:
                    hashes.append(("SHA-256" if len(digest) == 64 else "SHA-512", digest))
        purl = template.replace("{version}", enc(version))
        if purl in seen_purls:
            raise LockError(path, n, f"purl {purl} already used by pin '{seen_purls[purl]}'")
        seen_purls[purl] = name
        if layer not in ctx["layers"]:
            continue
        # The component version is what the purl says, so the two never disagree.
        purl_version = re.split(r"[?#]", purl)[0].rpartition("@")
        if purl_version[1]:
            version = unquote(purl_version[2])
        # The URL is a template ({version}, {arch}, ...), not an IRI: it is kept
        # as a property, never as an externalReferences entry.
        entries.append(make_entry(name, name, version, purl, ctype="application", hashes=hashes,
                                  template_url=None if url == "-" else url, layer=layer,
                                  path=None if bin_path == "-" else bin_path,
                                  probe=None if probe == "-" else probe))
    return entries


# --- pip ---------------------------------------------------------------------

PIP_REQ_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
                        r"(?:==\s*([^\s;]+)|@\s*(\S+))")
PIP_HASH_RE = re.compile(r"--hash=([a-z0-9]+):([0-9a-f]+)(?=\s|$)")
PIP_SKIP = ("--index-url", "--extra-index-url", "--find-links")
SDIST_EXTS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip")


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def version_from_url(url):
    """Version from a wheel or sdist file name, or None."""
    fname = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    version = None
    if fname.endswith(".whl"):
        parts = fname[:-4].split("-")
        if len(parts) in (5, 6):
            version = parts[1]
    else:
        for ext in SDIST_EXTS:
            if fname.endswith(ext) and "-" in fname[:-len(ext)]:
                version = fname[:-len(ext)].rsplit("-", 1)[1]
    return version if version and version[0].isdigit() else None


def parse_pip(text, row, ctx):
    entries, current = [], None
    path = row["file"]
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().rstrip("\\").rstrip()
        if not line or line.startswith("#") or line.startswith(PIP_SKIP):
            continue
        rest = line
        if not line.startswith("--hash="):
            m = PIP_REQ_RE.match(line)
            if not m:
                raise LockError(path, n, f"expected 'name==version' or 'name @ url', got '{shown(line)}'")
            name, version, url = pep503(m.group(1)), m.group(2), m.group(3)
            if url:
                version = version_from_url(url)
                if not version:
                    raise LockError(path, n, f"cannot read a version from the file name in {shown(url)}")
            current = make_entry(name, name, version, make_purl("pypi", name, version), url=url)
            entries.append(current)
            rest = line[m.end():].strip()
        elif current is None:
            raise LockError(path, n, "--hash before any requirement")
        hashes = PIP_HASH_RE.findall(rest)
        leftover = PIP_HASH_RE.sub("", rest).strip()
        if leftover and not leftover.startswith(";"):  # an environment marker is allowed
            raise LockError(path, n, f"unexpected text '{shown(leftover)}'")
        current["hashes"] += [check_hash(alg, digest, path, n) for alg, digest in hashes]
    return entries


# --- npm ---------------------------------------------------------------------

def platform_ok(allowed, value):
    """npm's os/cpu/libc rule: listed, or not excluded by a '!name' entry."""
    if not allowed or allowed == ["any"]:
        return True
    if "!" + value in allowed:
        return False
    positive = [a for a in allowed if not a.startswith("!")]
    return not positive or value in positive


def json_key_line(text, key):
    pos = text.find(json.dumps(key) + ":")
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


def parse_npm(text, row, ctx):
    path = row["file"]
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise LockError(path, e.lineno, f"invalid JSON: {e.msg}")
    except RecursionError:
        raise LockError(path, 1, "invalid JSON: nested too deeply")
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, dict) or doc.get("lockfileVersion") != 3:
        raise LockError(path, 1, "not a package-lock.json with lockfileVersion 3")
    entries = []
    for key, meta in packages.items():
        if "node_modules/" not in key:  # the root '' entry and workspace sources
            continue
        line = json_key_line(text, key)
        if not isinstance(meta, dict):
            raise LockError(path, line, f"'{shown(key)}' is not an object")
        if meta.get("link"):
            continue

        def field(name, many=False):
            """A string field ('' when absent); many: a list of strings, or one string."""
            value = meta.get(name)
            if many:
                value = [value] if isinstance(value, str) else [] if value is None else value
                ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
            else:
                value = "" if value is None else value
                ok = isinstance(value, str)
            if not ok:
                raise LockError(path, line, f"'{shown(key)}': {name} is not a "
                                + ("list of strings" if many else "string"))
            return value

        # An aliased install keeps the real package name in 'name'; the scanner
        # reads that name from the installed package.json too.
        name = field("name") or key.rsplit("node_modules/", 1)[1]
        version = meta.get("version")
        if not name or not isinstance(version, str) or not version:
            raise LockError(path, line, f"'{shown(key)}' has no version")
        # libc is honoured when the lock records it: the images are glibc.
        wanted = (("os", "linux"), ("cpu", NPM_CPU[ctx["arch"]]), ("libc", "glibc"))
        if not all([platform_ok(field(k, many=True), v) for k, v in wanted]):
            continue
        hashes = []
        for item in field("integrity").split():
            alg, _, b64 = item.partition("-")
            try:
                digest = base64.b64decode(b64, validate=True).hex()
            except ValueError:
                raise LockError(path, line, f"'{shown(key)}' has a bad integrity value")
            hashes.append(check_hash(alg, digest, path, line))
        entries.append(make_entry(name, name, version, make_purl("npm", name, version),
                                  hashes=hashes, url=field("resolved") or None))
    return entries


# --- conda, cran, vsix -------------------------------------------------------

CONDA_RE = re.compile(r"(?P<url>[a-z][a-z0-9+.-]*://[^\s#]+)"
                      r"#(?:sha256:(?P<sha256>[0-9a-f]{64})|(?P<md5>[0-9a-f]{32}))")


def parse_conda(text, row, ctx):
    entries, explicit = [], False
    path = row["file"]
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "@EXPLICIT":
            explicit = True
            continue
        if not explicit:
            raise LockError(path, n, "expected @EXPLICIT before the first URL")
        m = CONDA_RE.fullmatch(line)
        if not m:
            raise LockError(path, n, "expected '<url>#sha256:<64 hex>' or '<url>#<32 hex md5>'")
        parts = [unquote(p) for p in urlsplit(m["url"]).path.strip("/").split("/")]
        ext = next((e for e in (".conda", ".tar.bz2") if parts[-1].endswith(e)), None)
        stem = parts[-1][:-len(ext)].rsplit("-", 2) if ext else []
        if len(stem) != 3 or not all(stem) or len(parts) < 3:
            raise LockError(path, n, "URL is not <channel>/<subdir>/<name>-<version>-<build>"
                            f".conda|.tar.bz2: {shown(m['url'])}")
        name, version, build = stem
        purl = make_purl("conda", name, version, {"build": build, "channel": "/".join(parts[:-2]),
                                                  "subdir": parts[-2], "type": ext[1:]})
        digest = ("SHA-256", m["sha256"]) if m["sha256"] else ("MD5", m["md5"])
        entries.append(make_entry(name, name, version, purl, hashes=[digest], url=m["url"]))
    if not explicit:
        raise LockError(path, 1, "no @EXPLICIT line: not a conda explicit spec")
    return entries


def parse_cran(text, row, ctx):
    return [make_entry(name, name, version, make_purl("cran", name, version))
            for _, (name, version) in tsv_rows(text, row["file"], 2)]


def parse_vsix(text, row, ctx):
    entries = []
    for n, (ext_id, version, digest) in tsv_rows(text, row["file"], 3):
        if "." not in ext_id.strip("."):
            raise LockError(row["file"], n, f"'{ext_id}' is not publisher.name")
        if not SHA256_RE.fullmatch(digest):
            raise LockError(row["file"], n, f"'{digest}' is not a sha256")
        purl = make_purl("generic", ext_id, version, {"repository_url": "open-vsx.org"})
        entries.append(make_entry(ext_id, ext_id, version, purl, hashes=[("SHA-256", digest)]))
    return entries


PARSERS = {"base": parse_base, "pip": parse_pip, "npm": parse_npm, "conda": parse_conda,
           "pins": parse_pins, "cran": parse_cran, "vsix": parse_vsix}


# --- locks.tsv and the document ----------------------------------------------

def load_rows(root, locks):
    rows = []
    for n, (kind, layer, arch, file, prefix) in tsv_rows(read_text(root, locks, (locks, 1)), locks, 5):
        if kind not in PARSERS:
            raise LockError(locks, n, f"unknown kind '{kind}'")
        if layer not in LAYERS:
            raise LockError(locks, n, f"unknown layer '{layer}'")
        if arch != "*" and arch not in ARCHES:
            raise LockError(locks, n, f"unknown arch '{arch}'")
        if not in_repo(file):
            raise LockError(locks, n, f"file '{file}' is not a path inside the repo")
        if kind in NO_PREFIX_KINDS:
            if prefix != "-":
                raise LockError(locks, n, f"kind '{kind}' takes '-' as prefix")
            prefix = None
        elif not prefix.startswith("/"):
            raise LockError(locks, n, f"kind '{kind}' needs an absolute prefix, got '{prefix}'")
        else:
            prefix = prefix.rstrip("/") or "/"
        rows.append(dict(line=n, kind=kind, layer=layer, arch=arch, file=file, prefix=prefix))
    return rows


def collect(root, locks, variant, arch):
    """Lock entries of the variant after the layer-override rule, keyed by bom-ref."""
    layers = VARIANTS[variant]
    ctx = dict(root=root, arch=arch, layers=layers)
    entries = []
    for row in load_rows(root, locks):
        if row["layer"] not in layers or row["arch"] not in ("*", arch):
            continue
        text = read_text(root, row["file"], (locks, row["line"]))
        for entry in PARSERS[row["kind"]](text, row, ctx):
            entry.update(kind=row["kind"], file=row["file"], prefix=row["prefix"])
            entry.setdefault("layer", row["layer"])  # a pin carries its own layer
            entry["rank"] = (layers.index(entry["layer"]), row["line"])
            entries.append(entry)
    # Later layer wins per (kind, prefix, name); within a layer the later row
    # wins. Entries of one row never replace each other (npm nests versions).
    winner = {}
    for entry in entries:
        slot = (entry["kind"], entry["prefix"], entry["key"])
        winner[slot] = max(winner.get(slot, entry["rank"]), entry["rank"])
    by_ref = {}
    for entry in entries:
        if entry["rank"] == winner[(entry["kind"], entry["prefix"], entry["key"])]:
            ref = entry["purl"] + ("#" + entry["prefix"] if entry["prefix"] else "")
            by_ref[ref] = entry  # the same package twice in one lock is one component
    return by_ref


def component(ref, entry):
    comp = {"type": entry["type"], "bom-ref": ref, "name": entry["name"],
            "version": entry["version"], "purl": entry["purl"]}
    if entry["hashes"]:
        comp["hashes"] = [{"alg": a, "content": h} for a, h in sorted(set(entry["hashes"]))]
    if entry["url"]:
        comp["externalReferences"] = [{"type": "distribution", "url": entry["url"]}]
    props = [("kind", entry["kind"]), ("layer", entry["layer"]), ("file", entry["file"]),
             ("prefix", entry["prefix"]), ("path", entry.get("path")), ("probe", entry.get("probe")),
             ("url", entry.get("template_url"))]
    comp["properties"] = [{"name": "mesa:lock:" + k, "value": v} for k, v in props if v]
    return comp


def build(root, locks, variant, arch):
    by_ref = collect(root, locks, variant, arch)
    refs = sorted(by_ref, key=lambda r: (by_ref[r]["purl"], by_ref[r]["prefix"] or ""))
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [component(ref, by_ref[ref]) for ref in refs],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo-root", required=True, metavar="DIR", help="image repo checkout")
    ap.add_argument("--variant", required=True, choices=sorted(VARIANTS))
    ap.add_argument("--arch", required=True, choices=ARCHES)
    ap.add_argument("--locks", default="sbom/locks.tsv",
                    help="relative to the repo root (default: %(default)s)")
    ap.add_argument("-o", "--output", required=True, metavar="FILE", help="CycloneDX JSON to write")
    args = ap.parse_args(argv)
    try:
        doc = build(args.repo_root, args.locks, args.variant, args.arch)
    except LockError as e:
        print(f"sbom_from_locks: {e}", file=sys.stderr)
        return 2
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json.dumps(doc, indent=2) + "\n")
    except OSError as e:
        print(f"sbom_from_locks: {args.output}: {e.strerror}", file=sys.stderr)
        return 2
    counts = {}
    for comp in doc["components"]:
        kind = comp["properties"][0]["value"]
        counts[kind] = counts.get(kind, 0) + 1
    summary = ", ".join(f"{k} {counts[k]}" for k in PARSERS if k in counts) or "none"
    print(f"sbom_from_locks: {len(doc['components'])} components ({summary}) -> {args.output}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
