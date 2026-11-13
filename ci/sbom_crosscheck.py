#!/usr/bin/env python3
"""Check an image's scanner SBOM against its lock SBOM, in both directions.

Specified in ci/README.md ("sbom_crosscheck.py"). Stdlib only, Python >= 3.10.
Exit 0 = pass, 1 = check failed, 2 = bad input.
"""
import argparse
import json
import re
import sys
from collections import Counter
from urllib.parse import unquote

LAYERS = ("cpu", "gpu", "sandbox")
SCANNED_KINDS = ("pip", "npm", "cran")  # checked against scanner components
PREFIX_KINDS = SCANNED_KINDS + ("conda",)
UNCHECKED_KINDS = ("base", "vsix")
FORWARD = ("ok", "version-mismatch", "hash-mismatch", "missing", "unverifiable", "not-checked")
FAILURES = ("version-mismatch", "hash-mismatch", "missing")
REVERSE = ("lock", "pin", "base-layer", "allow", "mixed", "unexplained")
EXPLAINED = REVERSE[:4]  # what explains one location, strongest first
LOCATION_RE = re.compile(r"syft:location:\d+:path")
LAYER_RE = re.compile(r"syft:location:(\d+):layerID")
PREFIX_PROPS = ("mesa:lock:prefix", "mesa:probe:prefix")
SHOWN = 20  # unexplained components listed on the terminal; the report has all


# --- shared with sbom_merge.py (kept identical; tests compare the source) ---

class InputError(Exception):
    """Bad input (exit 2); the message starts with the file."""


def load_cdx(path):
    """A CycloneDX JSON document whose components are sound enough to index."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise InputError(f"{path}: {e.strerror}") from None
    except json.JSONDecodeError as e:
        raise InputError(f"{path}:{e.lineno}: invalid JSON: {e.msg}") from None
    except RecursionError:
        raise InputError(f"{path}: invalid JSON: nested too deeply") from None
    except UnicodeDecodeError as e:
        raise InputError(f"{path}: not UTF-8: {e.reason}") from None
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise InputError(f"{path}: not a CycloneDX document")
    if not isinstance(doc.setdefault("components", []), list):
        raise InputError(f"{path}: components is not a list")
    for i, comp in enumerate(doc["components"]):
        where = f"{path}: components[{i}]"
        if not isinstance(comp, dict) or not isinstance(comp.get("name"), str):
            raise InputError(f"{where} is not an object with a name")
        for field in ("purl", "bom-ref"):
            if not isinstance(comp.get(field, ""), str):
                raise InputError(f"{where}: {field} is not a string")
        for field in ("properties", "hashes", "externalReferences"):
            items = comp.get(field, [])
            if not isinstance(items, list) or not all(isinstance(x, dict) for x in items):
                raise InputError(f"{where}: {field} is not a list of objects")
    deps = doc.setdefault("dependencies", [])
    if not isinstance(deps, list) or not all(
            isinstance(d, dict) and isinstance(d.get("ref", ""), str)
            and isinstance(d.get("dependsOn", []), list) for d in deps):
        raise InputError(f"{path}: dependencies is not a list of objects with a ref and a dependsOn list")
    return doc


def parse_purl(purl):
    """(type, namespace, name, version, qualifiers), percent-decoded, or None.

    The name is normalised the way packages are compared: pypi per PEP 503,
    every other type exactly.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    rest, _, query = purl[4:].partition("#")[0].partition("?")
    ptype, _, path = rest.partition("/")
    version = ""
    at = path.rfind("@")
    if at > path.rfind("/"):  # an '@' before the last '/' is an unencoded npm scope
        path, version = path[:at], path[at + 1:]
    segments = [unquote(s) for s in path.split("/") if s]
    if not ptype or not segments:
        return None
    ptype, name = ptype.lower(), segments[-1]
    if ptype == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    qualifiers = {k: unquote(v) for k, _, v in (q.partition("=") for q in query.split("&")) if k}
    return ptype, "/".join(segments[:-1]), name, unquote(version), qualifiers


def props(comp, name):
    """String values of the properties called name, in document order."""
    return [p["value"] for p in comp.get("properties", [])
            if p.get("name") == name and isinstance(p.get("value"), str)]


def locations(comp):
    """Every syft:location:<n>:path of a scanner component."""
    return [p["value"] for p in comp.get("properties", [])
            if LOCATION_RE.fullmatch(str(p.get("name"))) and isinstance(p.get("value"), str)]


def containing(path, roots):
    """The roots that are path itself or a parent directory of it, longest first."""
    found = []
    while True:
        if path in roots:
            found.append(path)
        if path in ("/", ""):
            return found
        path = path.rpartition("/")[0] or "/"


def owner(path, prefixes):
    """The install prefix a path belongs to: the longest one that contains it.

    /opt/conda/envs/geospatial/... belongs to that env, not to /opt/conda, so
    nothing is matched across nested prefixes.
    """
    return next(iter(containing(path, prefixes)), None)


def pin_path(comp):
    """A pin's mesa:lock:path as containing() needs it: no trailing slash."""
    path = next(iter(props(comp, "mesa:lock:path")), None)
    return path and (path.rstrip("/") or "/")

# --- end of the shared block ---


def prop(comp, name):
    return next(iter(props(comp, name)), None)


def printable(text):
    return "".join(c if c.isprintable() else "?" for c in text)


def tsv_rows(path, ncols):
    """Yield (line number, columns) of a tab-separated file with '#' comments."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise InputError(f"{path}: {getattr(e, 'strerror', None) or e}") from None
    for n, line in enumerate(lines, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) != ncols:
            raise InputError(f"{path}:{n}: expected {ncols} tab-separated columns, got {len(cols)}")
        yield n, cols


def load_base_layers(path):
    layers = set()
    for n, (layer,) in tsv_rows(path, 1):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", layer):
            raise InputError(f"{path}:{n}: '{layer}' is not a sha256: diff ID")
        layers.add(layer)
    return layers


def load_allow(path):
    """allow.tsv as lookup tables; each rule is remembered as 'file:line: reason'."""
    allow = {"path": {}, "purl-type": {}, "purl": {}}
    for n, (rule, layer, value, reason) in tsv_rows(path, 4):
        if rule not in allow:
            raise InputError(f"{path}:{n}: unknown rule '{rule}' (path, purl-type, purl)")
        # The scanner reports layer digests, not layer names, so a rule cannot be
        # limited to its layer here: every rule covers the whole image.
        if layer != "*" and layer not in LAYERS:
            raise InputError(f"{path}:{n}: unknown layer '{layer}'")
        if not reason:
            raise InputError(f"{path}:{n}: a reason is required")
        why = f"{path}:{n}: {reason}"
        if rule == "path":
            if not value.startswith("/"):
                raise InputError(f"{path}:{n}: path '{value}' is not absolute")
            allow["path"][value.rstrip("/") or "/"] = why
        elif rule == "purl-type":
            if not re.fullmatch(r"[a-z][a-z0-9.+-]*", value):
                raise InputError(f"{path}:{n}: '{value}' is not a purl type")
            allow["purl-type"][value] = why
        else:
            purl = parse_purl(value)
            if not purl or "?" in value or "#" in value or not purl[3]:
                raise InputError(f"{path}:{n}: '{value}' is not pkg:<type>/<name>@<version or *> "
                                 "without qualifiers")
            allow["purl"].setdefault(purl[:3], {})[purl[3]] = why
    return allow


def bare(version):
    """Pins are compared without the 'v' that some purl templates and Go modules write."""
    return version[1:] if re.match(r"v\d", version) else version


def identity(comp, purl):
    """(names, versions) a component goes by; a pin's name need not be its purl's."""
    names, versions = {comp["name"]}, {bare(str(comp.get("version", "")))}
    if purl:
        names |= {purl[2], f"{purl[1]}/{purl[2]}".lstrip("/")}
        versions.add(bare(purl[3]))
    return names, versions - {""}


def located(comp):
    """(path, layer IDs) of every location of a scanner component: the layers are the
    syft:location:<n>:layerID values with the <n> of the path."""
    layers = {}
    for p in comp.get("properties", []):
        match = LAYER_RE.fullmatch(str(p.get("name")))
        if match:
            layers.setdefault(match.group(1), []).append(p.get("value"))
    return [(p["value"], layers.get(p["name"].split(":")[2], [])) for p in comp.get("properties", [])
            if LOCATION_RE.fullmatch(str(p.get("name"))) and isinstance(p.get("value"), str)]


def scanner_items(image, prefixes, pin_paths):
    """Scanner components as the checks need them. Files are ignored, and so is the
    operating-system entry: it is not a package and has no location, purl or layer."""
    items = []
    for comp in image["components"]:
        if comp.get("type") in ("file", "operating-system"):
            continue
        purl = parse_purl(comp.get("purl"))
        paths = locations(comp)
        items.append({
            "comp": comp, "purl": purl, "paths": paths,
            "name": purl[:3] if purl else None,
            "version": purl[3] if purl else str(comp.get("version", "")),
            "owners": {owner(p, prefixes) for p in paths} - {None},
            "pins": {root for p in paths for root in containing(p, pin_paths)},
            "located": located(comp),
        })
    return items


def lock_entries(locks, path):
    entries = []
    for i, comp in enumerate(locks["components"]):
        kind, prefix = prop(comp, "mesa:lock:kind"), prop(comp, "mesa:lock:prefix")
        purl = parse_purl(comp.get("purl"))
        where = f"{path}: components[{i}] ({comp.get('bom-ref')})"
        if not purl or kind not in PREFIX_KINDS + UNCHECKED_KINDS + ("pins",):
            raise InputError(f"{where}: not a lock component (needs a purl and a known mesa:lock:kind)")
        if kind in PREFIX_KINDS and not prefix:
            raise InputError(f"{where}: kind '{kind}' needs mesa:lock:prefix")
        entries.append({"comp": comp, "kind": kind, "purl": purl, "prefix": prefix,
                        "path": pin_path(comp), "probe": prop(comp, "mesa:lock:probe")})
    return entries


def sha256(comp):
    return next((h.get("content") for h in comp.get("hashes", []) if h.get("alg") == "SHA-256"), None)


def check_scanned(entry, by_name):
    """pip, npm, cran: a scanner component of that name located in the lock prefix."""
    found = sorted({item["version"] for item in by_name.get(entry["purl"][:3], [])
                    if entry["prefix"] in item["owners"]})
    if entry["purl"][3] in found:
        return "ok", ""
    if found:
        return "version-mismatch", "image has " + ", ".join(found)
    return "missing", f"no scanner component of that name under {entry['prefix']}"


def check_conda(entry, conda, have_probe):
    """conda: the probe's conda-meta record in the same prefix."""
    name, version, build = entry["purl"][2], entry["purl"][3], entry["purl"][4].get("build", "")
    found = conda.get((entry["prefix"], name), [])
    if not found:
        return "missing", (f"not in {entry['prefix']}/conda-meta" if have_probe
                           else "conda packages are only seen by the probe: no --probe-sbom given")
    for comp, purl in found:
        if (purl[3], purl[4].get("build", "")) == (version, build):
            ours, theirs = sha256(entry["comp"]), sha256(comp)
            if ours and theirs and ours != theirs:
                return "hash-mismatch", f"lock sha256 {ours}, image {theirs}"
            return "ok", ""
    return "version-mismatch", "image has " + ", ".join(
        f"{purl[3]} (build {purl[4].get('build', '?')})" for _, purl in found)


def check_pin(entry, results, by_pin):
    """pins: probe result ok, or a scanner component of that name and version under the path."""
    result = results.get(entry["purl"][:4])
    if result and result[0] == "ok":
        return "ok", "probe: " + result[1]
    names, versions = identity(entry["comp"], entry["purl"])
    found = set()
    for item in by_pin.get(entry["path"], []):
        item_names, item_versions = identity(item["comp"], item["purl"])
        if names & item_names:
            if versions & item_versions:
                return "ok", f"scanner component under {entry['path']}"
            found |= item_versions
    if found:
        return "version-mismatch", f"image has {', '.join(sorted(found))} under {entry['path']}"
    if result:
        return "version-mismatch", "probe: " + result[1]
    if not entry["probe"] and not entry["path"]:
        return "unverifiable", "the pin has neither a probe nor a path"
    return "missing", " and ".join(
        ([f"no probe result for '{entry['probe']}'"] if entry["probe"] else [])
        + ([f"no scanner component of that name under {entry['path']}"] if entry["path"] else []))


def forward_check(entries, items, probe):
    by_name, by_pin, conda, results = {}, {}, {}, {}
    for item in items:
        by_name.setdefault(item["name"], []).append(item)
        for root in item["pins"]:
            by_pin.setdefault(root, []).append(item)
    for comp in probe["components"] if probe else []:
        purl = parse_purl(comp.get("purl"))
        if not purl:
            continue
        if purl[0] == "conda" and prop(comp, "mesa:probe:prefix"):
            conda.setdefault((prop(comp, "mesa:probe:prefix"), purl[2]), []).append((comp, purl))
        if prop(comp, "mesa:probe:result"):
            # the output comes from inside the image: one line, nothing a terminal would interpret
            output = "".join(c if c.isprintable() else " " for c in prop(comp, "mesa:probe:output") or "")
            results[purl[:4]] = (prop(comp, "mesa:probe:result"), " ".join(output.split()))
    out = []
    for entry in entries:
        if entry["kind"] in SCANNED_KINDS:
            status, detail = check_scanned(entry, by_name)
        elif entry["kind"] == "conda":
            status, detail = check_conda(entry, conda, probe is not None)
        elif entry["kind"] == "pins":
            status, detail = check_pin(entry, results, by_pin)
        else:
            status, detail = "not-checked", "covered by the Dockerfile digest pin or the build's own assertion"
        out.append({"purl": entry["comp"]["purl"], "prefix": entry["prefix"], "status": status,
                    "detail": detail, "kind": entry["kind"]})
    return out


def sound(path):
    """An absolute path that can be compared component by component as it is written:
    no empty component, no '.', and no '..', which is not resolved and so never into a match."""
    return path.startswith("/") and not {"", ".", ".."} & set(path[1:].split("/"))


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def version_key(version):
    """A version as conda and PyPI both mean it, as far as that is certain: letters in
    lower case, and '_' or '-' read as '.' after the release number (1.0_post1 = 1.0-post1
    = 1.0.post1, +cu126_1 = +cu126.1). The release number itself stays as written."""
    version = version.lower()
    cut = re.match(r"(\d+!)?\d+(\.\d+)*", version)
    cut = cut.end() if cut else 0
    return version[:cut], re.sub(r"[-_]", ".", version[cut:])


def npm_container(path, prefix, names):
    """The locked npm package that holds path below its own package.json, or None.

    Packages are installed in <prefix>/node_modules/<name>, nested ones in
    .../<name>/node_modules/<name>: the package is named by the one or two (scoped)
    components after the last node_modules, and one more directory must follow.
    """
    parts = path[len(prefix.rstrip("/")) + 1:].split("/")
    if parts[0] != "node_modules" or parts[-1] != "package.json":
        return None
    inside = parts[len(parts) - parts[::-1].index("node_modules"):]
    size = 2 if inside[0].startswith("@") else 1
    name = "/".join(inside[:size])
    return name if len(inside) >= size + 2 and name in names else None


def lock_reason(item, path, prefix, locked, conda, npm):
    """Why the locks of prefix explain a scanner component located at path in it, or None."""
    purl = item["purl"]
    if not purl:
        return None
    ptype, namespace, name, version = purl[:4]
    if version in locked.get(item["name"], {}).get(prefix, ()):
        return f"locked in {prefix}"
    if not namespace:  # scanners report what conda installed as pypi and generic components
        for conda_name, conda_version in conda.get((prefix, ptype == "pypi", name), ()):
            if version == conda_version or (ptype == "pypi" and version_key(version) == version_key(conda_version)):
                return f"conda package {conda_name} {conda_version} locked in {prefix}"
    if ptype == "npm" and prefix in npm:
        if path == prefix.rstrip("/") + "/package.json":
            return "root manifest of the npm lock"
        holder = npm_container(path, prefix, npm[prefix])
        if holder:
            return f"inside the locked npm package {holder} in {prefix}"
    return None


def reverse_check(entries, items, prefixes, base_layers, allow):
    locked, conda, npm, pins = {}, {}, {}, {}
    for entry in entries:
        purl, prefix = entry["purl"], entry["prefix"]
        if prefix:
            locked.setdefault(purl[:3], {}).setdefault(prefix, set()).add(purl[3])
        if entry["kind"] == "conda":
            for pypi, name in ((False, purl[2]), (True, pep503(purl[2]))):
                conda.setdefault((prefix, pypi, name), []).append((purl[2], purl[3]))
        if entry["kind"] == "npm":
            npm.setdefault(prefix, set()).add(f"{purl[1]}/{purl[2]}".lstrip("/"))
        if entry["kind"] == "pins" and entry["path"]:
            pins[entry["path"]] = entry["comp"]["name"]
    out = []
    for item in items:
        comp, purl, paths = item["comp"], item["purl"], item["paths"]
        at = (f"at {paths[0]}" + (f" (+{len(paths) - 1} more)" if len(paths) > 1 else "")
              if paths else "without a location")
        whole = None  # a purl or purl-type rule allows the component wherever it is
        if purl:
            by_purl = allow["purl"].get(purl[:3], {})
            whole = by_purl.get(purl[3]) or by_purl.get("*") or allow["purl-type"].get(purl[0])
        found = []  # per location: {status: why}
        for path, layers in item["located"]:
            how = {}
            if sound(path):
                prefix = owner(path, prefixes)
                why = prefix and lock_reason(item, path, prefix, locked, conda, npm)
                pin = min(containing(path, pins), default=None)
                rule = next((allow["path"][root] for root in containing(path, allow["path"])), None)
                if why:
                    how["lock"] = why
                if pin:
                    how["pin"] = f"under the path of pin {pins[pin]} ({pin})"
                if layers and all(layer in base_layers for layer in layers):
                    how["base-layer"] = "in a base image layer"
                if rule:
                    how["allow"] = rule
            if whole:
                how["allow"] = whole
            found.append(how)
        shared = [status for status in EXPLAINED if all(status in how for how in found)]
        if not found:
            status, why = ("allow", whole) if whole else ("unexplained", at)
        elif shared:
            status = shared[0]
            why = ("every location is in a base image layer" if status == "base-layer"
                   else "; ".join(sorted({how[status] for how in found})))
        elif all(found):  # every location by its strongest mechanism
            used = {next((status, how[status]) for status in EXPLAINED if status in how) for how in found}
            status, why = "mixed", "; ".join(
                f"{s}: {w}" for s, w in sorted(used, key=lambda u: (EXPLAINED.index(u[0]), u[1])))
        else:  # name the locations nothing explains, and what the locks have there instead
            rest = [path for (path, _), how in zip(item["located"], found) if not how]
            owners = sorted({owner(path, prefixes) for path in rest if sound(path)} - {None})
            status, why = "unexplained", f"at {rest[0]}" + (f" (+{len(rest) - 1} more)" if len(rest) > 1 else "")
            if len(rest) < len(found):
                why += f"; explained: {len(found) - len(rest)} of {len(found)} locations"
            for kind, versions in (("lock", locked.get(item["name"], {})), ("conda lock", {
                    p: {v for _, v in conda.get((p, purl[0] == "pypi", purl[2]), ())}
                    for p in owners if purl and not purl[1]})):
                why += "".join(f"; the {kind} has {', '.join(sorted(versions[p]))} in {p}"
                               for p in owners if versions.get(p))
        if not purl:  # the report row has nothing else to tell such components apart
            label = f"{comp['name']} {comp.get('version', '')}"
            why = f"{label} {why}" if status == "unexplained" else f"{label} {at}: {why}"
        out.append({"purl": comp.get("purl") or None, "prefix": min(item["owners"], default=None),
                    "status": status, "detail": why, "type": purl[0] if purl else "(no purl)"})
    out.sort(key=lambda r: (r["purl"] is None, r["purl"] or "", r["detail"]))
    return out


def table(title, rows, group, columns):
    """Print counts of row[group] x row['status']; return them as {group: {status: n}}.

    Purls, paths, names and versions come from inside the image, so whatever is
    printed goes through printable(): no extra lines (GitHub reads '::error::'
    at the start of one as a command) and no terminal escapes. The report keeps
    the values as they are.
    """
    counts = {}
    for row in rows:
        counts.setdefault(row[group], Counter())[row["status"]] += 1
    columns = [c for c in columns if any(c in n for n in counts.values())]
    width = max([len(label) for label in counts] + [len(group)])
    print(f"\n{title}")
    print(f"  {group:<{width}}" + "".join(f"  {c:>{max(len(c), 5)}}" for c in columns))
    for label in sorted(counts):
        print(f"  {printable(label):<{width}}"
              + "".join(f"  {counts[label][c]:>{max(len(c), 5)}}" for c in columns))
    return {label: dict(sorted(n.items())) for label, n in sorted(counts.items())}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--locks-sbom", required=True, metavar="FILE", help="output of sbom_from_locks.py")
    ap.add_argument("--image-sbom", required=True, metavar="FILE", help="scanner (syft) CycloneDX JSON")
    ap.add_argument("--probe-sbom", metavar="FILE", help="output of sbom_probe.py (conda and pin probes)")
    ap.add_argument("--base-layers", metavar="FILE",
                    help="diff IDs of the digest-pinned base image, one sha256:<hex> per line")
    ap.add_argument("--allow", metavar="FILE", help="sbom/allow.tsv")
    ap.add_argument("--strict-reverse", action="store_true",
                    help="fail when a scanner component is unexplained")
    ap.add_argument("--report", metavar="FILE", help="write the full result as JSON")
    args = ap.parse_args(argv)
    try:
        locks, image = load_cdx(args.locks_sbom), load_cdx(args.image_sbom)
        probe = load_cdx(args.probe_sbom) if args.probe_sbom else None
        base_layers = load_base_layers(args.base_layers) if args.base_layers else set()
        allow = load_allow(args.allow) if args.allow else {"path": {}, "purl-type": {}, "purl": {}}
        entries = lock_entries(locks, args.locks_sbom)
        prefixes = {v for doc in (locks, probe) if doc for comp in doc["components"]
                    for name in PREFIX_PROPS for v in props(comp, name)}
        items = scanner_items(image, prefixes, {e["path"] for e in entries
                                                if e["kind"] == "pins" and e["path"]})
        forward = forward_check(entries, items, probe)
        reverse = reverse_check(entries, items, prefixes, base_layers, allow)
    except InputError as e:
        print(f"sbom_crosscheck: {e}", file=sys.stderr)
        return 2

    by_kind = table(f"forward check: {len(forward)} lock components", forward, "kind", FORWARD)
    for row in forward:
        if row["status"] in FAILURES + ("unverifiable",):
            print("  " + printable(f"{row['status']}: {row['purl']}"
                                   + (f" in {row['prefix']}" if row["prefix"] else "") + f": {row['detail']}"))
    by_type = table(f"reverse check: {len(reverse)} scanner components", reverse, "type", REVERSE)
    unexplained = [row for row in reverse if row["status"] == "unexplained"]
    for row in unexplained[:SHOWN]:
        print("  " + printable(f"unexplained: {row['purl'] or '(no purl)'} {row['detail']}"))
    if len(unexplained) > SHOWN:
        print(f"  ... and {len(unexplained) - SHOWN} more unexplained"
              + (f" (all in {args.report})" if args.report else " (use --report for all)"))

    failed = sum(row["status"] in FAILURES for row in forward)
    unverifiable = sum(row["status"] == "unverifiable" for row in forward)
    report = {
        "forward": [{k: row[k] for k in ("purl", "prefix", "status", "detail")} for row in forward],
        "reverse": [{k: row[k] for k in ("purl", "prefix", "status", "detail")} for row in reverse],
        "summary": {
            "forward": dict(sorted(Counter(row["status"] for row in forward).items())),
            "reverse": dict(sorted(Counter(row["status"] for row in reverse).items())),
            "forward_by_kind": by_kind,
            "reverse_by_type": by_type,
        },
    }
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(json.dumps(report, indent=2) + "\n")
        except OSError as e:
            print(f"sbom_crosscheck: {args.report}: {e.strerror}", file=sys.stderr)
            return 2

    problems = []
    if failed:
        problems.append(f"{failed} lock components are not in the image as locked")
    if unexplained and args.strict_reverse:
        problems.append(f"{len(unexplained)} scanner components are unexplained (--strict-reverse)")
    warnings = []
    if unverifiable:
        warnings.append(f"{unverifiable} unverifiable")
    if unexplained and not args.strict_reverse:
        warnings.append(f"{len(unexplained)} scanner components unexplained")
    print("\nsbom_crosscheck: " + ("FAIL: " + "; ".join(problems) if problems else "PASS")
          + (" (warnings: " + "; ".join(warnings) + ")" if warnings else ""))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
