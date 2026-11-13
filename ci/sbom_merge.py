#!/usr/bin/env python3
"""Merge the scanner, lock, probe and extras SBOMs into the published CycloneDX 1.6 SBOM.

Specified in ci/README.md ("sbom_merge.py"). Stdlib only, Python >= 3.10.
Exit 0 = written, 2 = bad input.
"""
import argparse
import copy
import json
import re
import sys
import uuid
from urllib.parse import quote, unquote

VARIANTS = ("cpu", "sandbox", "gpu", "gpu-sandbox")
ARCHES = ("amd64", "arm64")
LOCATION_RE = re.compile(r"syft:location:\d+:path")
PREFIX_PROPS = ("mesa:lock:prefix", "mesa:probe:prefix")
PLACE_PROPS = PREFIX_PROPS + ("mesa:lock:path",)
RFC3339_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)")


# --- shared with sbom_crosscheck.py (kept identical; tests compare the source) ---

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


def strip_package_id(purl):
    """Drop syft's package-id qualifier, which is an id of the scan, not of the package."""
    head, sep, subpath = purl.partition("#")
    base, _, query = head.partition("?")
    kept = [q for q in query.split("&") if q and not q.startswith("package-id=")]
    return base + ("?" + "&".join(kept) if kept else "") + sep + subpath


def key_of(comp):
    """What makes two components the same package, apart from where they are."""
    purl = parse_purl(comp.get("purl"))
    if not purl:
        return (None, "", comp["name"], str(comp.get("version", "")), None)
    ptype, namespace, name, version, qualifiers = purl
    # A conda build is a different artifact with different hashes.
    return (ptype, namespace, name, version, qualifiers.get("build") if ptype == "conda" else None)


def places(comp):
    """Paths that say where a component is: mesa prefix/path properties, then scanner locations."""
    return [v for name in PLACE_PROPS for v in props(comp, name)] + sorted(locations(comp))


def same_place(target_places, comp, prefixes):
    """True when a lock/probe/extras component sits where the target component is."""
    prefix = next((v for name in PREFIX_PROPS for v in props(comp, name)), None)
    path = pin_path(comp)
    if prefix:
        return any(owner(p, prefixes) == prefix for p in target_places)
    if path:
        return any(containing(p, {path}) for p in target_places)
    return not target_places  # e.g. a base image or a pin without a path


def union(dst, field, items, identity):
    """Append the items dst[field] does not have yet, so a repeated merge adds nothing."""
    have = {identity(x) for x in dst.get(field, [])}
    for item in items:
        if identity(item) not in have:
            have.add(identity(item))
            dst.setdefault(field, []).append(copy.deepcopy(item))


def gain(dst, src):
    """Give dst the hashes, distribution references and mesa:* properties of src."""
    union(dst, "hashes", src.get("hashes", []), lambda h: (h.get("alg"), h.get("content")))
    union(dst, "externalReferences",
          [r for r in src.get("externalReferences", []) if r.get("type") == "distribution"],
          lambda r: (r.get("type"), r.get("url")))
    union(dst, "properties",
          [p for p in src.get("properties", []) if str(p.get("name")).startswith("mesa:")],
          lambda p: (p.get("name"), p.get("value")))


def merge_components(docs):
    """Fold the documents' components together.

    docs is [(source, document or None)] with the image first. Returns
    (targets, origin): targets are {"comp", "source", "locked"}; origin maps
    (source, old bom-ref) to the targets that component ended up in.
    """
    prefixes = {v for _, doc in docs if doc for comp in doc["components"]
                for name in PREFIX_PROPS for v in props(comp, name)}
    targets, index, origin = [], {}, {}
    for source, doc in docs:
        for comp in doc["components"] if doc else []:
            if source == "image" and comp.get("type") == "file":
                continue
            key = key_of(comp)
            hits = [] if source == "image" else [
                t for t in index.get(key, []) if same_place(places(t["comp"]), comp, prefixes)]
            for target in hits:
                gain(target["comp"], comp)
                target["locked"] |= source == "locks"
            if not hits:
                new = copy.deepcopy(comp)
                # The probe emits every pin again, whatever the result. A pin it did
                # not find is still only what the lock says, like one never probed.
                unconfirmed = source == "probe" and any(
                    r != "ok" for r in props(comp, "mesa:probe:result"))
                kept_as = "locks" if unconfirmed else source
                if kept_as == "locks":
                    gain(new, {"properties": [{"name": "mesa:merge:source", "value": "lock-only"}]})
                hits = [{"comp": new, "source": kept_as, "locked": False}]
                targets += hits
                index.setdefault(key, []).append(hits[0])
            origin[(source, comp.get("bom-ref"))] = hits
    return targets, origin


def assign_refs(targets, taken):
    """Sort the components and give each a bom-ref unique in the document.

    The ref is the purl without package-id. Components that share a purl (the
    same package in several places) also get '#<place>'. Both are derived from
    the component, not from its old ref, so a second merge yields the same refs.
    """
    targets.sort(key=lambda t: (t["comp"]["name"], str(t["comp"].get("version", "")),
                                t["comp"].get("purl", ""), places(t["comp"]),
                                json.dumps(t["comp"], sort_keys=True)))
    wanted = {}
    for target in targets:
        comp = target["comp"]
        ref = (strip_package_id(comp["purl"]) if comp.get("purl")
               else str(comp.get("bom-ref") or f"{comp['name']}@{comp.get('version', '')}"))
        if comp.get("purl"):
            comp["purl"] = ref
        target["ref"] = ref
        wanted.setdefault(ref, []).append(target)
    for group in wanted.values():
        if len(group) > 1:
            for target in group:
                where = places(target["comp"])
                if where:
                    target["ref"] += "#" + where[0]
    taken = set(taken)
    for target in targets:
        ref, n = target["ref"], 1
        while ref in taken:
            n += 1
            ref = f"{target['ref']}~{n}"
        taken.add(ref)
        target["comp"]["bom-ref"] = ref


def merge_dependencies(docs, origin):
    """Dependency entries of the inputs, re-pointed, for refs that still exist."""
    graph = {}
    for source, doc in docs:
        for entry in doc["dependencies"] if doc else []:
            wanted = [dep for dep in entry.get("dependsOn", []) if isinstance(dep, str)]
            deps = {t["comp"]["bom-ref"] for dep in wanted for t in origin.get((source, dep), [])}
            if wanted and not deps:  # an empty list would claim "depends on nothing"
                continue
            for target in origin.get((source, entry.get("ref")), []):
                graph.setdefault(target["comp"]["bom-ref"], set()).update(deps)
    return [{"ref": ref, "dependsOn": sorted(graph[ref])} for ref in sorted(graph)]


def build(args, image, locks, probe, extras):
    docs = [("image", image), ("probe", probe), ("locks", locks), ("extras", extras)]
    targets, origin = merge_components(docs)
    hex_digest = args.digest.partition(":")[2]
    image_purl = (f"pkg:oci/{quote(args.name.rsplit('/', 1)[-1].lower(), safe='')}@sha256%3A{hex_digest}"
                  f"?arch={args.arch}&repository_url={quote(args.name.lower(), safe='/:')}")
    assign_refs(targets, {image_purl})

    ours = [("mesa:version", args.version), ("mesa:variant", args.variant),
            ("mesa:arch", args.arch), ("mesa:revision", args.revision)]
    scanner_meta = image.get("metadata") if isinstance(image.get("metadata"), dict) else {}
    kept = [p for p in scanner_meta.get("properties") or []
            if isinstance(p, dict) and p.get("name") not in dict(ours)]
    metadata = {"timestamp": args.timestamp}
    if "tools" in scanner_meta:
        metadata["tools"] = scanner_meta["tools"]
    metadata["component"] = {"type": "container", "bom-ref": image_purl, "name": args.name,
                             "version": args.digest, "purl": image_purl}
    metadata["properties"] = [{"name": k, "value": v} for k, v in ours] + kept

    doc = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        # Same digest and variant, same serial number: a rebuild of the SBOM is the same document.
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{args.digest}#{args.variant}")),
        "version": 1,
        "metadata": metadata,
        "components": [t["comp"] for t in targets],
        "dependencies": merge_dependencies(docs, origin),
    }
    counts = dict.fromkeys(("image", "image+lock", "probe", "probe+lock", "locks", "extras"), 0)
    for target in targets:
        counts[target["source"]] += 1
        if target["locked"] and target["source"] != "locks":
            counts[target["source"] + "+lock"] += 1
    counts["files"] = sum(c.get("type") == "file" for c in image["components"])
    return doc, counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image-sbom", required=True, metavar="FILE", help="scanner (syft) CycloneDX JSON")
    ap.add_argument("--locks-sbom", required=True, metavar="FILE", help="output of sbom_from_locks.py")
    ap.add_argument("--probe-sbom", metavar="FILE", help="output of sbom_probe.py")
    ap.add_argument("--extras", metavar="FILE", help="hand-listed components (sbom/extras.cdx.json)")
    ap.add_argument("--name", required=True, help="image repository, e.g. harbor.cyverse.org/vice/mesa-cli")
    ap.add_argument("--digest", required=True, help="image digest, sha256:<64 hex>")
    ap.add_argument("--version", required=True, help="release version, e.g. v2.0.0")
    ap.add_argument("--variant", required=True, choices=VARIANTS)
    ap.add_argument("--arch", required=True, choices=ARCHES)
    ap.add_argument("--revision", required=True, help="git commit the image was built from")
    ap.add_argument("--timestamp", required=True, help="RFC 3339, e.g. 2026-11-12T08:18:11Z")
    ap.add_argument("-o", "--output", required=True, metavar="FILE", help="CycloneDX JSON to write")
    args = ap.parse_args(argv)
    try:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest):
            raise InputError(f"--digest: '{args.digest}' is not sha256:<64 hex>")
        if not RFC3339_RE.fullmatch(args.timestamp):
            raise InputError(f"--timestamp: '{args.timestamp}' is not RFC 3339")
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*", args.name)
                or ":" in args.name.rsplit("/", 1)[-1]):
            raise InputError(f"--name: '{args.name}' is not a repository without tag or digest")
        if not args.version.strip() or not args.revision.strip():
            raise InputError("--version and --revision must not be empty")
        doc, counts = build(args, load_cdx(args.image_sbom), load_cdx(args.locks_sbom),
                            load_cdx(args.probe_sbom) if args.probe_sbom else None,
                            load_cdx(args.extras) if args.extras else None)
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json.dumps(doc, indent=2) + "\n")
        except OSError as e:
            raise InputError(f"{args.output}: {e.strerror}") from None
    except InputError as e:
        print(f"sbom_merge: {e}", file=sys.stderr)
        return 2
    print(f"sbom_merge: {len(doc['components'])} components: {counts['image']} from the scanner "
          f"({counts['image+lock']} with a lock entry; {counts['files']} file entries dropped), "
          f"{counts['probe']} from the probe ({counts['probe+lock']} with a lock entry), "
          f"{counts['locks']} lock-only, {counts['extras']} extras; "
          f"{len(doc['dependencies'])} dependency entries -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
