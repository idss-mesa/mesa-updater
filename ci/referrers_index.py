#!/usr/bin/env python3
"""Build the OCI image index for a subject's referrers fallback tag.

Each --manifest is a referrer manifest as fetched (raw bytes). See ci/README.md.
"""
import argparse
import hashlib
import json
import re
import sys

INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class BadInput(Exception):
    pass


def typed(obj, key, kind, path):
    """obj[key] when it is a kind, None when absent; any other JSON type is refused."""
    value = obj.get(key)
    if value is not None and not isinstance(value, kind):
        raise BadInput(f"{path}: {key} is not {'an object' if kind is dict else 'a string'}")
    return value


def descriptor(digest, path, subject):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise BadInput(f"{path}: {e.strerror}")
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != digest:
        raise BadInput(f"{path}: content is {actual}, not {digest}")
    try:
        manifest = json.loads(raw)
    except RecursionError:
        raise BadInput(f"{path}:1: not JSON: nested too deeply")
    except ValueError as e:
        raise BadInput(f"{path}:{getattr(e, 'lineno', 1)}: not JSON: {e}")
    if not isinstance(manifest, dict):
        raise BadInput(f"{path}:1: not a manifest (JSON object expected)")
    # The manifest comes from the registry: whatever goes into the index is type checked.
    referred = typed(typed(manifest, "subject", dict, path) or {}, "digest", str, path)
    if referred != subject:
        raise BadInput(f"{path}: subject is {referred}, not {subject}")
    media_type = typed(manifest, "mediaType", str, path)
    if not media_type:
        raise BadInput(f"{path}: manifest has no mediaType")

    desc = {"mediaType": media_type, "digest": digest, "size": len(raw)}
    artifact_type = (typed(manifest, "artifactType", str, path)
                     or typed(typed(manifest, "config", dict, path) or {}, "mediaType", str, path))
    if artifact_type:
        desc["artifactType"] = artifact_type
    annotations = typed(manifest, "annotations", dict, path)
    if annotations:
        if not all(isinstance(v, str) for v in annotations.values()):
            raise BadInput(f"{path}: annotations is not an object of strings")
        desc["annotations"] = annotations
    return desc


def build_index(subject, manifests):
    """manifests: iterable of (digest, path). Descriptors sorted by digest, one per digest."""
    if not DIGEST.fullmatch(subject):
        raise BadInput(f"--subject-digest: '{subject}' is not sha256:<64 hex>")
    by_digest = {}
    for digest, path in manifests:
        if not DIGEST.fullmatch(digest):
            raise BadInput(f"--manifest: '{digest}' is not sha256:<64 hex>")
        by_digest[digest] = descriptor(digest, path, subject)
    return {
        "schemaVersion": 2,
        "mediaType": INDEX_TYPE,
        "manifests": [by_digest[d] for d in sorted(by_digest)],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--subject-digest", required=True, metavar="sha256:HEX")
    ap.add_argument("--manifest", required=True, action="append", metavar="DIGEST=FILE",
                    help="referrer manifest digest and the file holding its raw bytes (repeatable)")
    ap.add_argument("-o", "--output", required=True, metavar="index.json")
    args = ap.parse_args(argv)
    try:
        pairs = []
        for item in args.manifest:
            digest, sep, path = item.partition("=")
            if not sep or not path:
                raise BadInput(f"--manifest: '{item}' is not <digest>=<file>")
            pairs.append((digest, path))
        index = build_index(args.subject_digest, pairs)
    except BadInput as e:
        print(f"referrers_index: {e}", file=sys.stderr)
        return 2
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json.dumps(index, separators=(",", ":")) + "\n")
    except OSError as e:
        print(f"referrers_index: {args.output}: {e.strerror}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
