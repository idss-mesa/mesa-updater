#!/usr/bin/env python3
"""Probe a container image for what scanners miss.

    sbom_probe.py --image REF --locks-sbom locks.cdx.json -o probe.cdx.json [--docker docker]

Starts one throwaway container of the image (--network none, entrypoint
overridden, no GPU) and writes a CycloneDX 1.6 document with:

- conda: one component per package record in every <prefix>/conda-meta
  directory of the image (all of /, except /proc, /sys and /dev);
- pins: every lock component that has a mesa:lock:probe command, again, with
  mesa:probe:result (ok / mismatch) and mesa:probe:output.

Everything that comes out of the image is treated as data: it is parsed, size
bounded and never passed to a shell. Exit 0 = probed (mismatches are for
sbom_crosscheck.py to judge), 1 = the image could not be probed, 2 = bad input.
"""
import argparse
import contextlib
import copy
import json
import posixpath
import re
import secrets
import shlex
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.parse

SHELL = "/bin/sh"
CONDA_PRUNE = ("/proc", "/sys", "/dev")  # kernel file systems, not image content
START_TIMEOUT = 600  # seconds for the container's sh to answer; docker may have to pull
CONDA_TIMEOUT = 300  # seconds for the whole conda-meta stream
PIN_TIMEOUT = 30  # seconds per pin command
MAX_RECORD_BYTES = 64 << 20  # largest real record seen: 4.6 MB (qt6-main)
MAX_RECORDS = 100_000
MAX_HEADER_BYTES = 1 << 20  # of a tar long-name or pax header; real ones are a few hundred
MAX_FIELD_CHARS = 2048  # of a record field that is kept
MAX_OUTPUT_BYTES = 64 << 10  # of a pin command's output searched for the version
OUTPUT_CHARS = 200
RECORD_KEYS = ("name", "version", "build", "channel", "subdir", "url", "fn", "sha256", "md5")

EXTENSION_TYPES = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
                   tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE)


def conda_script(root="/", prune=CONDA_PRUNE):
    """sh script that writes a tar of every conda-meta directory below root.

    Runs in the image's sh. Only constants are interpolated; the directory
    names find discovers go straight to tar's argv, never through a shell.
    """
    skip = " -o ".join("-path " + shlex.quote(p) for p in prune)
    return (f"exec find {shlex.quote(root)} \\( {skip} \\) -prune -o "
            "-type d -name conda-meta -prune -exec tar -cf - {} +\n")


class InputError(Exception):
    """Bad --locks-sbom or arguments (exit 2)."""


class ProbeError(Exception):
    """The image could not be probed (exit 1)."""


# ---------------------------------------------------------------- docker ----

class Container:
    """The only code that talks to docker. Tests replace it."""

    def __init__(self, docker, image):
        self.docker = docker
        self.name = "mesa-probe-" + secrets.token_hex(8)
        # The container's sh idles on our stdin pipe, so it exits (and --rm
        # removes it) when we close the pipe or this process dies. "-s" also
        # keeps the image's CMD from being appended to the entrypoint.
        self.proc = subprocess.Popen(
            [docker, "run", "--rm", "-i", "--name", self.name, "--network", "none",
             "--entrypoint", SHELL, image, "-s"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # What answers is the image's sh: it may never do so, or never end the line.
        expired = threading.Event()

        def expire():
            expired.set()
            self.proc.kill()

        timer = threading.Timer(START_TIMEOUT, expire)
        timer.start()
        try:
            self.proc.stdin.write(b"echo mesa-probe-ready\n")
            self.proc.stdin.flush()
            ready = self.proc.stdout.readline(64).strip()
        except OSError:
            ready = b""
        finally:
            timer.cancel()
        if ready != b"mesa-probe-ready":
            self.close(kill=True)
            raise ProbeError(f"cannot start {SHELL} in a container of {image}"
                             + (f": no answer within {START_TIMEOUT}s" if expired.is_set() else ""))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self, kill=False):
        with contextlib.suppress(OSError):
            self.proc.stdin.close()
        if not kill:
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                kill = True
        if kill:
            # Client first, so it starts nothing more; then the container, which
            # can outlive its client.
            self.proc.kill()
            self.proc.wait()
            subprocess.run([self.docker, "rm", "-f", self.name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        self.proc.stdout.close()

    @contextlib.contextmanager
    def _exec(self, script, timeout, user=None, stderr=None):
        """docker exec sh -c script; yields (process, event set if it timed out)."""
        argv = [self.docker, "exec"] + (["--user", user] if user else [])
        proc = subprocess.Popen(argv + [self.name, SHELL, "-c", script],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr)
        timed_out = threading.Event()

        def expire():
            # Killing the docker client closes our pipe; whatever still runs
            # in the container dies with the container.
            timed_out.set()
            proc.kill()

        timer = threading.Timer(timeout, expire)
        timer.start()
        try:
            yield proc, timed_out
        finally:
            timer.cancel()
            proc.kill()
            proc.stdout.close()
            proc.wait()

    @contextlib.contextmanager
    def conda_tar(self):
        """Yield a buffered stream: a tar of every conda-meta directory.

        Read as root so no prefix is missed for lack of permission (the
        sandbox variants run as a non-root user and /root is 0700).
        """
        with tempfile.TemporaryFile() as err:
            with self._exec(conda_script(), CONDA_TIMEOUT, "0:0", err) as (proc, timed_out):
                try:
                    yield proc.stdout
                    status = proc.wait()
                finally:
                    if timed_out.is_set():
                        raise ProbeError(f"conda probe timed out after {CONDA_TIMEOUT}s")
            if status != 0:
                err.seek(0)
                detail = printable(err.read(2000).decode("utf-8", "replace").strip())
                raise ProbeError(f"conda probe failed in the image (exit {status}): {detail}")

    def run(self, command):
        """Run a pins.tsv probe command; return (exit status or None on timeout, output)."""
        with self._exec(command, PIN_TIMEOUT, stderr=subprocess.STDOUT) as (proc, timed_out):
            out = proc.stdout.read(MAX_OUTPUT_BYTES)
            while proc.stdout.read(1 << 16):  # discard the rest; the timer bounds this
                pass
            status = proc.wait()
        return (None if timed_out.is_set() else status), out.decode("utf-8", "replace")


# ----------------------------------------------------------------- conda ----

def conda_component(record, prefix):
    """CycloneDX component for one conda-meta record, or None if it is malformed."""
    if not isinstance(record, dict):
        return None
    name, version, build = (record.get(k) for k in ("name", "version", "build"))
    if not all(isinstance(v, str) and v and len(v) <= 256 for v in (name, version, build)):
        return None

    def text(key):
        value = record.get(key)
        return value if isinstance(value, str) and len(value) <= MAX_FIELD_CHARS else ""

    def segments(value):
        try:
            path = urllib.parse.urlsplit(value).path
        except ValueError:  # e.g. "http://[::1"
            return []
        return [urllib.parse.unquote(p) for p in path.split("/") if p]

    # Same reading of the URL as sbom_from_locks.py gives an explicit lock:
    # <channel, one or more segments>/<subdir>/<file>.
    url, subdir = text("url"), text("subdir")
    parts = segments(url)
    if len(parts) >= 3:
        filename, subdir = parts.pop(), parts.pop()
    else:
        filename = text("fn")
        # conda writes the channel as a URL, sometimes with the subdir; mamba as a name
        parts = segments(text("channel"))
        if parts and parts[-1] == subdir:
            parts.pop()
    kind = next((k for k in ("conda", "tar.bz2") if filename.endswith("." + k)), "")

    qualifiers = [("build", build), ("channel", "/".join(parts)), ("subdir", subdir), ("type", kind)]
    quote = urllib.parse.quote
    purl = "pkg:conda/%s@%s?%s" % (
        quote(name, safe=""), quote(version, safe=""),
        "&".join(f"{k}={quote(v, safe='/:')}" for k, v in qualifiers if v))

    component = {"type": "library", "name": name, "version": version,
                 "purl": purl, "bom-ref": f"{purl}#{prefix}"}
    hashes = [{"alg": alg, "content": record[key].lower()}
              for alg, key, size in (("SHA-256", "sha256", 64), ("MD5", "md5", 32))
              if isinstance(record.get(key), str)
              and re.fullmatch(r"[0-9a-fA-F]{%d}" % size, record[key])]
    if hashes:
        component["hashes"] = hashes
    if re.fullmatch(r"[a-z][a-z0-9+.-]*://\S+", url):
        component["externalReferences"] = [{"type": "distribution", "url": url}]
    component["properties"] = [{"name": "mesa:probe:prefix", "value": prefix}]
    return component


class BoundedTarInfo(tarfile.TarInfo):
    """Refuses the members tarfile would read into memory at any size the
    stream claims: long-name and pax headers, and sparse maps. tar writes
    neither large headers nor sparse members for a conda-meta directory.
    (_proc_member is how tarfile itself dispatches on these member types.)
    """

    def _proc_member(self, tar):
        if self.type in EXTENSION_TYPES and self.size > MAX_HEADER_BYTES:
            raise ProbeError(f"conda-meta stream from the image has a tar header of {self.size} bytes")
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise ProbeError("conda-meta stream from the image has a sparse member")
        return super()._proc_member(tar)

    def _proc_gnusparse_10(self, *args):
        raise ProbeError("conda-meta stream from the image has a sparse member")


def read_conda_tar(stream):
    """Parse a tar of conda-meta directories from a buffered binary stream.

    Returns ({prefix: [component, ...]}, number of *.json entries skipped).
    Nothing is extracted to disk.
    """
    prefixes, skipped, seen, count = {}, 0, {}, 0
    if not stream.peek(1):  # no conda-meta directory in the image
        return prefixes, skipped
    try:
        # ignore_zeros: find may split a long directory list over several tar runs
        with tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True, tarinfo=BoundedTarInfo) as tar:
            for member in tar:
                path = posixpath.normpath("/" + member.name)
                parent, base = posixpath.split(path)
                if member.isdir():
                    if base == "conda-meta":
                        prefixes.setdefault(parent, [])
                    continue
                if posixpath.basename(parent) != "conda-meta" or not base.endswith(".json"):
                    continue
                count += 1
                if count > MAX_RECORDS:
                    raise ProbeError(f"more than {MAX_RECORDS} conda records in the image")
                prefix = posixpath.dirname(parent)
                record = None
                if member.islnk():  # hard link to a record earlier in the stream
                    record = seen.get(posixpath.normpath("/" + member.linkname))
                elif member.isfile() and member.size <= MAX_RECORD_BYTES:
                    try:
                        record = json.loads(tar.extractfile(member).read())
                    except (ValueError, RecursionError):
                        pass
                    if isinstance(record, dict):  # keep what is used, at a bounded size
                        record = {k: v for k in RECORD_KEYS
                                  if isinstance(v := record.get(k), str) and len(v) <= MAX_FIELD_CHARS}
                    seen[path] = record
                component = conda_component(record, prefix)
                if component is None:
                    skipped += 1
                else:
                    prefixes.setdefault(prefix, []).append(component)
    except tarfile.TarError as e:
        raise ProbeError(f"conda-meta stream from the image is not a readable tar: {e}") from None
    return prefixes, skipped


# ------------------------------------------------------------------ pins ----

def lock_property(component, name):
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return prop.get("value")
    return None


def version_in(version, output):
    """True when output contains version as a whole version, not inside a longer one.

    A leading "v" (kept when the purl template writes one) is not required in
    the output: tini v0.19.0 prints "tini version 0.19.0".
    """
    if re.match(r"v[0-9]", version):
        version = version[1:]
    if not version:
        return False
    pattern = r"(?<![0-9])(?<![0-9]\.)" + re.escape(version) + r"(?![0-9])(?!\.[0-9])"
    return re.search(pattern, output) is not None


def probe_pin(component, run):
    """The lock component again, with mesa:probe:result and mesa:probe:output."""
    version = component.get("version")
    if not isinstance(version, str) or not version:
        ok, output = False, "lock component has no version"
    else:
        status, output = run(lock_property(component, "mesa:lock:probe"))
        output = output.strip()
        if status is None:
            ok, output = False, f"timeout after {PIN_TIMEOUT}s: {output}"
        elif status != 0:
            ok, output = False, f"exit {status}: {output}"
        else:
            ok = version_in(version, output)
    result = copy.deepcopy(component)
    result["properties"] = list(result.get("properties") or []) + [
        {"name": "mesa:probe:result", "value": "ok" if ok else "mismatch"},
        {"name": "mesa:probe:output", "value": output[:OUTPUT_CHARS]},
    ]
    return result


def load_pins(path):
    """Lock components that carry a mesa:lock:probe command."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise InputError(f"{path}: {e.strerror}") from None
    except json.JSONDecodeError as e:
        raise InputError(f"{path}:{e.lineno}: {e.msg}") from None
    except RecursionError:
        raise InputError(f"{path}: invalid JSON: nested too deeply") from None
    except UnicodeDecodeError as e:
        raise InputError(f"{path}: not UTF-8: {e.reason}") from None
    components = doc.get("components", []) if isinstance(doc, dict) else None
    if not isinstance(components, list) or doc.get("bomFormat") != "CycloneDX":
        raise InputError(f"{path}: not a CycloneDX document with a components list")
    pins = []
    for i, component in enumerate(components):
        if not isinstance(component, dict):
            raise InputError(f"{path}: components[{i}] is not an object")
        command = lock_property(component, "mesa:lock:probe")
        if command is None:
            continue
        if not isinstance(command, str) or not command.strip():
            raise InputError(f"{path}: components[{i}]: mesa:lock:probe is not a command")
        pins.append(component)
    return pins


# ------------------------------------------------------------------ main ----

def printable(text):
    return "".join(c if c.isprintable() else "?" for c in text)


def probe(container, pins, image):
    """Return (CycloneDX document, summary lines)."""
    with container.conda_tar() as stream:
        prefixes, skipped = read_conda_tar(stream)
    components, summary = [], []
    for prefix in sorted(prefixes):
        components += prefixes[prefix]
        summary.append(f"conda {printable(prefix)}: {len(prefixes[prefix])} packages")
    summary.append(f"conda: {len(prefixes)} prefixes, {skipped} records skipped")
    for pin in pins:
        result = probe_pin(pin, container.run)
        components.append(result)
        summary.append("pin %s %s: %s (%s)" % (
            pin.get("name"), pin.get("version"),
            lock_property(result, "mesa:probe:result"),
            printable(lock_property(result, "mesa:probe:output"))))
    components.sort(key=lambda c: (str(c.get("purl", "")), str(c.get("bom-ref", ""))))
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"properties": [
            {"name": "mesa:probe:image", "value": image},
            {"name": "mesa:probe:skipped", "value": str(skipped)},
        ]},
        "components": components,
    }
    return doc, summary


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Collect conda packages and pin probe results from a container image.")
    parser.add_argument("--image", required=True, metavar="REF")
    parser.add_argument("--locks-sbom", required=True, metavar="locks.cdx.json")
    parser.add_argument("-o", "--output", required=True, metavar="probe.cdx.json")
    parser.add_argument("--docker", default="docker", help="docker CLI to use (default: docker)")
    args = parser.parse_args(argv)
    try:
        if not args.image or args.image.startswith("-"):
            raise InputError(f"--image: not an image reference: {args.image!r}")
        pins = load_pins(args.locks_sbom)
        try:
            container = Container(args.docker, args.image)
        except OSError as e:
            raise ProbeError(f"cannot run {args.docker}: {e.strerror}") from None
        with container:
            doc, summary = probe(container, pins, args.image)
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
                f.write("\n")
        except OSError as e:
            raise InputError(f"{args.output}: {e.strerror}") from None
    except InputError as e:
        print(f"sbom_probe: {e}", file=sys.stderr)
        return 2
    except ProbeError as e:
        print(f"sbom_probe: {e}", file=sys.stderr)
        return 1
    print("\n".join(summary), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
