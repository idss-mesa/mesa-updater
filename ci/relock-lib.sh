# shellcheck shell=bash
# Helpers for a repo's ./relock.sh: each regenerates one kind of lock file
# from its intent file. Sourced, not executed. Needs docker, uv and crane on
# PATH; npm runs from the official Node image at the version the Dockerfile
# pins.
#
# Everything is written in place; `git diff` afterwards is the change set.

: "${MESA_ARCHES:=amd64 arm64}"

_die() { echo "relock: $*" >&2; exit 1; }

_uv_platform() {
  case "$1" in
    amd64) echo x86_64-manylinux_2_28 ;;
    arm64) echo aarch64-manylinux_2_28 ;;
    *) _die "unknown arch $1" ;;
  esac
}

_conda_platform() {
  case "$1" in
    amd64) echo linux-64 ;;
    arm64) echo linux-aarch64 ;;
    *) _die "unknown arch $1" ;;
  esac
}

# dockerfile_arg DOCKERFILE NAME -> default value of `ARG NAME=value`
dockerfile_arg() {
  local value
  value=$(sed -n "s/^ARG $2=//p" "$1" | tail -1)
  [ -n "$value" ] || _die "$1 has no ARG $2"
  printf '%s\n' "$value"
}

# set_dockerfile_arg DOCKERFILE NAME VALUE
set_dockerfile_arg() {
  grep -q "^ARG $2=" "$1" || _die "$1 has no ARG $2"
  # value goes through the environment so sed never sees it as a pattern
  NAME="$2" VALUE="$3" perl -pi -e 's/^ARG \Q$ENV{NAME}\E=.*/ARG $ENV{NAME}=$ENV{VALUE}/' "$1"
}

# base_digest DOCKERFILE ARG [--dated FLOATING_TAG]
#
# Re-resolves the base image in `ARG <ARG>=repo:tag@sha256:...` to the index
# digest its tag points at now. With --dated, FLOATING_TAG (e.g. latest) is
# resolved instead and the newest YYYY-MM-DD tag with that same digest is
# written, so the pin names an immutable upstream tag (Jupyter Docker Stacks).
base_digest() {
  local dockerfile=$1 arg=$2 floating="" current repo tag digest dated
  [ "${3:-}" = "--dated" ] && floating=$4
  current=$(dockerfile_arg "$dockerfile" "$arg")
  repo=${current%@*}; tag=${repo##*:}; repo=${repo%:*}
  if [ -n "$floating" ]; then
    digest=$(crane digest "$repo:$floating")
    dated=""
    for t in $(crane ls "$repo" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' | sort -r | head -10); do
      if [ "$(crane digest "$repo:$t")" = "$digest" ]; then dated=$t; break; fi
    done
    [ -n "$dated" ] || _die "no dated tag of $repo matches $floating ($digest)"
    tag=$dated
  else
    digest=$(crane digest "$repo:$tag")
  fi
  set_dockerfile_arg "$dockerfile" "$arg" "$repo:$tag@$digest"
  echo "base   $arg = $repo:$tag@$digest"
}

# pip_lock FILE.in PYTHON_VERSION [uv pip compile args...]
#
# Writes FILE.<arch>.txt for every arch: exact versions with sha256 hashes,
# wheels only, resolved for that arch and Python version.
pip_lock() {
  local in=$1 pyver=$2 arch out; shift 2
  for arch in $MESA_ARCHES; do
    out="${in%.in}.$arch.txt"
    uv pip compile --quiet --upgrade --generate-hashes --only-binary :all: --no-annotate \
      --python-version "$pyver" --python-platform "$(_uv_platform "$arch")" \
      --custom-compile-command "make relock" "$@" -o "$out" "$in"
    echo "pip    $out ($(grep -c '^[A-Za-z0-9]' "$out") packages)"
  done
}

# base_pip_constraints IMAGE PYTHON [PIP_LOCK...] > constraints.txt
#
# Prints name==version for every distribution PYTHON has in IMAGE, with the
# given pip locks applied on top: the package set of a lower layer. A later
# layer's lock is resolved with it as constraints (`pip_lock ... -c FILE`), so
# that layer can only add packages, never move one the lower layer ships.
base_pip_constraints() {
  local image=$1 python=$2 freeze; shift 2
  freeze=$(mktemp)
  docker run --rm --network none --entrypoint "$python" "$image" -m pip list --format=freeze > "$freeze" 2>/dev/null \
    || { rm -f "$freeze"; _die "cannot list the packages of $python in $image"; }
  python3 - "$freeze" "$@" <<'PY'
import re, sys

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

pins = {}
for path in sys.argv[1:]:
    for line in open(path):
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)", line)
        if match:
            pins[norm(match.group(1))] = match.group(2)
if not pins:
    sys.exit("relock: no packages found for the constraints")
for name in sorted(pins):
    print(f"{name}=={pins[name]}")
PY
  rm -f "$freeze"
}

# npm_lock DIR NODE_VERSION
#
# Rewrites DIR/package-lock.json from DIR/package.json (exact versions there
# are the intent). No package script runs. The lock covers every os/cpu, so
# one file serves both arches.
npm_lock() {
  local dir=$1 node_version=$2
  rm -f "$dir/package-lock.json"
  # Always the Node (and so npm) version the image ships, never the host's.
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$(cd "$dir" && pwd):/w" -w /w \
    "node:${node_version}-slim" npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null
  npm_lock_libc "$dir/package-lock.json"
}

# npm_lock_libc PACKAGE-LOCK.json
#
# npm 10 does not write a package's `libc` field into the lock, so `npm ci`
# would install the musl builds of platform binaries next to the glibc ones
# (Claude Code: +270 MB). npm does honour the field when it is there, so it is
# copied in from the registry metadata of each os-specific entry. Then the
# lock is checked: every entry has an integrity hash, both arches are covered.
npm_lock_libc() {
  python3 - "$1" <<'PY'
import json, sys, urllib.error, urllib.parse, urllib.request

path = sys.argv[1]
lock = json.load(open(path))
packages = lock["packages"]
for key, entry in packages.items():
    if not entry.get("os") or "libc" in entry:
        continue
    name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}/{entry['version']}"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            libc = json.load(response).get("libc")
    except (urllib.error.URLError, ValueError) as error:
        sys.exit(f"relock: {url}: {error}")
    if libc:
        entry["libc"] = libc
with open(path, "w") as out:
    json.dump(lock, out, indent=2)
    out.write("\n")

missing = [k for k, v in packages.items() if k and not v.get("link") and not v.get("integrity")]
if missing:
    sys.exit(f"relock: {path}: entries without an integrity hash: {missing[:5]}")
for cpu in ("x64", "arm64"):
    if not any(v.get("os") == ["linux"] and v.get("cpu") == [cpu] for v in packages.values()):
        sys.exit(f"relock: {path}: no linux/{cpu} optional binaries in the lock")
print(f"npm    {path} ({len(packages) - 1} packages)")
PY
}

# conda_lock ENVIRONMENT.yml OUT_PREFIX BASE_IMAGE
#
# Solves ENVIRONMENT.yml with the base image's own mamba (the solver that
# would otherwise run at build time) and writes OUT_PREFIX.<arch>.lock: an
# explicit spec, one URL#sha256 per package. Takes about 10 minutes per arch
# for cli's geospatial env; arches run in parallel.
#
# The solve must not depend on the machine it runs on, so the virtual
# packages are fixed: x86-64-v3 (AVX2, the level the env's SuiteSparse builds
# need anyway) and a 4.18 kernel (RHEL 8, the oldest host these images run on).
conda_lock() {
  local env_yml=$1 out_prefix=$2 base_image=$3 arch pids="" tmp
  tmp=$(mktemp -d)
  for arch in $MESA_ARCHES; do
    (
      docker run --rm --network bridge -e CONDA_OVERRIDE_ARCHSPEC=x86_64_v3 -e CONDA_OVERRIDE_LINUX=4.18 \
        -v "$(cd "$(dirname "$env_yml")" && pwd)/$(basename "$env_yml"):/tmp/environment.yml:ro" \
        --entrypoint mamba "$base_image" \
        env create -n relock -f /tmp/environment.yml --platform "$(_conda_platform "$arch")" --dry-run --json \
        > "$tmp/$arch.json" 2> "$tmp/$arch.err" || { tail -20 "$tmp/$arch.err" >&2; exit 1; }
    ) &
    pids="$pids $!"
  done
  for pid in $pids; do wait "$pid" || { rm -r "$tmp"; _die "conda solve failed for $env_yml"; }; done
  for arch in $MESA_ARCHES; do
    python3 - "$tmp/$arch.json" "$(_conda_platform "$arch")" "$env_yml" > "$out_prefix.$arch.lock" <<'PY'
import json, sys
solve = json.load(open(sys.argv[1]))
if not solve.get("success"):
    sys.exit("relock: conda solve did not succeed")
packages = solve["actions"]["LINK"]
bad = [p["name"] for p in packages if len(p.get("sha256") or "") != 64 or not p["url"].startswith("https://")]
if bad:
    sys.exit(f"relock: conda packages without an https URL and sha256: {bad[:5]}")
print(f"# Generated by `make relock` from {sys.argv[3]}. Do not edit.")
print(f"# platform: {sys.argv[2]}")
print("@EXPLICIT")
for p in sorted(packages, key=lambda p: p["url"]):
    print(f'{p["url"]}#sha256:{p["sha256"]}')
PY
    echo "conda  $out_prefix.$arch.lock ($(grep -c '^https://' "$out_prefix.$arch.lock") packages)"
  done
  rm -r "$tmp"
}
