#!/usr/bin/env bash
# One entry point for what the workflows do, so every step also runs by hand:
#
#   ci/mesa-ci.sh check                     static checks (no Docker)
#   VARIANT=cpu ci/mesa-ci.sh build         build the variant as a local image
#   VARIANT=cpu ci/mesa-ci.sh test          run the variant's test script
#   VARIANT=cpu ci/mesa-ci.sh sbom          scan, cross-check, write the SBOM
#
# Run from the image repo's root. Reads ./mesa.env and ./VERSION.
#
#   VARIANT   cpu | sandbox | gpu | gpu-sandbox                 (default cpu)
#   ARCH      amd64 | arm64                          (default: this machine)
#   BASE_REF  image the variant builds FROM   (default: the local image of
#             the variant below it: cpu for sandbox and gpu, gpu for gpu-sandbox)
#   DIGEST    sha256:... of the pushed image, recorded in the SBOM
#             (default: the local image ID)
#   OUT       directory for SBOMs and reports                   (default out)
#   STRICT_REVERSE=1  fail when a scanner component is unexplained
#
# Needs docker; `sbom` also needs syft and crane (ci/install-tools.sh puts
# them in ./.tools/bin, which is added to PATH here).
set -euo pipefail

die() { echo "mesa-ci: $*" >&2; exit 1; }

[ -f mesa.env ] && [ -f VERSION ] || die "run from the image repo root (mesa.env and VERSION not found)"
ci=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PATH="$PWD/.tools/bin:$PATH"

# mesa.env is KEY=value lines; only the keys below are read.
conf() {
  local value
  value=$(sed -n "s/^$1=//p" mesa.env | tail -1)
  value=${value#\"}; value=${value%\"}
  printf '%s' "$value"
}
image=$(conf MESA_IMAGE); context=$(conf MESA_CONTEXT); arches=$(conf MESA_ARCHES)
[ -n "$image" ] && [ -n "$context" ] && [ -n "$arches" ] || die "mesa.env must set MESA_IMAGE, MESA_CONTEXT and MESA_ARCHES"
name=${image##*/}

version=$(cat VERSION)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must be X.Y.Z, found '$version'"

case $(uname -m) in
  x86_64) host_arch=amd64 ;;
  aarch64) host_arch=arm64 ;;
  *) die "unsupported machine $(uname -m)" ;;
esac
variant=${VARIANT:-cpu}
arch=${ARCH:-$host_arch}
out=${OUT:-out}
case $variant in cpu | sandbox | gpu | gpu-sandbox) ;; *) die "unknown VARIANT '$variant'" ;; esac
case $arch in amd64 | arm64) ;; *) die "unknown ARCH '$arch'" ;; esac

local_tag() { echo "mesa-local/$name:$1-$arch"; }
python() { python3 "$@"; }

variants_for_arch() { # every variant this repo publishes for $1
  if [ "$1" = amd64 ]; then echo cpu sandbox gpu gpu-sandbox; else echo cpu; fi
}

cmd_check() {
  ( cd "$ci" && sha256sum --check --quiet SHARED.sha256 ) || die "a shared file in ci/ differs from ci/SHARED.sha256 (copy it again from idss-mesa/mesa-updater)"
  local a v tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -r '$tmp'" EXIT
  for a in $arches; do
    for v in $(variants_for_arch "$a"); do
      python "$ci/sbom_from_locks.py" --repo-root . --variant "$v" --arch "$a" -o "$tmp/locks.json" 2>&1 | sed "s/^/$v $a: /"
    done
  done
  echo "check: ok (version $version)"
}

cmd_build() {
  local dir base args=()
  case $variant in
    cpu) dir=$context ;;
    gpu) dir=gpu; base=${BASE_REF:-$(local_tag cpu)} ;;
    sandbox) dir=sandbox; base=${BASE_REF:-$(local_tag cpu)} ;;
    gpu-sandbox) dir=sandbox; base=${BASE_REF:-$(local_tag gpu)} ;;
  esac
  [ "$variant" = cpu ] || args+=(--build-arg "BASE_IMAGE=$base")
  if [ "$variant" = cpu ]; then
    args+=(--build-arg "MESA_VERSION=v$version" --build-arg "MESA_REVISION=$(git rev-parse HEAD)")
  fi
  docker buildx build --platform "linux/$arch" "${args[@]}" -t "$(local_tag "$variant")" --load "$dir"
  echo "build: $(local_tag "$variant") $(docker image inspect -f '{{.Id}}' "$(local_tag "$variant")")"
}

cmd_test() {
  local tag
  tag=$(local_tag "$variant")
  case $variant in
    cpu)
      [ -x ci/test-cpu.sh ] || die "ci/test-cpu.sh is missing"
      ci/test-cpu.sh "$tag" ;;
    gpu) gpu/test-gpu.sh "$tag" ;;
    sandbox | gpu-sandbox)
      SANDBOX_PORT=$(conf MESA_SANDBOX_PORT) SANDBOX_PATH=$(conf MESA_SANDBOX_PATH) \
        SANDBOX_DOCKER_ARGS=$(conf MESA_SANDBOX_DOCKER_ARGS) sandbox/test-sandbox.sh "$tag" ;;
  esac
}

# Diff IDs of the digest-pinned base image named by the CPU Dockerfile, for
# the platform being checked: what the scanner finds there is the base's.
base_layers() {
  local ref
  ref=$(sed -n 's/^ARG BASE_IMAGE=//p' "$context/Dockerfile" | tail -1)
  [[ $ref == *@sha256:* ]] || die "$context/Dockerfile: ARG BASE_IMAGE is not digest-pinned"
  crane config --platform "linux/$arch" "$ref" \
    | python -c 'import json, sys; print("\n".join(json.load(sys.stdin)["rootfs"]["diff_ids"]))'
}

cmd_sbom() {
  local tag dir digest strict=() allow=() extras=()
  tag=$(local_tag "$variant")
  dir="$out/$variant-$arch"
  mkdir -p "$dir"
  digest=${DIGEST:-$(docker image inspect -f '{{.Id}}' "$tag")}
  [ -z "${STRICT_REVERSE:-}" ] || strict=(--strict-reverse)
  [ ! -f sbom/allow.tsv ] || allow=(--allow sbom/allow.tsv)
  [ ! -f sbom/extras.cdx.json ] || extras=(--extras sbom/extras.cdx.json)

  SYFT_CHECK_FOR_APP_UPDATE=false syft scan "docker:$tag" -q -o "cyclonedx-json@1.6=$dir/syft.cdx.json"
  python "$ci/sbom_from_locks.py" --repo-root . --variant "$variant" --arch "$arch" -o "$dir/locks.cdx.json"
  python "$ci/sbom_probe.py" --image "$tag" --locks-sbom "$dir/locks.cdx.json" -o "$dir/probe.cdx.json"
  base_layers > "$dir/base-layers.txt"
  # The merged SBOM is written even when the cross-check fails, so a failed
  # run still shows what the image contains.
  local rc=0
  python "$ci/sbom_crosscheck.py" --locks-sbom "$dir/locks.cdx.json" --image-sbom "$dir/syft.cdx.json" \
    --probe-sbom "$dir/probe.cdx.json" --base-layers "$dir/base-layers.txt" "${allow[@]}" "${strict[@]}" \
    --report "$dir/report.json" | tee "$dir/crosscheck.txt" || rc=$?
  python "$ci/sbom_merge.py" --image-sbom "$dir/syft.cdx.json" --locks-sbom "$dir/locks.cdx.json" \
    --probe-sbom "$dir/probe.cdx.json" "${extras[@]}" \
    --name "$image" --digest "$digest" --version "v$version" --variant "$variant" --arch "$arch" \
    --revision "$(git rev-parse HEAD)" --timestamp "$(git log -1 --format=%cI)" -o "$dir/image.cdx.json"
  rm -f "$dir/syft.cdx.json"   # tens of MB of per-file entries; image.cdx.json is the result
  return "$rc"
}

case ${1:-} in
  check) cmd_check ;;
  build) cmd_build ;;
  test) cmd_test ;;
  sbom) cmd_sbom ;;
  *) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
