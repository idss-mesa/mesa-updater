#!/usr/bin/env bash
# One entry point for what the workflows do, so every step also runs by hand:
#
#   ci/mesa-ci.sh check                     static checks (no Docker)
#   VARIANT=cpu ci/mesa-ci.sh build         build the variant as a local image
#   VARIANT=cpu ci/mesa-ci.sh test          run the variant's test script
#   VARIANT=cpu ci/mesa-ci.sh push          push the local image under a staging tag
#   VARIANT=cpu ci/mesa-ci.sh sbom          scan, cross-check, write the SBOM
#
# Run from the image repo's root. Reads ./mesa.env and ./VERSION.
#
#   VARIANT   cpu | sandbox | gpu | gpu-sandbox                 (default cpu)
#   ARCH      amd64 | arm64                          (default: this machine)
#   BASE_REF  image the variant builds FROM   (default: the local image of
#             the variant below it: cpu for sandbox and gpu, gpu for gpu-sandbox)
#   DIGEST    sha256:... of the pushed image, recorded in the SBOM
#             (default: what `push` recorded, else the local image ID)
#   OUT       directory for SBOMs and reports                   (default out)
#   STRICT_REVERSE=1  fail when a scanner component is unexplained
#   STAGE_ID  names the staging tag `push` writes, stage-<STAGE_ID>-<variant>-<arch>
#             (default: the first 12 characters of the commit)
#   CHECK_RELEASED=1  `check` also fails when VERSION is already released
#             (git tag vX.Y.Z on origin) and the image's files differ from it
#
# Needs docker; `push` needs crane and a registry login; `sbom` needs syft
# and crane (ci/install-tools.sh puts them in ./.tools/bin, which is added to
# PATH here).
set -euo pipefail

die() { echo "mesa-ci: $*" >&2; exit 1; }

if [ ! -f mesa.env ] || [ ! -f VERSION ]; then die "run from the image repo root (mesa.env and VERSION not found)"; fi
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
if [ -z "$image" ] || [ -z "$context" ] || [ -z "$arches" ]; then die "mesa.env must set MESA_IMAGE, MESA_CONTEXT and MESA_ARCHES"; fi
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

# A change to what goes into an image must come with a new VERSION: merging
# a new VERSION is what releases, and a released version is never rebuilt.
# Compared with the released tag itself, so it holds whatever the branch is
# based on. An unreachable origin is an error, not "not released".
check_released() {
  local tags changed
  tags=$(git ls-remote --tags origin "refs/tags/v$version") || die "cannot list the tags of origin (is v$version released?)"
  if [ -z "$tags" ]; then echo "check: VERSION $version is not released yet"; return 0; fi
  # One commit is enough in CI's shallow checkout; a full clone must stay full.
  local depth=()
  [ "$(git rev-parse --is-shallow-repository)" != true ] || depth=(--depth 1)
  git fetch --quiet --no-tags "${depth[@]}" origin "refs/tags/v$version" || die "cannot fetch tag v$version from origin"
  changed=$(git diff --name-only FETCH_HEAD HEAD -- "$context" gpu sandbox ':!*.md') || die "cannot compare with tag v$version"
  if [ -n "$changed" ]; then
    echo "  ${changed//$'\n'/$'\n'  }" >&2
    die "these image files differ from the released v$version: raise VERSION"
  fi
  echo "check: the image files are those of the released v$version"
}

cmd_check() {
  ( cd "$ci" && sha256sum --check --quiet SHARED.sha256 ) || die "a shared file in ci/ differs from ci/SHARED.sha256 (copy it again from idss-mesa/mesa-updater)"
  [ -z "${CHECK_RELEASED:-}" ] || check_released
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
  mkdir -p "$out/$variant-$arch"
  rm -f "$out/$variant-$arch/digest" "$out/$variant-$arch/base"   # of an image this build replaces
  if [ "$variant" = cpu ]; then
    args+=(--build-arg "MESA_VERSION=v$version" --build-arg "MESA_REVISION=$(git rev-parse HEAD)")
  fi
  # No provenance attestation: with it some image stores push an index, and
  # the digest recorded by `push` must be the image manifest itself.
  docker buildx build --platform "linux/$arch" --provenance=false "${args[@]}" -t "$(local_tag "$variant")" --load "$dir"
  # A release proves each variant was built on the staged image below it.
  if [[ ${base:-} =~ @(sha256:[0-9a-f]{64})$ ]]; then echo "${BASH_REMATCH[1]}" > "$out/$variant-$arch/base"; fi
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

# Push the local image under a staging tag and record its digest. Staging tags
# are not what anyone pulls: a release or rolling workflow tags the digest
# once every variant has passed.
#
# The tag is never read back: anyone with push access could have moved it. The
# digest is the one docker reports for this push, and it is recorded only if
# the manifest stored under that digest is this very image: its config is the
# local image (the image ID is the config digest; with the containerd image
# store it is the manifest digest itself).
cmd_push() {
  local stage log digest id manifest bound
  stage="$image:stage-${STAGE_ID:-$(git rev-parse --short=12 HEAD)}-$variant-$arch"
  id=$(docker image inspect -f '{{.Id}}' "$(local_tag "$variant")")
  docker tag "$(local_tag "$variant")" "$stage"
  log=$(docker push "$stage")
  digest=$(sed -n 's/.*digest: \(sha256:[0-9a-f]\{64\}\).*/\1/p' <<<"$log" | tail -n 1)
  [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "docker push $stage did not report a digest"
  manifest=$(crane manifest "$image@$digest")
  bound=$(python -c '
import json, sys
manifest, digest, image_id = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
if "manifests" in manifest:
    print("index")
elif image_id in (digest, manifest.get("config", {}).get("digest")):
    print("yes")
else:
    print("no")' "$manifest" "$digest" "$id")
  case $bound in
    yes) ;;
    index) die "$image@$digest is an image index, not a single image: the build must push one manifest" ;;
    *) die "$image@$digest is not the image that was built and tested here ($id)" ;;
  esac
  mkdir -p "$out/$variant-$arch"
  echo "$digest" > "$out/$variant-$arch/digest"
  echo "push: $stage $digest"
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
  digest=${DIGEST:-$(cat "$dir/digest" 2>/dev/null || docker image inspect -f '{{.Id}}' "$tag")}
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
  push) cmd_push ;;
  sbom) cmd_sbom ;;
  *) sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
