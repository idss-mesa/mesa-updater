#!/usr/bin/env bash
# Attest a CycloneDX SBOM to an image digest, then write the OCI referrers
# fallback tag that Harbor 2.9.0 needs (ci/README.md, docs/harbor-referrers.md).
#
#   attach_sbom.sh <repo>@sha256:<64 hex> <image.cdx.json>
#   attach_sbom.sh --index-only <repo>@sha256:<64 hex>
#
# --index-only signs nothing: it rewrites the fallback tag from the referrers
# the registry already has (exit 3 when there are none). It repairs a run that
# died between the attestation and the tag.
set -euo pipefail

die() { echo "attach_sbom: $1" >&2; exit "${2:-1}"; }

usage="usage: attach_sbom.sh <repo>@sha256:<64 hex> <image.cdx.json>
       attach_sbom.sh --index-only <repo>@sha256:<64 hex>"
index_only=
if [[ ${1:-} == --index-only ]]; then
  index_only=1
  shift
  [[ $# -eq 1 ]] || die "$usage" 2
else
  [[ $# -eq 2 ]] || die "$usage" 2
fi
ref=$1 sbom=${2:-}
[[ $ref =~ ^([A-Za-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+)@sha256:([0-9a-f]{64})$ ]] ||
  die "'$ref' is not <registry>/<repository>@sha256:<64 hex>" 2
repo=${BASH_REMATCH[1]} hex=${BASH_REMATCH[4]}
digest=sha256:$hex
[[ -n $index_only ]] || [[ -f $sbom && -r $sbom ]] || die "cannot read SBOM '$sbom'" 2
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/manifests"

# Digests of the descriptors under "referrers" (oras) or "manifests" (registry API).
digests() {
  python3 -c '
import json, sys
doc = json.load(sys.stdin)
for desc in doc.get("referrers") or doc.get("manifests") or []:
    print(desc["digest"])'
}

auth_header='^Authorization: [A-Za-z]+ [A-Za-z0-9._~+/=-]+$'

# Write every referrer digest of the subject to file $1, sorted.
list_referrers() {
  local auth code
  # oras reads the referrers API of a conforming registry and otherwise the
  # fallback tag, which is how the index written by an earlier run is kept.
  oras discover --format json "$ref" >"$tmp/discover.json"
  digests <"$tmp/discover.json" >"$tmp/found"
  # Harbor 2.9.0 lists the right digests but under a content type oras rejects,
  # so ask its API directly too. crane turns the Docker config login into a
  # pull token; curl gets it on stdin so it never shows up in argv.
  auth=$(crane auth token -H "$repo")
  [[ $auth =~ $auth_header ]] || die "unexpected output from 'crane auth token -H $repo'"
  code=$(printf 'header = "%s"\n' "$auth" | curl --silent --show-error --config - \
    --output "$tmp/api.json" --dump-header "$tmp/api.headers" --write-out '%{http_code}' \
    "https://${repo%%/*}/v2/${repo#*/}/referrers/$digest")
  case $code in
    200)
      ! grep -qi '^link:' "$tmp/api.headers" || die "referrers API response for $ref is paginated; not supported"
      digests <"$tmp/api.json" >>"$tmp/found"
      ;;
    404) ;; # no referrers API: clients keep the fallback tag, which oras read above
    *) die "referrers API answered HTTP $code for $ref" ;;
  esac
  LC_ALL=C sort -u "$tmp/found" >"$1"
}

# Fetch the manifest of every digest listed in file $1 that is not here yet.
fetch() {
  local d
  while read -r d; do
    [[ $d =~ ^sha256:[0-9a-f]{64}$ ]] || die "unexpected referrer digest '$d' for $ref"
    [[ -f $tmp/manifests/${d#sha256:} ]] || crane manifest "$repo@$d" >"$tmp/manifests/${d#sha256:}"
  done <"$1"
}

# Build the index of the digests listed in file $1 as file $2.
build_index() {
  local d manifests=()
  while read -r d; do
    manifests+=(--manifest "$d=$tmp/manifests/${d#sha256:}")
  done <"$1"
  python3 "$here/referrers_index.py" --subject-digest "$digest" "${manifests[@]}" -o "$2"
}

# Everything that can fail on what is already there fails here, before anything
# is signed: a referrer that cannot be fetched or indexed would otherwise stop
# every run after its attestation was pushed, and each retry would add another.
push_index() { # index file, list of referrers
  oras manifest push --media-type application/vnd.oci.image.index.v1+json "$repo:sha256-$hex" "$1"
  echo "attach_sbom: $repo:sha256-$hex lists $(wc -l <"$2") referrer(s) of $digest"
}

list_referrers "$tmp/before"
fetch "$tmp/before"
if [[ -s $tmp/before ]]; then
  build_index "$tmp/before" "$tmp/preflight.json"
fi

if [[ -n $index_only ]]; then
  if [[ ! -s $tmp/before ]]; then
    echo "attach_sbom: the registry lists no referrer of $ref"
    exit 3
  fi
  push_index "$tmp/preflight.json" "$tmp/before"
  exit 0
fi

attest=(attest --type cyclonedx --predicate "$sbom")
[[ -z ${COSIGN_KEY:-} ]] || attest+=(--key "$COSIGN_KEY")
[[ -z ${COSIGN_SIGNING_CONFIG:-} ]] || attest+=(--signing-config "$COSIGN_SIGNING_CONFIG")
COSIGN_YES=true cosign "${attest[@]}" "$ref"

list_referrers "$tmp/after"
# Guards the listing above: an index without the new attestation would hide it.
[[ -n $(LC_ALL=C comm -13 "$tmp/before" "$tmp/after") ]] ||
  die "cosign attest succeeded but the registry lists no new referrer of $ref"

fetch "$tmp/after"
build_index "$tmp/after" "$tmp/index.json"
push_index "$tmp/index.json" "$tmp/after"
