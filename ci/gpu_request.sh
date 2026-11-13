#!/usr/bin/env bash
# Ask the GPU builder to build this commit's GPU variants and collect the
# result. The builder is the private repo idss-mesa/mesa-gpu-builder, the only
# repo the gpu06 runner serves; it builds nothing but commits on `main` of the
# image repos (see its README).
#
#   gpu_request.sh start CPU_DIGEST          dispatch a build; prints the builder's run id
#   gpu_request.sh wait RUN_ID MINUTES DIR   wait up to MINUTES; when the build has
#                                            finished, download its result into DIR
#   gpu_request.sh cancel RUN_ID             cancel a build nobody waits for any more
#
# `wait` exits 1 when the build failed and 0 otherwise; with GITHUB_OUTPUT set
# it writes done=true or done=false there, so a workflow can wait in several
# steps (a GitHub App token lasts one hour).
#
# GH_TOKEN must be allowed to run workflows in the builder repo. `start` reads
# GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT and STAGE_ID.
set -euo pipefail

die() { echo "gpu_request: $*" >&2; exit 1; }

builder=${MESA_GPU_BUILDER:-idss-mesa/mesa-gpu-builder}
workflow=build.yml
poll=${GPU_REQUEST_POLL_SECONDS:-60}

run_id() { [[ ${1:-} =~ ^[0-9]+$ ]] || die "'${1:-}' is not a run id"; }

cmd_start() {
  local cpu_digest=${1:-} repo request title response runs id=
  [[ $cpu_digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "'$cpu_digest' is not a digest"
  : "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${STAGE_ID:?}"
  repo=${GITHUB_REPOSITORY#*/}
  request="$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
  # The answer names the run this dispatch started.
  response=$(gh api --method POST "repos/$builder/actions/workflows/$workflow/dispatches" \
    -f ref=main -F return_run_details=true \
    -f "inputs[repo]=$repo" -f "inputs[commit]=$GITHUB_SHA" -f "inputs[cpu_digest]=$cpu_digest" \
    -f "inputs[stage_id]=$STAGE_ID" -f "inputs[request]=$request")
  id=$(jq -r '.workflow_run_id // empty' <<<"$response" 2>/dev/null) || id=
  if [[ ! $id =~ ^[0-9]+$ ]]; then
    # No run id in the answer: look for the run by the name the builder gives
    # it, "<repo> <request>". A failed lookup is tried again; the build is
    # already running and nobody else would wait for it.
    title="$repo $request"
    id=
    for _ in $(seq 30); do
      sleep "$((poll < 10 ? poll : 10))"
      if runs=$(gh run list --repo "$builder" --workflow "$workflow" --event workflow_dispatch --limit 50 \
        --json databaseId,displayTitle); then
        id=$(jq -r --arg t "$title" '[.[] | select(.displayTitle == $t)][0].databaseId // empty' <<<"$runs")
        [ -z "$id" ] || break
      fi
    done
    [[ $id =~ ^[0-9]+$ ]] || die "the builder did not start a run named '$title'"
  fi
  echo "gpu_request: builder run $id for $repo $request" >&2
  echo "$id"
}

cmd_wait() {
  local run=${1:-} minutes=${2:-} dir=${3:-} deadline state status conclusion errors=0
  run_id "$run"
  [[ $minutes =~ ^[0-9]+$ ]] || die "'$minutes' is not a number of minutes"
  [ -n "$dir" ] || die "wait needs a directory for the result"
  deadline=$((SECONDS + minutes * 60))
  while :; do
    if state=$(gh run view "$run" --repo "$builder" --json status,conclusion --jq '.status + " " + (.conclusion // "")'); then
      errors=0
      read -r status conclusion <<<"$state"
      if [ "$status" = completed ]; then
        [ "$conclusion" = success ] || die "the GPU build (run $run in $builder) ended as '$conclusion'"
        gh run download "$run" --repo "$builder" --name gpu-result --dir "$dir"
        echo "gpu_request: build finished; result in $dir" >&2
        [ -z "${GITHUB_OUTPUT:-}" ] || echo "done=true" >>"$GITHUB_OUTPUT"
        return 0
      fi
    else
      # One failed poll is not a failed build.
      errors=$((errors + 1))
      [ "$errors" -lt 5 ] || die "cannot read the state of run $run in $builder"
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "gpu_request: run $run is still '${status:-unknown}' after $minutes minutes" >&2
      [ -z "${GITHUB_OUTPUT:-}" ] || echo "done=false" >>"$GITHUB_OUTPUT"
      return 0
    fi
    sleep "$poll"
  done
}

cmd_cancel() {
  run_id "${1:-}"
  gh run cancel "$1" --repo "$builder" >&2
}

case ${1:-} in
  start | wait | cancel) cmd=$1; shift; "cmd_$cmd" "$@" ;;
  *) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
