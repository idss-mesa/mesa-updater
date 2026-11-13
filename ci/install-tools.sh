#!/usr/bin/env bash
# Install the CI tools pinned in tools.lock (see ci/README.md).
set -euo pipefail

usage="usage: install-tools.sh [--dest DIR] [name ...]
Installs the named tools (default: all in tools.lock) for this machine's
architecture into DIR (default ./.tools/bin). TOOLS_LOCK=<path> overrides the
lock file next to this script. Downloaded archives are kept in DIR/.archives:
every run checks what is installed against the lock, without the network."

die() { echo "install-tools: $1" >&2; exit "${2:-1}"; }

lock=${TOOLS_LOCK:-$(dirname "${BASH_SOURCE[0]}")/tools.lock}
dest=./.tools/bin
names=()
while (($#)); do
  case $1 in
    --dest) (($# >= 2)) || die "--dest needs a directory" 2; dest=$2; shift 2 ;;
    --dest=*) dest=${1#--dest=}; shift ;;
    -h | --help) echo "$usage"; exit 0 ;;
    -*) die "unknown option '$1'
$usage" 2 ;;
    *) names+=("$1"); shift ;;
  esac
done
[[ -n $dest ]] || die "--dest needs a directory" 2

machine=$(uname -m)
case $machine in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) die "unsupported architecture '$machine' (tools.lock has amd64 and arm64)" 2 ;;
esac

# Read the whole lock before touching the network, so a bad line fails early.
[[ -f $lock && -r $lock ]] || die "cannot read lock file $lock" 2
declare -A row=() known=()
all=()
n=0
bad() { die "$lock:$n: $1" 2; }
# The member is extracted by exact name; it must stay inside the archive root.
bad_member='^/[/-]|/\.\./|//|[[:space:]]'
while IFS= read -r line || [[ -n $line ]]; do
  n=$((n + 1))
  [[ -z $line || $line == \#* ]] && continue
  tabs=${line//[^$'\t']/}
  IFS=$'\t' read -r name version a url sha member <<<"$line"
  [[ ${#tabs} -eq 5 && -n $member ]] || bad "expected 6 tab-separated fields: name version arch url sha256 member"
  [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || bad "bad tool name '$name'"
  [[ $a == amd64 || $a == arm64 ]] || bad "arch must be amd64 or arm64, not '$a'"
  [[ $url =~ ^https?://[^[:space:]]+$ ]] || bad "url must be http(s), not '$url'"
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || bad "sha256 must be 64 lowercase hex digits, not '$sha'"
  [[ $member == - || ! /$member/ =~ $bad_member ]] || bad "bad archive member '$member'"
  [[ -z ${row[$name/$a]:-} ]] || bad "second entry for $name $a"
  row[$name/$a]=$version$'\t'$url$'\t'$sha$'\t'$member
  [[ -n ${known[$name]:-} ]] || all+=("$name")
  known[$name]=1
done <"$lock"

((${#names[@]})) || names=("${all[@]}")
((${#names[@]})) || die "$lock lists no tools" 2
for name in "${names[@]}"; do
  [[ -n $name && -n ${known[$name]:-} ]] || die "unknown tool '$name' (not in $lock)" 2
  [[ -n ${row[$name/$arch]:-} ]] || die "$lock has no $arch entry for '$name'" 2
done

tmp=$(mktemp -d)
staged=
cleanup() {
  rm -rf "$tmp"
  [[ -z $staged ]] || rm -f "$staged"
}
trap cleanup EXIT

# True when $1 is a regular file whose SHA-256 is $2.
has_sha() { [[ -f $1 && ! -L $1 && $(sha256sum <"$1" | cut -d' ' -f1) == "$2" ]]; }

# Put file $1 at $2 with mode $3. Staged inside the target directory so the final mv is a rename.
place() {
  mkdir -p "${2%/*}"
  staged=${2%/*}/.${2##*/}.$$
  cp -- "$1" "$staged"
  chmod "$3" "$staged"
  mv -f -- "$staged" "$2"
  staged=
}

# Pass 1: verify everything. Nothing reaches $dest unless every requested tool
# has the recorded hash.
#
# What the lock hashes is kept in $dest: the binary itself, or the archive it
# was extracted from. A later run then decides from the lock alone, without the
# network, whether the installed tool is still the pinned one; nothing else in
# $dest is trusted, and a binary that differs is installed again.
declare -A binary=() archive=()
for name in "${names[@]}"; do
  IFS=$'\t' read -r version url sha member <<<"${row[$name/$arch]}"
  if [[ $member == - ]]; then kept=$dest/$name; else kept=$dest/.archives/$name.tar.gz; fi
  src=$kept
  if ! has_sha "$kept" "$sha"; then
    src=$tmp/$name.download
    curl -fsSL --retry 3 --proto '=http,https' -o "$src" "$url" || die "$name $version: download failed: $url"
    got=$(sha256sum <"$src" | cut -d' ' -f1)
    [[ $got == "$sha" ]] || die "$name $version ($arch): sha256 mismatch for $url
  expected $sha
  got      $got"
    [[ $member == - ]] || archive[$name]=$src
  fi
  bin=$src
  if [[ $member != - ]]; then
    mkdir "$tmp/$name.x"
    tar -xzf "$src" -C "$tmp/$name.x" -- "$member" || die "$name $version: cannot extract '$member' from $url"
    bin=$tmp/$name.x/$member
    [[ -f $bin && ! -L $bin ]] || die "$name $version: '$member' in $url is not a regular file"
  fi
  if [[ -x $dest/$name && ! -L $dest/$name ]] && cmp -s -- "$bin" "$dest/$name"; then
    echo "$name $version: already installed"
  else
    binary[$name]=$bin
  fi
done

# Pass 2: install.
for name in "${names[@]}"; do
  IFS=$'\t' read -r version url sha member <<<"${row[$name/$arch]}"
  [[ -z ${archive[$name]:-} ]] || place "${archive[$name]}" "$dest/.archives/$name.tar.gz" 0644
  [[ -n ${binary[$name]:-} ]] || continue
  place "${binary[$name]}" "$dest/$name" 0755
  echo "$name $version: installed $dest/$name"
done
