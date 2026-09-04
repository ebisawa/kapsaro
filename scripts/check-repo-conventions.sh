#!/usr/bin/env bash
# Copyright 2026 Satoshi Ebisawa
# SPDX-License-Identifier: Apache-2.0
#
# Runs the cross-file checks that a single-file guard cannot make: test-file
# registration (missing, stale and duplicated) and trailing whitespace in the
# published guides. Runs either as an agent hook or as a plain command.
#
# Usage:
#   check-repo-conventions.sh              # check the whole tree
#   <hook JSON on stdin>                   # agent Stop hook
#
# Exits 2 with an explanation on stderr when a check fails. As a hook it stays
# quiet while the working tree is clean; run directly to check unconditionally.

set -uo pipefail

# Hook input arrives on stdin only when the agent harness runs this script, which
# it signals with CLAUDE_PROJECT_DIR. A plain command may also have a non-tty
# stdin that never closes, so the read is bounded instead of waiting for EOF.
input=""
if [ -n "${CLAUDE_PROJECT_DIR:-}" ] && [ ! -t 0 ] && [ "$#" -eq 0 ]; then
  IFS= read -r -t 3 -d '' input || true
  case "$input" in
    *hook_event_name*|*stop_hook_active*)
      active=$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null)
      [ "$active" = "true" ] && exit 0
      hook_mode=1
      ;;
  esac
fi

root="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$root" 2>/dev/null || exit 0

if [ "${hook_mode:-0}" = "1" ]; then
  git rev-parse --git-dir >/dev/null 2>&1 || exit 0
  [ -n "$(git status --porcelain 2>/dev/null)" ] || exit 0
fi

test_roots=""
for dir in tests/unit/internal tests/cli tests/test_utils \
  crates/kapsaro-core/tests/unit/internal crates/kapsaro-core/tests/unit/external \
  crates/kapsaro-core/tests/test_support; do
  [ -d "$dir" ] && test_roots="$test_roots $dir"
done

source_dirs=""
for dir in src tests crates/*/src crates/*/tests; do
  [ -d "$dir" ] && source_dirs="$source_dirs $dir"
done

# One pass over every source: collect the paths that #[path] attributes and
# plain `mod name;` declarations resolve to. A plain declaration can land next
# to a crate or target root, or inside the sibling directory, so accept both.
#
# Records are tab separated. Field 1 is the kind, "P" for a #[path] attribute
# and "M" for a plain declaration; field 2 is the resolved path. A "P" record
# also carries the test binary the registration belongs to in field 3 and the
# registering file in field 4, which the stale and duplicate checks below need.
registrations=""
if [ -n "$source_dirs" ]; then
  registrations=$(grep -rHnE \
    '#\[path[[:space:]]*=[[:space:]]*"[^"]*"|^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;' \
    $source_dirs --include='*.rs' 2>/dev/null | awk '
    # The test binary a registering file compiles into. Anything under a src
    # tree belongs to that crate lib or bin binary; anything under a tests tree
    # belongs to the target named by the first component below it. Targets that
    # register another top-level target, as cli_integration.rs does, are read as
    # separate binaries, so a registration shared across those two is allowed.
    function binary_key(path,   parts, n, i, seg, out) {
      n = split(path, parts, "/")
      out = ""
      for (i = 1; i <= n; i++) {
        out = (i == 1) ? parts[i] : out "/" parts[i]
        if (parts[i] == "src") return out
        if (parts[i] == "tests") {
          if (i == n) return out
          seg = parts[i + 1]
          sub(/\.rs$/, "", seg)
          return out "/" seg
        }
      }
      return path
    }
    function normalize(base, rel,   combined, parts, n, i, seg, out, result) {
      combined = base "/" rel
      n = split(combined, parts, "/")
      out = ""
      result = 0
      delete stack
      for (i = 1; i <= n; i++) {
        seg = parts[i]
        if (seg == "" || seg == ".") continue
        if (seg == "..") { if (result > 0) result-- ; continue }
        result++
        stack[result] = seg
      }
      for (i = 1; i <= result; i++) out = (i == 1) ? stack[i] : out "/" stack[i]
      return out
    }
    {
      split($0, f, ":")
      path = f[1]
      dir = path
      sub(/\/[^\/]*$/, "", dir)
      if (dir == path) dir = "."
      stem = path
      sub(/.*\//, "", stem)
      sub(/\.rs$/, "", stem)

      line = $0
      sub(/^[^:]*:[0-9]+:/, "", line)

      if (match(line, /#\[path[[:space:]]*=[[:space:]]*"[^"]*"/)) {
        target = substr(line, RSTART, RLENGTH)
        sub(/^#\[path[[:space:]]*=[[:space:]]*"/, "", target)
        sub(/"$/, "", target)
        print "P\t" normalize(dir, target) "\t" binary_key(path) "\t" path
        next
      }
      if (match(line, /mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;/)) {
        name = substr(line, RSTART, RLENGTH)
        sub(/^mod[[:space:]]+/, "", name)
        sub(/[[:space:]]*;$/, "", name)
        print "M\t" normalize(dir, name ".rs")
        print "M\t" normalize(dir, stem "/" name ".rs")
      }
    }')
fi

unregistered=""
if [ -n "$test_roots" ]; then
  candidates=$(find $test_roots -name '*.rs' -type f 2>/dev/null | sort)
  registered=$(printf '%s\n' "$registrations" | awk -F'\t' 'NF >= 2 { print $2 }' | sort -u)
  unregistered=$(printf '%s\n' "$candidates" | grep -vxF -f <(printf '%s\n' "$registered") 2>/dev/null | sed 's/^/  /')
fi

# A #[path] naming a file that no longer exists. The build catches it, but it
# survives in a tree that is not built until CI, so report it here as well.
stale=$(printf '%s\n' "$registrations" | awk -F'\t' '$1 == "P" { print $2 }' | sort -u | while read -r target; do
  [ -n "$target" ] || continue
  [ -f "$target" ] || printf '  %s\n' "$target"
done)

# The same file registered twice into one test binary. Registrations that reach
# two different binaries are how a shared helper tree is compiled into both, so
# only a repeat within one binary is a problem.
duplicated=$(printf '%s\n' "$registrations" | awk -F'\t' '
  $1 == "P" {
    key = $3 SUBSEP $2
    count[key]++
    if (count[key] == 1) {
      target[key] = $2
      binary[key] = $3
      sources[key] = $4
    } else {
      sources[key] = sources[key] ", " $4
    }
  }
  END {
    for (key in count) {
      if (count[key] > 1) {
        printf "  %s（テストバイナリ %s、登録元 %s）\n", target[key], binary[key], sources[key]
      }
    }
  }' | sort)

trailing=""
if [ -d guides ]; then
  trailing=$(grep -rn ' $' guides --include='*.md' 2>/dev/null | head -20)
fi

problems=""
if [ -n "$unregistered" ]; then
  problems="${problems}登録されていないテストファイルがあります。コンパイルされないため、テストが存在しないまま緑になります。

$unregistered

登録手順は kapsaro-testing skill にあります。
"
fi
if [ -n "$stale" ]; then
  problems="${problems}実体のないファイルを指す #[path] 登録があります。ファイルを消したときの取り残しです。

$stale

登録を削除するか、正しいパスへ直してください。
"
fi
if [ -n "$duplicated" ]; then
  problems="${problems}同じテストバイナリへ二重登録されているテストファイルがあります。

$duplicated

どちらか一方の登録を削除してください。
"
fi
if [ -n "$trailing" ]; then
  problems="${problems}guides の Markdown に行末スペースがあります。

$trailing
"
fi

if [ -n "$problems" ]; then
  printf '%s' "$problems" >&2
  exit 2
fi

exit 0
