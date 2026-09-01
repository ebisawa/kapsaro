#!/usr/bin/env bash
# Copyright 2026 Satoshi Ebisawa
# SPDX-License-Identifier: Apache-2.0
#
# Runs the cross-file checks that a single-file guard cannot make: test-file
# registration and trailing whitespace in the published guides. Runs either as
# an agent hook or as a plain command.
#
# Usage:
#   check-repo-conventions.sh              # check the whole tree
#   <hook JSON on stdin>                   # agent Stop hook
#
# Exits 2 with an explanation on stderr when a check fails. As a hook it stays
# quiet while the working tree is clean; run directly to check unconditionally.

set -uo pipefail

if [ ! -t 0 ] && [ "$#" -eq 0 ]; then
  input=$(cat)
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

unregistered=""
if [ -n "$test_roots" ]; then
  candidates=$(find $test_roots -name '*.rs' -type f 2>/dev/null | sort)

  source_dirs=""
  for dir in src tests crates/*/src crates/*/tests; do
    [ -d "$dir" ] && source_dirs="$source_dirs $dir"
  done

  # One pass over every source: collect the paths that #[path] attributes and
  # plain `mod name;` declarations resolve to. A plain declaration can land next
  # to a crate or target root, or inside the sibling directory, so accept both.
  registered=$(grep -rHnE \
    '#\[path[[:space:]]*=[[:space:]]*"[^"]*"|^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;' \
    $source_dirs --include='*.rs' 2>/dev/null | awk '
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
        print normalize(dir, target)
        next
      }
      if (match(line, /mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;/)) {
        name = substr(line, RSTART, RLENGTH)
        sub(/^mod[[:space:]]+/, "", name)
        sub(/[[:space:]]*;$/, "", name)
        print normalize(dir, name ".rs")
        print normalize(dir, stem "/" name ".rs")
      }
    }' | sort -u)

  unregistered=$(printf '%s\n' "$candidates" | grep -vxF -f <(printf '%s\n' "$registered") 2>/dev/null | sed 's/^/  /')
fi

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
