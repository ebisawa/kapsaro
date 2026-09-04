#!/usr/bin/env bash
# Copyright 2026 Satoshi Ebisawa
# SPDX-License-Identifier: Apache-2.0
#
# Checks the Rust production-source conventions that can be decided from a
# single file. Runs either as an agent hook or as a plain command.
#
# Usage:
#   check-source-conventions.sh <file.rs> [<file.rs> ...]
#   check-source-conventions.sh            # all production sources
#   <hook JSON on stdin>                   # agent PostToolUse hook
#
# Exits 2 with an explanation on stderr when a file violates a convention.

set -uo pipefail

root="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

# mod.rs files that predate the convention. Do not add to this list.
allowed_mod_rs="crates/kapsaro-core/src/api/mod.rs"

# Hook input arrives on stdin only when the agent harness runs this script, which
# it signals with CLAUDE_PROJECT_DIR. A plain command may also have a non-tty
# stdin that never closes, so the read is bounded instead of waiting for EOF.
files=""
if [ "$#" -gt 0 ]; then
  files="$*"
elif [ -n "${CLAUDE_PROJECT_DIR:-}" ] && [ ! -t 0 ]; then
  input=""
  IFS= read -r -t 3 -d '' input || true
  files=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
  [ -n "$files" ] || exit 0
else
  files=$(find "$root/src" "$root"/crates/*/src -name '*.rs' -type f 2>/dev/null)
fi

problems=""
add() { problems="${problems}- $1"$'\n'; }

for file in $files; do
  case "$file" in
    /*) ;;
    *) file="$root/$file" ;;
  esac

  case "$file" in
    *.rs) ;;
    *) continue ;;
  esac
  [ -f "$file" ] || continue

  # Production sources only. Test trees are checked by check-repo-conventions.sh.
  case "$file" in
    "$root"/src/*|"$root"/crates/*/src/*) ;;
    *) continue ;;
  esac

  rel="${file#"$root"/}"

  if [ "$(basename "$file")" = "mod.rs" ]; then
    case " $allowed_mod_rs " in
      *" $rel "*) ;;
      *) add "$rel は mod.rs です。モジュールは {module_name}.rs と {module_name}/ のペアで構成します" ;;
    esac
  fi

  line1=$(sed -n '1p' "$file")
  line2=$(sed -n '2p' "$file")
  if [ "$line1" != "// Copyright 2026 Satoshi Ebisawa" ] \
    || [ "$line2" != "// SPDX-License-Identifier: Apache-2.0" ]; then
    add "$rel に Copyright ヘッダがありません。1 行目を '// Copyright 2026 Satoshi Ebisawa'、2 行目を '// SPDX-License-Identifier: Apache-2.0' にします"
  fi

  if ! head -8 "$file" | grep -q '^//!'; then
    add "$rel にファイルの役割を述べる //! コメントがありません。Copyright ヘッダの下に 1 行から 2 行で書きます"
  fi

  inline=$(awk '
    { lines[NR] = $0 }
    /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/ {
      for (i = NR - 3; i < NR; i++) {
        if (i > 0 && lines[i] ~ /#\[cfg\(test\)\]/) { print NR; break }
      }
    }
  ' "$file")

  if [ -n "$inline" ]; then
    add "$rel の $(echo "$inline" | tr '\n' ' ')行目にインラインテストモジュールがあります。テスト本体は tests/ ツリーへ置き、#[cfg(test)] #[path = \"...\"] mod <name>; で登録します"
  fi
done

if [ -n "$problems" ]; then
  printf 'kapsaro のコード規約に違反しています。\n\n%s\n詳細は kapsaro-conventions skill にあります。\n' "$problems" >&2
  exit 2
fi

exit 0
