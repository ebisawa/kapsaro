#!/usr/bin/env bash
# Copyright 2026 Satoshi Ebisawa
# SPDX-License-Identifier: Apache-2.0
#
# Measures per-layer test coverage with cargo-llvm-cov and extracts the set of
# core production lines reached only by the CLI E2E tests (cli_integration).

set -euo pipefail

cd "$(dirname "$0")/.."
OUT=target/coverage-layers
mkdir -p "$OUT"

cargo llvm-cov clean --workspace

# Every run uses --workspace so feature unification stays identical across
# invocations; packages lacking a named test target are skipped by cargo.
# The report subcommand defaults to the current package, so both production
# packages are selected explicitly.
report() {
    cargo llvm-cov report --lcov -p kapsaro -p kapsaro-core --output-path "$1"
}

# Unit layers only (accumulated into shared profiling data).
cargo llvm-cov --no-report --workspace --bins --lib
cargo llvm-cov --no-report --workspace --test unit --test public_api
report "$OUT/cov-units.lcov"

# Add the CLI E2E layer on top of the accumulated unit-layer data.
cargo llvm-cov --no-report --workspace --test cli_integration
report "$OUT/cov-units-plus-e2e.lcov"

# Extract "file:line" entries with at least one hit from an lcov report.
extract_hit_lines() {
    awk -F: '/^SF:/{f=$2} /^DA:/{split($2,a,","); if(a[2]>0) print f":"a[1]}' "$1" | sort
}

extract_hit_lines "$OUT/cov-units.lcov" > "$OUT/units-hit-lines.txt"
extract_hit_lines "$OUT/cov-units-plus-e2e.lcov" > "$OUT/all-hit-lines.txt"

# Lines reached only by E2E. Hits inside crates/kapsaro-core/src indicate
# domain coverage that must move to unit tests before the E2E test shrinks.
comm -13 "$OUT/units-hit-lines.txt" "$OUT/all-hit-lines.txt" \
    > "$OUT/e2e-only-lines.txt"
grep '/crates/kapsaro-core/src/' "$OUT/e2e-only-lines.txt" \
    > "$OUT/e2e-only-core-lines.txt" || true

echo "--- coverage-layers summary ---"
echo "units-hit lines:        $(wc -l < "$OUT/units-hit-lines.txt")"
echo "units+e2e hit lines:    $(wc -l < "$OUT/all-hit-lines.txt")"
echo "e2e-only lines (all):   $(wc -l < "$OUT/e2e-only-lines.txt")"
echo "e2e-only lines (core):  $(wc -l < "$OUT/e2e-only-core-lines.txt")"
echo "reports under $OUT/"
