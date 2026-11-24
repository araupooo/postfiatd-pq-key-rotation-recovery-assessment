#!/usr/bin/env bash
# make_sha256sums.sh — regenerate SHA256SUMS over every committed file
# except outputs/run_all.log (transient; holds the wall-clock start line)
# and SHA256SUMS itself. Deterministic ordering (LC_ALL=C sort).
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
find . -type f \
    -not -path './.git/*' \
    -not -name 'SHA256SUMS' \
    -not -path './outputs/run_all.log' \
    | sort | xargs sha256sum > SHA256SUMS
echo "SHA256SUMS: $(wc -l < SHA256SUMS) entries"
