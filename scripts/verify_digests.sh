#!/usr/bin/env bash
# verify_digests.sh — verify every committed file against SHA256SUMS.
# Exit 0 when all digests match, non-zero otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS
