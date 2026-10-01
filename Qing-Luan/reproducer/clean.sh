#!/usr/bin/env bash
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
find "$here/spec-aligned" "$here/pristine" -type f \( \
    -name 'hostile_review_api' -o \
    -name 'hostile_review_standalone' -o \
    -name 'hostile_review_sanitize' -o \
    -name 'hostile_review_sanitize_standalone' -o \
    -name 'combined_extractor' \
    -o -name 'combined_extractor_sanitize' \
\) -delete
rm -f "$here/validation.log"
