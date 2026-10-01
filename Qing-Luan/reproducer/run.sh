#!/usr/bin/env bash
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$here/build_and_run.sh" | tee "$here/validation.log"
