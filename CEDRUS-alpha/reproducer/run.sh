#!/bin/sh
# Compatibility entry point retained for previously published instructions.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$here/run_all.sh" "$@"
