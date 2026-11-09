#!/usr/bin/env bash
set -euo pipefail
exec python3 -B "$(dirname "$0")/portable_build.py" "$@"
