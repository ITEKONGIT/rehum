#!/usr/bin/env bash
set -euo pipefail

project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$project_directory"
if command -v python3 >/dev/null 2>&1; then
    exec python3 rehum.py "$@"
elif command -v python >/dev/null 2>&1; then
    exec python rehum.py "$@"
else
    echo "error: Python 3 was not found. Install Python 3.11 or newer." >&2
    exit 1
fi
