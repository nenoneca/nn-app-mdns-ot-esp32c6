#!/usr/bin/env bash
# One-command build. Resolves deps (env/flag/auto-fetch) via the nn-app-build
# submodule. See ./.nn-build/README.md.  Usage: ./build.sh [--version X] ...
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -f .nn-build/nn-build.sh ]]; then
	git submodule update --init --recursive .nn-build
fi
exec ./.nn-build/nn-build.sh --app-repo "$(pwd)" "$@"
