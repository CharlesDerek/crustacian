#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
make_bin=${MAKE:-make}

case "${1:-}" in
	-h|--help)
		cat <<'USAGE'
Usage: scripts/validate-non-mutating.sh [MAKE_VAR=value ...]

Runs the repo-local validate-non-mutating Makefile target.

The target uses file checks, shell syntax checks, Ansible syntax/check mode,
Markdown linting, Helm lint/template rendering, and kubectl client-side dry-run
validation when the related tools and files are available. Missing optional
tools or directories are skipped with a no-op message.
USAGE
		exit 0
		;;
esac

"$make_bin" --no-print-directory -C "$repo_root" validate-non-mutating "$@"
