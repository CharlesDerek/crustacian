#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
make_bin=${MAKE:-make}

"$make_bin" --no-print-directory -C "$repo_root" validate-non-mutating "$@"
sh "$repo_root/scripts/validate-ansible-playbooks.sh"
