#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/crustacian-validation.XXXXXX")
output_file="$tmp_dir/validation-runner.out"

cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validation_runner \
		CARGO= \
		HELM= \
		KUBECTL= \
		KUBERNETES_MANIFEST_DIRS="$tmp_dir/missing-manifests" \
		>"$output_file" 2>&1
); then
	cat "$output_file" >&2
	exit 1
fi

if ! grep -q "No Kubernetes manifest directories found; skipping Kubernetes validation." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to skip Kubernetes validation without manifest directories." >&2
	exit 1
fi

if ! grep -Eq "(charts/ not found|helm not found); skipping Helm validation." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to skip Helm validation when Helm validation cannot run." >&2
	exit 1
fi

if grep -q "Running Rust validation" "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to avoid Rust validation." >&2
	exit 1
fi

if ! grep -q "Checking shell script syntax: tests/validate-targets.sh" "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to run shell syntax validation." >&2
	exit 1
fi

if ! grep -q "Non-mutating validation completed." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to complete successfully." >&2
	exit 1
fi
