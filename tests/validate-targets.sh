#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/crustacian-validation.XXXXXX")
output_file="$tmp_dir/validation-runner.out"
target_output_file="$tmp_dir/validate-non-mutating.out"
dry_run_output_file="$tmp_dir/validate-dry-run.out"
script_output_file="$tmp_dir/validation-script.out"
kubectl_skip_output="$tmp_dir/kubectl-skip.out"
kubectl_dry_run_output="$tmp_dir/kubectl-dry-run.out"
kubectl_log="$tmp_dir/kubectl.log"
shell_failure_output="$tmp_dir/shell-failure.out"
helm_empty_output="$tmp_dir/helm-empty.out"
ansible_skip_output="$tmp_dir/ansible-skip.out"
ansible_syntax_output="$tmp_dir/ansible-syntax.out"
ansible_check_output="$tmp_dir/ansible-check.out"
ansible_log="$tmp_dir/ansible-playbook.log"
git_diff_output="$tmp_dir/git-diff-check.out"
git_log="$tmp_dir/git.log"

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

if ! grep -Eq "(charts not found|helm not found); skipping Helm validation." "$output_file"; then
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

if ! grep -q "No Ansible playbook directory found; skipping Ansible validation." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to include Ansible playbook validation." >&2
	exit 1
fi

if ! grep -q "Non-mutating validation completed." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to complete successfully." >&2
	exit 1
fi

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-non-mutating \
		CARGO= \
		HELM= \
		KUBECTL= \
		KUBERNETES_MANIFEST_DIRS="$tmp_dir/missing-manifests" \
		>"$target_output_file" 2>&1
); then
	cat "$target_output_file" >&2
	exit 1
fi

if ! grep -q "No Kubernetes manifest directories found; skipping Kubernetes validation." "$target_output_file"; then
	cat "$target_output_file" >&2
	echo "Expected validate-non-mutating to skip Kubernetes validation without manifest directories." >&2
	exit 1
fi

if grep -q "Running Rust validation" "$target_output_file"; then
	cat "$target_output_file" >&2
	echo "Expected validate-non-mutating to avoid Rust validation." >&2
	exit 1
fi

if ! grep -q "Non-mutating validation completed." "$target_output_file"; then
	cat "$target_output_file" >&2
	echo "Expected validate-non-mutating to complete successfully." >&2
	exit 1
fi

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-dry-run \
		CARGO= \
		HELM= \
		KUBECTL= \
		KUBERNETES_MANIFEST_DIRS="$tmp_dir/missing-manifests" \
		>"$dry_run_output_file" 2>&1
); then
	cat "$dry_run_output_file" >&2
	exit 1
fi

if ! grep -q "No Kubernetes manifest directories found; skipping Kubernetes validation." "$dry_run_output_file"; then
	cat "$dry_run_output_file" >&2
	echo "Expected validate-dry-run to skip Kubernetes validation without manifest directories." >&2
	exit 1
fi

if grep -q "Running Rust validation" "$dry_run_output_file"; then
	cat "$dry_run_output_file" >&2
	echo "Expected validate-dry-run to avoid Rust validation." >&2
	exit 1
fi

if ! grep -q "Non-mutating validation completed." "$dry_run_output_file"; then
	cat "$dry_run_output_file" >&2
	echo "Expected validate-dry-run to complete successfully." >&2
	exit 1
fi

if ! (
	cd "$repo_root"
	MAKE="${MAKE:-make}" sh scripts/validate-non-mutating.sh \
		CARGO= \
		HELM= \
		KUBECTL= \
		KUBERNETES_MANIFEST_DIRS="$tmp_dir/missing-manifests" \
		>"$script_output_file" 2>&1
); then
	cat "$script_output_file" >&2
	exit 1
fi

if ! grep -q "Non-mutating validation completed." "$script_output_file"; then
	cat "$script_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh to complete successfully." >&2
	exit 1
fi

if ! grep -q "No Ansible playbook directory found; skipping Ansible validation." "$script_output_file"; then
	cat "$script_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh to include Ansible playbook validation." >&2
	exit 1
fi

fake_git="$tmp_dir/git"
cat >"$fake_git" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$GIT_LOG"
case "$*" in
	"rev-parse --is-inside-work-tree")
		printf 'true\n'
		;;
	"diff --check")
		;;
	*)
		echo "unexpected git args: $*" >&2
		exit 2
		;;
esac
SHELL
chmod +x "$fake_git"

if ! (
	cd "$repo_root"
	GIT_LOG="$git_log" \
		"${MAKE:-make}" --no-print-directory validate-files \
		GIT="$fake_git" \
		>"$git_diff_output" 2>&1
); then
	cat "$git_diff_output" >&2
	exit 1
fi

if ! grep -q "diff --check" "$git_log"; then
	cat "$git_diff_output" >&2
	cat "$git_log" >&2
	echo "Expected validate-files to run git diff --check." >&2
	exit 1
fi

manifest_dir="$tmp_dir/manifests"
nested_manifest_dir="$manifest_dir/nested"
mkdir -p "$nested_manifest_dir"
cat >"$nested_manifest_dir/example.yaml" <<'MANIFEST'
apiVersion: v1
kind: ConfigMap
metadata:
  name: validation-example
MANIFEST

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-kubernetes \
		KUBECTL= \
		KUBERNETES_MANIFEST_DIRS="$manifest_dir" \
		>"$kubectl_skip_output" 2>&1
); then
	cat "$kubectl_skip_output" >&2
	exit 1
fi

if ! grep -q "kubectl not found; skipping Kubernetes manifest validation." "$kubectl_skip_output"; then
	cat "$kubectl_skip_output" >&2
	echo "Expected validate-kubernetes to skip safely when kubectl is unavailable." >&2
	exit 1
fi

fake_kubectl="$tmp_dir/kubectl"
cat >"$fake_kubectl" <<'SHELL'
#!/bin/sh
set -eu
printf 'KUBECONFIG=%s args=%s\n' "${KUBECONFIG:-}" "$*" >>"$KUBECTL_LOG"
SHELL
chmod +x "$fake_kubectl"

if ! (
	cd "$repo_root"
	KUBECTL_LOG="$kubectl_log" \
		"${MAKE:-make}" --no-print-directory validate-kubernetes \
		KUBECTL="$fake_kubectl" \
		VALIDATION_KUBECONFIG=/dev/null \
		KUBERNETES_MANIFEST_DIRS="$manifest_dir" \
		>"$kubectl_dry_run_output" 2>&1
); then
	cat "$kubectl_dry_run_output" >&2
	exit 1
fi

if ! grep -q -- "KUBECONFIG=/dev/null args=apply --dry-run=client --validate=false -f $nested_manifest_dir/example.yaml" "$kubectl_log"; then
	cat "$kubectl_dry_run_output" >&2
	cat "$kubectl_log" >&2
	echo "Expected validate-kubernetes to use client-side dry-run with an isolated kubeconfig." >&2
	exit 1
fi

bad_shell_dir="$tmp_dir/bad-shell"
mkdir "$bad_shell_dir"
cat >"$bad_shell_dir/invalid.sh" <<'SHELL'
if true; then
	echo "missing fi"
SHELL

if (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-shell \
		SHELL_VALIDATION_DIRS="$bad_shell_dir" \
		>"$shell_failure_output" 2>&1
); then
	cat "$shell_failure_output" >&2
	echo "Expected validate-shell to fail when any checked shell script is invalid." >&2
	exit 1
fi

if ! grep -q "Checking shell script syntax: $bad_shell_dir/invalid.sh" "$shell_failure_output"; then
	cat "$shell_failure_output" >&2
	echo "Expected validate-shell to report the invalid shell script path." >&2
	exit 1
fi

empty_chart_dir="$tmp_dir/empty-charts"
mkdir "$empty_chart_dir"

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-helm \
		HELM= \
		HELM_CHART_DIR="$empty_chart_dir" \
		>"$helm_empty_output" 2>&1
); then
	cat "$helm_empty_output" >&2
	exit 1
fi

if ! grep -q "No Helm charts found; skipping Helm validation." "$helm_empty_output"; then
	cat "$helm_empty_output" >&2
	echo "Expected validate-helm to skip safely when the chart directory is empty." >&2
	exit 1
fi

if ! (
	cd "$repo_root"
	ANSIBLE_PLAYBOOK_DIR="$tmp_dir/missing-playbooks" sh scripts/validate-ansible-playbooks.sh \
		>"$ansible_skip_output" 2>&1
); then
	cat "$ansible_skip_output" >&2
	exit 1
fi

if ! grep -q "No Ansible playbook directory found; skipping Ansible validation." "$ansible_skip_output"; then
	cat "$ansible_skip_output" >&2
	echo "Expected Ansible validation to skip safely without a playbook directory." >&2
	exit 1
fi

ansible_playbook_dir="$tmp_dir/playbooks"
mkdir "$ansible_playbook_dir"
cat >"$ansible_playbook_dir/site.yml" <<'PLAYBOOK'
---
- hosts: localhost
  gather_facts: false
  tasks: []
PLAYBOOK
cat >"$ansible_playbook_dir/destroy-cluster.yml" <<'PLAYBOOK'
---
- hosts: localhost
  gather_facts: false
  tasks: []
PLAYBOOK

fake_ansible_playbook="$tmp_dir/ansible-playbook"
cat >"$fake_ansible_playbook" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$ANSIBLE_LOG"
SHELL
chmod +x "$fake_ansible_playbook"

if ! (
	cd "$repo_root"
	ANSIBLE_LOG="$ansible_log" \
	ANSIBLE_PLAYBOOK="$fake_ansible_playbook" \
	ANSIBLE_PLAYBOOK_DIR="$ansible_playbook_dir" \
		sh scripts/validate-ansible-playbooks.sh \
		>"$ansible_syntax_output" 2>&1
); then
	cat "$ansible_syntax_output" >&2
	exit 1
fi

if ! grep -q -- "--syntax-check $ansible_playbook_dir/site.yml" "$ansible_log"; then
	cat "$ansible_syntax_output" >&2
	cat "$ansible_log" >&2
	echo "Expected Ansible validation to run syntax-check for non-destructive playbooks." >&2
	exit 1
fi

if grep -q "destroy-cluster" "$ansible_log"; then
	cat "$ansible_log" >&2
	echo "Expected Ansible validation to exclude destructive playbooks." >&2
	exit 1
fi

: >"$ansible_log"
if ! (
	cd "$repo_root"
	ANSIBLE_LOG="$ansible_log" \
	ANSIBLE_PLAYBOOK="$fake_ansible_playbook" \
	ANSIBLE_PLAYBOOK_DIR="$ansible_playbook_dir" \
	ANSIBLE_VALIDATION_MODE=check \
		sh scripts/validate-ansible-playbooks.sh \
		>"$ansible_check_output" 2>&1
); then
	cat "$ansible_check_output" >&2
	exit 1
fi

if ! grep -q -- "--check $ansible_playbook_dir/site.yml" "$ansible_log"; then
	cat "$ansible_check_output" >&2
	cat "$ansible_log" >&2
	echo "Expected Ansible validation check mode to use --check." >&2
	exit 1
fi
