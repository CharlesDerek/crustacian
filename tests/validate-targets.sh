#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/crustacian-validation.XXXXXX")
output_file="$tmp_dir/validation-runner.out"
target_output_file="$tmp_dir/validate-non-mutating.out"
dry_run_output_file="$tmp_dir/validate-dry-run.out"
script_output_file="$tmp_dir/validation-script.out"
script_help_output_file="$tmp_dir/validation-script-help.out"
kubectl_skip_output="$tmp_dir/kubectl-skip.out"
kubectl_dry_run_output="$tmp_dir/kubectl-dry-run.out"
kubectl_failure_output="$tmp_dir/kubectl-failure.out"
kubectl_kubeconfig_output="$tmp_dir/kubectl-kubeconfig.out"
kubectl_log="$tmp_dir/kubectl.log"
workflow_output="$tmp_dir/workflow.out"
workflow_actionlint_output="$tmp_dir/workflow-actionlint.out"
workflow_failure_output="$tmp_dir/workflow-failure.out"
actionlint_log="$tmp_dir/actionlint.log"
tofu_skip_output="$tmp_dir/tofu-skip.out"
tofu_output="$tmp_dir/tofu.out"
tofu_failure_output="$tmp_dir/tofu-failure.out"
tofu_log="$tmp_dir/tofu.log"
shell_failure_output="$tmp_dir/shell-failure.out"
markdown_skip_output="$tmp_dir/markdown-skip.out"
markdown_default_output="$tmp_dir/markdown-default.out"
markdown_output="$tmp_dir/markdown.out"
markdown_log="$tmp_dir/markdownlint.log"
helm_empty_output="$tmp_dir/helm-empty.out"
helm_output="$tmp_dir/helm.out"
helm_failure_output="$tmp_dir/helm-failure.out"
helm_log="$tmp_dir/helm.log"
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
		MARKDOWNLINT= \
		ACTIONLINT= \
		TOFU= \
		TERRAFORM= \
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

if ! grep -q "markdownlint not found; skipping documentation validation." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to include documentation validation with a safe skip when markdownlint is unavailable." >&2
	exit 1
fi

if ! grep -q "actionlint not found; completed basic GitHub Actions workflow validation." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to include GitHub Actions workflow validation." >&2
	exit 1
fi

if ! grep -q "OpenTofu/Terraform CLI not found; skipping OpenTofu validation." "$output_file"; then
	cat "$output_file" >&2
	echo "Expected validation_runner to include OpenTofu validation with a safe skip when the CLI is unavailable." >&2
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
		MARKDOWNLINT= \
		ACTIONLINT= \
		TOFU= \
		TERRAFORM= \
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

if ! grep -q "markdownlint not found; skipping documentation validation." "$target_output_file"; then
	cat "$target_output_file" >&2
	echo "Expected validate-non-mutating to include documentation validation with a safe skip when markdownlint is unavailable." >&2
	exit 1
fi

if ! grep -q "actionlint not found; completed basic GitHub Actions workflow validation." "$target_output_file"; then
	cat "$target_output_file" >&2
	echo "Expected validate-non-mutating to include GitHub Actions workflow validation." >&2
	exit 1
fi

if ! grep -q "OpenTofu/Terraform CLI not found; skipping OpenTofu validation." "$target_output_file"; then
	cat "$target_output_file" >&2
	echo "Expected validate-non-mutating to include OpenTofu validation with a safe skip when the CLI is unavailable." >&2
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
		MARKDOWNLINT= \
		ACTIONLINT= \
		TOFU= \
		TERRAFORM= \
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

if ! grep -q "markdownlint not found; skipping documentation validation." "$dry_run_output_file"; then
	cat "$dry_run_output_file" >&2
	echo "Expected validate-dry-run to include documentation validation with a safe skip when markdownlint is unavailable." >&2
	exit 1
fi

if ! grep -q "actionlint not found; completed basic GitHub Actions workflow validation." "$dry_run_output_file"; then
	cat "$dry_run_output_file" >&2
	echo "Expected validate-dry-run to include GitHub Actions workflow validation." >&2
	exit 1
fi

if ! grep -q "OpenTofu/Terraform CLI not found; skipping OpenTofu validation." "$dry_run_output_file"; then
	cat "$dry_run_output_file" >&2
	echo "Expected validate-dry-run to include OpenTofu validation with a safe skip when the CLI is unavailable." >&2
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
		MARKDOWNLINT= \
		ACTIONLINT= \
		TOFU= \
		TERRAFORM= \
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

if ! grep -q "markdownlint not found; skipping documentation validation." "$script_output_file"; then
	cat "$script_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh to include documentation validation with a safe skip when markdownlint is unavailable." >&2
	exit 1
fi

if ! (
	cd "$repo_root"
	sh scripts/validate-non-mutating.sh --help \
		>"$script_help_output_file" 2>&1
); then
	cat "$script_help_output_file" >&2
	exit 1
fi

if ! grep -q "Usage: scripts/validate-non-mutating.sh" "$script_help_output_file"; then
	cat "$script_help_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh --help to describe the validation entry point." >&2
	exit 1
fi

if ! grep -q "client-side dry-run" "$script_help_output_file"; then
	cat "$script_help_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh --help to describe non-mutating Kubernetes validation." >&2
	exit 1
fi

if ! grep -q "Markdown linting" "$script_help_output_file"; then
	cat "$script_help_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh --help to describe documentation validation." >&2
	exit 1
fi

if ! grep -q "GitHub Actions workflow" "$script_help_output_file"; then
	cat "$script_help_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh --help to describe GitHub Actions workflow validation." >&2
	exit 1
fi

if ! grep -q "OpenTofu/Terraform" "$script_help_output_file"; then
	cat "$script_help_output_file" >&2
	echo "Expected scripts/validate-non-mutating.sh --help to describe OpenTofu validation." >&2
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

workflow_dir="$tmp_dir/workflows"
mkdir "$workflow_dir"
cat >"$workflow_dir/ci.yml" <<'WORKFLOW'
name: Example validation
on:
  push:
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
WORKFLOW

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-github-actions \
		ACTIONLINT= \
		GITHUB_WORKFLOW_DIRS="$workflow_dir" \
		>"$workflow_output" 2>&1
); then
	cat "$workflow_output" >&2
	exit 1
fi

if ! grep -q "Checking GitHub Actions workflow structure: $workflow_dir/ci.yml" "$workflow_output"; then
	cat "$workflow_output" >&2
	echo "Expected validate-github-actions to inspect workflow files." >&2
	exit 1
fi

if ! grep -q "actionlint not found; completed basic GitHub Actions workflow validation." "$workflow_output"; then
	cat "$workflow_output" >&2
	echo "Expected validate-github-actions to complete basic validation without actionlint." >&2
	exit 1
fi

fake_actionlint="$tmp_dir/actionlint"
cat >"$fake_actionlint" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$ACTIONLINT_LOG"
SHELL
chmod +x "$fake_actionlint"

if ! (
	cd "$repo_root"
	ACTIONLINT_LOG="$actionlint_log" \
		"${MAKE:-make}" --no-print-directory validate-github-actions \
		ACTIONLINT="$fake_actionlint" \
		GITHUB_WORKFLOW_DIRS="$workflow_dir" \
		>"$workflow_actionlint_output" 2>&1
); then
	cat "$workflow_actionlint_output" >&2
	exit 1
fi

if ! grep -q -- "$workflow_dir/ci.yml" "$actionlint_log"; then
	cat "$workflow_actionlint_output" >&2
	cat "$actionlint_log" >&2
	echo "Expected validate-github-actions to pass workflow files to actionlint." >&2
	exit 1
fi

bad_workflow_dir="$tmp_dir/bad-workflows"
mkdir "$bad_workflow_dir"
cat >"$bad_workflow_dir/missing-jobs.yml" <<'WORKFLOW'
name: Missing jobs
on:
  pull_request:
WORKFLOW

if (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-github-actions \
		ACTIONLINT= \
		GITHUB_WORKFLOW_DIRS="$bad_workflow_dir" \
		>"$workflow_failure_output" 2>&1
); then
	cat "$workflow_failure_output" >&2
	echo "Expected validate-github-actions to fail when a workflow is missing jobs." >&2
	exit 1
fi

if ! grep -q "missing top-level 'jobs:' key" "$workflow_failure_output"; then
	cat "$workflow_failure_output" >&2
	echo "Expected validate-github-actions to explain the missing jobs key." >&2
	exit 1
fi

tf_dir="$tmp_dir/opentofu/kubernetes"
mkdir -p "$tf_dir"
cat >"$tf_dir/main.tf" <<'TERRAFORM'
terraform {
  required_version = ">= 1.6.0"
}

output "example" {
  value = "ok"
}
TERRAFORM

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-opentofu \
		TOFU= \
		TERRAFORM= \
		OPENTOFU_DIRS="$tmp_dir/opentofu" \
		>"$tofu_skip_output" 2>&1
); then
	cat "$tofu_skip_output" >&2
	exit 1
fi

if ! grep -q "OpenTofu/Terraform CLI not found; skipping OpenTofu validation." "$tofu_skip_output"; then
	cat "$tofu_skip_output" >&2
	echo "Expected validate-opentofu to skip safely when no CLI is available." >&2
	exit 1
fi

fake_tofu="$tmp_dir/tofu"
cat >"$fake_tofu" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$TOFU_LOG"
SHELL
chmod +x "$fake_tofu"

if ! (
	cd "$repo_root"
	TOFU_LOG="$tofu_log" \
		"${MAKE:-make}" --no-print-directory validate-opentofu \
		TOFU="$fake_tofu" \
		TERRAFORM= \
		OPENTOFU_DIRS="$tmp_dir/opentofu" \
		>"$tofu_output" 2>&1
); then
	cat "$tofu_output" >&2
	exit 1
fi

if ! grep -q -- "-chdir=$tf_dir fmt -check -recursive" "$tofu_log"; then
	cat "$tofu_output" >&2
	cat "$tofu_log" >&2
	echo "Expected validate-opentofu to run fmt checks." >&2
	exit 1
fi

if ! grep -q -- "init -backend=false -input=false" "$tofu_log"; then
	cat "$tofu_output" >&2
	cat "$tofu_log" >&2
	echo "Expected validate-opentofu to run backend-free init." >&2
	exit 1
fi

if ! grep -q -- "validate" "$tofu_log"; then
	cat "$tofu_output" >&2
	cat "$tofu_log" >&2
	echo "Expected validate-opentofu to run validate." >&2
	exit 1
fi

cat >"$fake_tofu" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$TOFU_LOG"
case "$*" in
	*validate)
		exit 1
		;;
esac
SHELL
chmod +x "$fake_tofu"

if (
	cd "$repo_root"
	TOFU_LOG="$tofu_log" \
		"${MAKE:-make}" --no-print-directory validate-opentofu \
		TOFU="$fake_tofu" \
		TERRAFORM= \
		OPENTOFU_DIRS="$tmp_dir/opentofu" \
		>"$tofu_failure_output" 2>&1
); then
	cat "$tofu_failure_output" >&2
	echo "Expected validate-opentofu to fail when tofu validate fails." >&2
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

if ! grep -q -- "KUBECONFIG=/dev/null args=--kubeconfig /dev/null apply --dry-run=client --validate=false -f $nested_manifest_dir/example.yaml" "$kubectl_log"; then
	cat "$kubectl_dry_run_output" >&2
	cat "$kubectl_log" >&2
	echo "Expected validate-kubernetes to use client-side dry-run with an isolated kubeconfig." >&2
	exit 1
fi

if (
	cd "$repo_root"
	KUBECTL_LOG="$kubectl_log" \
		"${MAKE:-make}" --no-print-directory validate-kubernetes \
		KUBECTL="$fake_kubectl" \
		VALIDATION_KUBECONFIG="$tmp_dir/real-kubeconfig" \
		KUBERNETES_MANIFEST_DIRS="$manifest_dir" \
		>"$kubectl_kubeconfig_output" 2>&1
); then
	cat "$kubectl_kubeconfig_output" >&2
	echo "Expected validate-kubernetes to reject real kubeconfig paths." >&2
	exit 1
fi

if ! grep -q "Refusing Kubernetes validation with VALIDATION_KUBECONFIG=$tmp_dir/real-kubeconfig" "$kubectl_kubeconfig_output"; then
	cat "$kubectl_kubeconfig_output" >&2
	echo "Expected validate-kubernetes to explain the kubeconfig refusal." >&2
	exit 1
fi

cat >"$fake_kubectl" <<'SHELL'
#!/bin/sh
set -eu
printf 'KUBECONFIG=%s args=%s\n' "${KUBECONFIG:-}" "$*" >>"$KUBECTL_LOG"
exit 1
SHELL
chmod +x "$fake_kubectl"

if (
	cd "$repo_root"
	KUBECTL_LOG="$kubectl_log" \
		"${MAKE:-make}" --no-print-directory validate-kubernetes \
		KUBECTL="$fake_kubectl" \
		VALIDATION_KUBECONFIG=/dev/null \
		KUBERNETES_MANIFEST_DIRS="$manifest_dir" \
		>"$kubectl_failure_output" 2>&1
); then
	cat "$kubectl_failure_output" >&2
	echo "Expected validate-kubernetes to fail when client-side dry-run fails." >&2
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

if ! (
	cd "$repo_root"
	"${MAKE:-make}" --no-print-directory validate-docs \
		MARKDOWNLINT= \
		MARKDOWN_VALIDATION_PATHS="$tmp_dir/missing-docs" \
		>"$markdown_skip_output" 2>&1
); then
	cat "$markdown_skip_output" >&2
	exit 1
fi

if ! grep -q "No Markdown documents found; skipping documentation validation." "$markdown_skip_output"; then
	cat "$markdown_skip_output" >&2
	echo "Expected validate-docs to skip safely when there are no Markdown documents." >&2
	exit 1
fi

markdown_dir="$tmp_dir/docs"
mkdir "$markdown_dir"
cat >"$markdown_dir/example.md" <<'MARKDOWN'
# Example
MARKDOWN

fake_markdownlint="$tmp_dir/markdownlint"
cat >"$fake_markdownlint" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$MARKDOWN_LOG"
SHELL
chmod +x "$fake_markdownlint"

if ! (
	cd "$repo_root"
	MARKDOWN_LOG="$markdown_log" \
		"${MAKE:-make}" --no-print-directory validate-docs \
		MARKDOWNLINT="$fake_markdownlint" \
		MARKDOWN_VALIDATION_PATHS="$markdown_dir" \
		>"$markdown_output" 2>&1
); then
	cat "$markdown_output" >&2
	exit 1
fi

if ! grep -q -- "$markdown_dir/example.md" "$markdown_log"; then
	cat "$markdown_output" >&2
	cat "$markdown_log" >&2
	echo "Expected validate-docs to run markdownlint on discovered Markdown files." >&2
	exit 1
fi

: >"$markdown_log"
if ! (
	cd "$repo_root"
	MARKDOWN_LOG="$markdown_log" \
		"${MAKE:-make}" --no-print-directory validate-docs \
		MARKDOWNLINT="$fake_markdownlint" \
		>"$markdown_default_output" 2>&1
); then
	cat "$markdown_default_output" >&2
	exit 1
fi

if ! grep -q -- "ReadMe.md" "$markdown_log"; then
	cat "$markdown_default_output" >&2
	cat "$markdown_log" >&2
	echo "Expected validate-docs defaults to include the checked-in ReadMe.md file." >&2
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

chart_dir="$tmp_dir/charts/example-chart"
mkdir -p "$chart_dir"
cat >"$chart_dir/Chart.yaml" <<'CHART'
apiVersion: v2
name: example-chart
version: 0.1.0
CHART
non_chart_dir="$tmp_dir/charts/not-a-chart"
mkdir -p "$non_chart_dir"

fake_helm="$tmp_dir/helm"
cat >"$fake_helm" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$HELM_LOG"
case "$1" in
	lint|template)
		exit 0
		;;
	*)
		echo "unexpected helm command: $*" >&2
		exit 2
		;;
esac
SHELL
chmod +x "$fake_helm"

if ! (
	cd "$repo_root"
	HELM_LOG="$helm_log" \
		"${MAKE:-make}" --no-print-directory validate-helm \
		HELM="$fake_helm" \
		HELM_CHART_DIR="$tmp_dir/charts" \
		>"$helm_output" 2>&1
); then
	cat "$helm_output" >&2
	exit 1
fi

if ! grep -q -- "lint $chart_dir" "$helm_log"; then
	cat "$helm_output" >&2
	cat "$helm_log" >&2
	echo "Expected validate-helm to lint discovered charts." >&2
	exit 1
fi

if ! grep -q -- "template example-chart $chart_dir" "$helm_log"; then
	cat "$helm_output" >&2
	cat "$helm_log" >&2
	echo "Expected validate-helm to render discovered charts without contacting a cluster." >&2
	exit 1
fi

if grep -q -- "$non_chart_dir" "$helm_log"; then
	cat "$helm_output" >&2
	cat "$helm_log" >&2
	echo "Expected validate-helm to ignore directories without Chart.yaml." >&2
	exit 1
fi

cat >"$fake_helm" <<'SHELL'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$HELM_LOG"
case "$1" in
	lint)
		exit 1
		;;
	template)
		exit 0
		;;
	*)
		echo "unexpected helm command: $*" >&2
		exit 2
		;;
esac
SHELL
chmod +x "$fake_helm"

if (
	cd "$repo_root"
	HELM_LOG="$helm_log" \
		"${MAKE:-make}" --no-print-directory validate-helm \
		HELM="$fake_helm" \
		HELM_CHART_DIR="$tmp_dir/charts" \
		>"$helm_failure_output" 2>&1
); then
	cat "$helm_failure_output" >&2
	echo "Expected validate-helm to fail when helm lint fails." >&2
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
