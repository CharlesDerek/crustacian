SHELL := /bin/sh
CARGO ?= $(shell command -v cargo 2>/dev/null)
GIT ?= $(shell command -v git 2>/dev/null)
HELM ?= $(shell command -v helm 2>/dev/null)
KUBECTL ?= $(shell command -v kubectl 2>/dev/null)
ANSIBLE_PLAYBOOK ?= $(shell command -v ansible-playbook 2>/dev/null)
MARKDOWNLINT ?= $(shell command -v markdownlint 2>/dev/null)
ACTIONLINT ?= $(shell command -v actionlint 2>/dev/null)
TOFU ?= $(shell command -v tofu 2>/dev/null)
TERRAFORM ?= $(shell command -v terraform 2>/dev/null)
ANSIBLE_PLAYBOOK_DIR ?= ansible/playbooks
ANSIBLE_VALIDATION_MODE ?= syntax-check
HELM_CHART_DIR ?= charts
VALIDATION_KUBECONFIG ?= /dev/null
KUBERNETES_MANIFEST_DIRS ?= k8s kubernetes manifests deploy
SHELL_VALIDATION_DIRS ?= scripts tests
MARKDOWN_VALIDATION_PATHS ?= README.md docs
GITHUB_WORKFLOW_DIRS ?= .github/workflows
OPENTOFU_DIRS ?= infra/opentofu tofu opentofu terraform infra/terraform

VALIDATE_TARGETS := validate-files
ifneq ($(strip $(CARGO)),)
VALIDATE_TARGETS += validate-rust
endif
VALIDATE_TARGETS += validate-shell validate-github-actions validate-opentofu validate-ansible validate-helm validate-kubernetes validate-tests
NON_MUTATING_VALIDATION_TARGETS := validate-files validate-shell validate-docs validate-github-actions validate-opentofu validate-ansible validate-helm validate-kubernetes

.PHONY: validate validate-local validate-non-mutating validate-dry-run validation_runner validate-files validate-rust validate-shell validate-docs validate-github-actions validate-opentofu validate-ansible validate-helm validate-kubernetes validate-tests

validate validate-local: $(VALIDATE_TARGETS)
	@echo "Non-mutating validation completed."

validate-non-mutating: $(NON_MUTATING_VALIDATION_TARGETS)
	@echo "Non-mutating validation completed."

validate-dry-run: validate-non-mutating

validation_runner: validate-non-mutating

validate-files:
	@if [ -n "$(GIT)" ] && "$(GIT)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		echo "Checking working tree diff for whitespace errors..."; \
		"$(GIT)" diff --check; \
	else \
		echo "git work tree not available; skipping file validation."; \
	fi

validate-rust:
	@if [ -f Cargo.toml ]; then \
		if [ -n "$(CARGO)" ] && command -v "$(CARGO)" >/dev/null 2>&1; then \
			echo "Running Rust validation with cargo fmt, clippy, check, and test..."; \
			status=0; \
			if "$(CARGO)" fmt --version >/dev/null 2>&1; then \
				"$(CARGO)" fmt --check || status=1; \
			else \
				echo "cargo fmt not available; skipping Rust formatting validation."; \
			fi; \
			if "$(CARGO)" clippy --version >/dev/null 2>&1; then \
				"$(CARGO)" clippy --locked --all-targets -- -D warnings || status=1; \
			else \
				echo "cargo clippy not available; skipping Rust lint validation."; \
			fi; \
			"$(CARGO)" check --locked || status=1; \
			"$(CARGO)" test --locked || status=1; \
			exit "$$status"; \
		else \
			echo "cargo not found; skipping Rust validation."; \
		fi; \
	else \
		echo "Cargo.toml not found; skipping Rust validation."; \
	fi

validate-shell:
	@files_file=$$(mktemp "$${TMPDIR:-/tmp}/crustacian-shell-validation.XXXXXX"); \
	trap 'rm -f "$$files_file"' EXIT HUP INT TERM; \
	for dir in $(SHELL_VALIDATION_DIRS); do \
		if [ -d "$$dir" ]; then \
			find "$$dir" -type f \( -name '*.sh' -o -perm -111 \) -print; \
		fi; \
	done | sort >"$$files_file"; \
	if [ ! -s "$$files_file" ]; then \
		echo "No shell scripts found; skipping shell syntax validation."; \
		exit 0; \
	fi; \
	status=0; \
	while IFS= read -r script; do \
		echo "Checking shell script syntax: $$script"; \
		sh -n "$$script" || status=1; \
	done <"$$files_file"; \
	exit "$$status"

validate-docs:
	@docs_file=$$(mktemp "$${TMPDIR:-/tmp}/crustacian-doc-validation.XXXXXX"); \
	trap 'rm -f "$$docs_file"' EXIT HUP INT TERM; \
	for path in $(MARKDOWN_VALIDATION_PATHS); do \
		if [ -f "$$path" ]; then \
			printf '%s\n' "$$path"; \
		elif [ -d "$$path" ]; then \
			find "$$path" -type f \( -name '*.md' -o -name '*.markdown' \) -print; \
		fi; \
	done | sort >"$$docs_file"; \
	if [ ! -s "$$docs_file" ]; then \
		echo "No Markdown documents found; skipping documentation validation."; \
		exit 0; \
	elif [ -z "$(MARKDOWNLINT)" ] || ! command -v "$(MARKDOWNLINT)" >/dev/null 2>&1; then \
		echo "markdownlint not found; skipping documentation validation."; \
		exit 0; \
	fi; \
	echo "Running Markdown validation with markdownlint..."; \
	xargs "$(MARKDOWNLINT)" <"$$docs_file"

validate-github-actions:
	@workflows_file=$$(mktemp "$${TMPDIR:-/tmp}/crustacian-github-workflows.XXXXXX"); \
	trap 'rm -f "$$workflows_file"' EXIT HUP INT TERM; \
	dir_found=0; \
	for dir in $(GITHUB_WORKFLOW_DIRS); do \
		if [ -d "$$dir" ]; then \
			dir_found=1; \
			find "$$dir" -type f \( -name '*.yml' -o -name '*.yaml' \) -print >>"$$workflows_file"; \
		fi; \
	done; \
	sort "$$workflows_file" -o "$$workflows_file"; \
	if [ "$$dir_found" -eq 0 ]; then \
		echo "No GitHub workflow directories found; skipping GitHub Actions validation."; \
		exit 0; \
	elif [ ! -s "$$workflows_file" ]; then \
		echo "No GitHub workflow files found; skipping GitHub Actions validation."; \
		exit 0; \
	fi; \
	status=0; \
	while IFS= read -r workflow; do \
		echo "Checking GitHub Actions workflow structure: $$workflow"; \
		if grep -n '	' "$$workflow"; then \
			echo "GitHub Actions workflow contains tab indentation: $$workflow" >&2; \
			status=1; \
		fi; \
		for key in name on jobs; do \
			if ! grep -Eq "^$$key:" "$$workflow"; then \
				echo "GitHub Actions workflow missing top-level '$$key:' key: $$workflow" >&2; \
				status=1; \
			fi; \
		done; \
	done <"$$workflows_file"; \
	if [ "$$status" -ne 0 ]; then \
		exit "$$status"; \
	fi; \
	if [ -n "$(ACTIONLINT)" ] && command -v "$(ACTIONLINT)" >/dev/null 2>&1; then \
		echo "Running GitHub Actions validation with actionlint..."; \
		xargs "$(ACTIONLINT)" <"$$workflows_file"; \
	else \
		echo "actionlint not found; completed basic GitHub Actions workflow validation."; \
	fi

validate-opentofu:
	@tf_dirs_file=$$(mktemp "$${TMPDIR:-/tmp}/crustacian-opentofu-dirs.XXXXXX"); \
	trap 'rm -f "$$tf_dirs_file"' EXIT HUP INT TERM; \
	for dir in $(OPENTOFU_DIRS); do \
		if [ -d "$$dir" ]; then \
			find "$$dir" -type f -name '*.tf' -exec dirname {} \; >>"$$tf_dirs_file"; \
		fi; \
	done; \
	sort -u "$$tf_dirs_file" -o "$$tf_dirs_file"; \
	if [ ! -s "$$tf_dirs_file" ]; then \
		echo "No OpenTofu/Terraform files found; skipping OpenTofu validation."; \
		exit 0; \
	fi; \
	tf_bin="$(TOFU)"; \
	if [ -z "$$tf_bin" ]; then \
		tf_bin="$(TERRAFORM)"; \
	fi; \
	if [ -z "$$tf_bin" ] || ! command -v "$$tf_bin" >/dev/null 2>&1; then \
		echo "OpenTofu/Terraform CLI not found; skipping OpenTofu validation."; \
		exit 0; \
	fi; \
	status=0; \
	while IFS= read -r tf_dir; do \
		echo "Validating OpenTofu/Terraform directory: $$tf_dir"; \
		"$$tf_bin" -chdir="$$tf_dir" fmt -check -recursive || status=1; \
		work_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/crustacian-opentofu-work.XXXXXX"); \
		cp -R "$$tf_dir/." "$$work_dir/"; \
		"$$tf_bin" -chdir="$$work_dir" init -backend=false -input=false || status=1; \
		"$$tf_bin" -chdir="$$work_dir" validate || status=1; \
		rm -rf "$$work_dir"; \
	done <"$$tf_dirs_file"; \
	exit "$$status"

validate-tests:
	@echo "Running validation target self-checks..."
	@sh tests/validate-targets.sh

validate-ansible:
	@ANSIBLE_PLAYBOOK="$(ANSIBLE_PLAYBOOK)" \
		ANSIBLE_PLAYBOOK_DIR="$(ANSIBLE_PLAYBOOK_DIR)" \
		ANSIBLE_VALIDATION_MODE="$(ANSIBLE_VALIDATION_MODE)" \
		sh scripts/validate-ansible-playbooks.sh

validate-helm:
	@if [ -d "$(HELM_CHART_DIR)" ]; then \
		charts_file=$$(mktemp "$${TMPDIR:-/tmp}/crustacian-helm-charts.XXXXXX"); \
		trap 'rm -f "$$charts_file"' EXIT HUP INT TERM; \
		find "$(HELM_CHART_DIR)" -mindepth 1 -maxdepth 1 -type d -print | while IFS= read -r chart; do \
			if [ -f "$$chart/Chart.yaml" ]; then \
				printf '%s\n' "$$chart"; \
			fi; \
		done | sort >"$$charts_file"; \
		if [ ! -s "$$charts_file" ]; then \
			echo "No Helm charts found; skipping Helm validation."; \
			exit 0; \
		fi; \
		if [ -n "$(HELM)" ] && command -v "$(HELM)" >/dev/null 2>&1; then \
			status=0; \
			while IFS= read -r chart; do \
				echo "Validating Helm chart: $$chart"; \
				"$(HELM)" lint "$$chart" || status=1; \
				"$(HELM)" template "$$(basename "$$chart")" "$$chart" >/dev/null || status=1; \
			done <"$$charts_file"; \
			exit "$$status"; \
		else \
			echo "helm not found; skipping Helm validation."; \
		fi; \
	else \
		echo "$(HELM_CHART_DIR) not found; skipping Helm validation."; \
	fi

validate-kubernetes:
	@manifests_file=$$(mktemp "$${TMPDIR:-/tmp}/crustacian-kubernetes-manifests.XXXXXX"); \
	trap 'rm -f "$$manifests_file"' EXIT HUP INT TERM; \
	dir_found=0; \
	for dir in $(KUBERNETES_MANIFEST_DIRS); do \
		if [ -d "$$dir" ]; then \
			dir_found=1; \
			find "$$dir" -type f \( -name '*.yaml' -o -name '*.yml' \) -print >>"$$manifests_file"; \
		fi; \
	done; \
	sort "$$manifests_file" -o "$$manifests_file"; \
	if [ "$$dir_found" -eq 0 ]; then \
		echo "No Kubernetes manifest directories found; skipping Kubernetes validation."; \
		exit 0; \
	elif [ ! -s "$$manifests_file" ]; then \
		echo "No Kubernetes manifest files found; skipping Kubernetes validation."; \
		exit 0; \
	elif [ -z "$(KUBECTL)" ]; then \
		echo "kubectl not found; skipping Kubernetes manifest validation."; \
		exit 0; \
	elif [ "$(VALIDATION_KUBECONFIG)" != "/dev/null" ]; then \
		echo "Refusing Kubernetes validation with VALIDATION_KUBECONFIG=$(VALIDATION_KUBECONFIG); use /dev/null for non-mutating validation."; \
		exit 2; \
	fi; \
	status=0; \
	while IFS= read -r manifest; do \
		echo "Client-side dry-run validation for Kubernetes manifest: $$manifest"; \
		KUBECONFIG="$(VALIDATION_KUBECONFIG)" "$(KUBECTL)" --kubeconfig "$(VALIDATION_KUBECONFIG)" apply --dry-run=client --validate=false -f "$$manifest" >/dev/null || status=1; \
	done <"$$manifests_file"; \
	exit "$$status"
