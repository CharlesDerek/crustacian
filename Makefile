SHELL := /bin/sh
CARGO ?= $(shell command -v cargo 2>/dev/null)
GIT ?= $(shell command -v git 2>/dev/null)
HELM ?= $(shell command -v helm 2>/dev/null)
KUBECTL ?= $(shell command -v kubectl 2>/dev/null)
ANSIBLE_PLAYBOOK ?= $(shell command -v ansible-playbook 2>/dev/null)
ANSIBLE_PLAYBOOK_DIR ?= ansible/playbooks
ANSIBLE_VALIDATION_MODE ?= syntax-check
HELM_CHART_DIR ?= charts
VALIDATION_KUBECONFIG ?= /dev/null
KUBERNETES_MANIFEST_DIRS ?= k8s kubernetes manifests deploy
SHELL_VALIDATION_DIRS ?= scripts tests

VALIDATE_TARGETS := validate-files
ifneq ($(strip $(CARGO)),)
VALIDATE_TARGETS += validate-rust
endif
VALIDATE_TARGETS += validate-shell validate-ansible validate-helm validate-kubernetes validate-tests
NON_MUTATING_VALIDATION_TARGETS := validate-files validate-shell validate-ansible validate-helm validate-kubernetes

.PHONY: validate validate-local validate-non-mutating validate-dry-run validation_runner validate-files validate-rust validate-shell validate-ansible validate-helm validate-kubernetes validate-tests

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
			echo "Running Rust validation with cargo check and cargo test..."; \
			"$(CARGO)" check --locked; \
			"$(CARGO)" test --locked; \
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
