SHELL := /bin/sh
CARGO ?= $(shell command -v cargo 2>/dev/null)
GIT ?= $(shell command -v git 2>/dev/null)
HELM ?= $(shell command -v helm 2>/dev/null)
KUBECTL ?= $(shell command -v kubectl 2>/dev/null)
VALIDATION_KUBECONFIG ?= /dev/null
KUBERNETES_MANIFEST_DIRS ?= k8s kubernetes manifests deploy

VALIDATE_TARGETS := validate-files
ifneq ($(strip $(CARGO)),)
VALIDATE_TARGETS += validate-rust
endif
VALIDATE_TARGETS += validate-helm validate-kubernetes

.PHONY: validate validate-local validation_runner validate-files validate-rust validate-helm validate-kubernetes

validate validate-local validation_runner: $(VALIDATE_TARGETS)
	@echo "Non-mutating validation completed."

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

validate-helm:
	@if [ -d charts ]; then \
		if [ -n "$(HELM)" ] && command -v "$(HELM)" >/dev/null 2>&1; then \
			find charts -mindepth 1 -maxdepth 1 -type d -print | sort | while IFS= read -r chart; do \
				echo "Validating Helm chart: $$chart"; \
				"$(HELM)" lint "$$chart"; \
				"$(HELM)" template "$$(basename "$$chart")" "$$chart" >/dev/null; \
			done; \
		else \
			echo "helm not found; skipping Helm validation."; \
		fi; \
	else \
		echo "charts/ not found; skipping Helm validation."; \
	fi

validate-kubernetes:
	@manifest_found=0; \
	dir_found=0; \
	for dir in $(KUBERNETES_MANIFEST_DIRS); do \
		if [ -d "$$dir" ]; then \
			dir_found=1; \
			for manifest in "$$dir"/*.yaml "$$dir"/*.yml; do \
				[ -e "$$manifest" ] || continue; \
				manifest_found=1; \
			done; \
		fi; \
	done; \
	if [ "$$dir_found" -eq 0 ]; then \
		echo "No Kubernetes manifest directories found; skipping Kubernetes validation."; \
		exit 0; \
	elif [ "$$manifest_found" -eq 0 ]; then \
		echo "No Kubernetes manifest files found; skipping Kubernetes validation."; \
		exit 0; \
	elif [ -z "$(KUBECTL)" ]; then \
		echo "kubectl not found; skipping Kubernetes manifest validation."; \
		exit 0; \
	fi; \
	for dir in $(KUBERNETES_MANIFEST_DIRS); do \
		if [ -d "$$dir" ]; then \
			for manifest in "$$dir"/*.yaml "$$dir"/*.yml; do \
				[ -e "$$manifest" ] || continue; \
				echo "Client-side dry-run validation for Kubernetes manifest: $$manifest"; \
				KUBECONFIG="$(VALIDATION_KUBECONFIG)" "$(KUBECTL)" apply --dry-run=client --validate=false -f "$$manifest" >/dev/null; \
			done; \
		fi; \
	done
