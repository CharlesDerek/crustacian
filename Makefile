SHELL := /bin/sh
CARGO ?= $(shell command -v cargo 2>/dev/null)
HELM ?= $(shell command -v helm 2>/dev/null)

.PHONY: validate validate-rust validate-helm

validate: validate-rust validate-helm
	@echo "Non-mutating validation completed."

validate-rust:
	@if [ -f Cargo.toml ]; then \
		if [ -n "$(CARGO)" ]; then \
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
		if [ -n "$(HELM)" ]; then \
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
