# Optional Dependencies

Crustacian can run without the following optional endpoint tools, but related
automation or validation workflows may be unavailable when they are missing.

Run `make validate-non-mutating` for repository-local validation that does not
contact or mutate a real cluster. The target uses file checks, shell syntax
checks, Ansible syntax-check validation when `ansible-playbook` is available,
Helm lint/template validation when `helm` is available, and client-side
Kubernetes manifest dry-run validation when `kubectl` is available. Missing
optional tools are reported as skips. `make validate-dry-run` is available as a
descriptive alias for the same non-mutating checks.

Run `scripts/validate-non-mutating.sh` for the same Makefile validation from a
script entry point. The Ansible check uses `ansible-playbook --syntax-check` by
default, or `ansible-playbook --check` when `ANSIBLE_VALIDATION_MODE=check` is
set. Destructive playbooks are excluded from this validation path.

| Dependency | Status on endpoint host | Notes |
| ---------- | ----------------------- | ----- |
| `helm` | Not detected | Required only for Helm chart linting, rendering, or other Helm-specific validation workflows. |
| `ansible-playbook` | Not detected | Required only for Ansible playbook syntax-check or check-mode validation workflows. |
| `yq` | Not detected | Required only for YAML query, transformation, or validation workflows that explicitly call `yq`. |
| `jq` | Not detected | Required only for JSON query, transformation, or validation workflows that explicitly call `jq`. |
