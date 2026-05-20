# Optional Dependencies

Crustacian can run without the following optional endpoint tools, but related
automation or validation workflows may be unavailable when they are missing.

Run `make validate-non-mutating` for repository-local validation that does not
contact or mutate a real cluster. The target uses file checks, Helm lint/template
validation when `helm` is available, and client-side Kubernetes manifest dry-run
validation when `kubectl` is available. Missing optional tools are reported as
skips.

| Dependency | Status on endpoint host | Notes |
| ---------- | ----------------------- | ----- |
| `helm` | Not detected | Required only for Helm chart linting, rendering, or other Helm-specific validation workflows. |
| `yq` | Not detected | Required only for YAML query, transformation, or validation workflows that explicitly call `yq`. |
