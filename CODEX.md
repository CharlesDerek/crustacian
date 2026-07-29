# CODEX.md

This file is the MRGI working ledger for detachable Codex repo-improvement loops.

## Operating Rules

- Treat README.md and this CODEX.md as the source of truth for project direction and current stage.
- Each unchecked checkbox is a task from the agent's perspective. Nested checkboxes are valid tasks.
- Prefer the smallest useful change that showcases the repository owner's skillsets.
- Do not erase useful history. Move completed tasks to the completed log.
- If a task fails, keep it unchecked and annotate the latest failure, likely cause, and next attempt.
- Commit only coherent, verified changes. Use clear commit messages and push when a remote is configured.
- Return control to the human between stages with a concise boomerang summary: changed, verified, verdict, suggested next task.

## Current Stage

Stage 3: CI target matrix.

- Status: Complete; ready for Stage 4 selection.
- Completed task: Add CI target matrix for Windows, Linux, and macOS Rust checks.
- Selected next task: Add configurable endpoint retry policy through environment variables.
- Rationale: Configurable retry policy builds on the ingest/backpressure work, showcases Rust configuration design and bounded failure handling, and remains smaller than the dashboard, exporter, or mesh roadmap items.

## Task List

- [ ] Add configurable endpoint retry policy through environment variables

## Active Attempt

- Task: Add configurable endpoint retry policy through environment variables.
- Stage: Selected for Stage 4
- Last result: Repaired Windows-target clippy fallout from the Stage 3 matrix by removing an unused Windows helper, using `io::Error::other` for Windows-only errors, and moving the endpoint test module after Windows config templates.
- Last failure: None.
- Next attempt: Add documented environment variables for endpoint ingest retry attempts, initial backoff, max backoff, and jitter while preserving bounded defaults and tests.

## Completed Log

- Repaired Windows CI matrix failures in `src/main.rs`: removed unused `run_silent`, replaced Windows-only `io::ErrorKind::Other` constructions with `io::Error::other`, and moved the test module after config templates to satisfy `clippy::items-after-test-module`. Verified with `cargo fmt --check`, `cargo test`, `cargo build`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings`.
- Completed CI target matrix in `.github/workflows/rust.yml`: Rust format, clippy, check, and test now run across `ubuntu-latest`, `windows-latest`, and `macos-latest`; repository-wide non-mutating validation remains Ubuntu-only with OpenTofu setup, and the docs-site workflow now watches `README.md`. Verified with PyYAML parsing for all workflow files, `make validate-github-actions`, `make validate-files`, and `git diff --check`; `actionlint` is not installed, so Makefile validation used its basic workflow checks.
- Completed ingest bearer-token authentication in `src/bin/crustacian-ingest.rs`: `CRUSTACIAN_INGEST_TOKEN` and `--bearer-token` now enable opt-in `Authorization: Bearer <token>` enforcement for `POST /v1/ingest`; missing or invalid tokens return HTTP `401`, `/health` remains open for liveness checks, docs describe the configuration, and tests cover no-token local mode plus missing, invalid, valid, and case-insensitive bearer headers. Verified with `cargo fmt --check`, `cargo test`, `cargo build`, and `cargo clippy --locked --bin crustacian-ingest -- -D warnings`.
- Completed Stage 1 hygiene: confirmed `.mrgi` is ignored, normalized the tracked readme filename to `README.md` for MRGI compatibility, and selected exactly one next task.
- Completed stricter ingest telemetry validation in `src/edr_transport.rs`: batch metadata now enforces minimum/non-empty values, endpoint events require the schema fields from `schemas/endpoint-event.schema.json`, boolean recommendation flags must be booleans, confidence must be 0..=1, event schema version is checked, and event endpoint IDs must match the batch endpoint ID. Verified with `cargo fmt --check`, `cargo test`, and `cargo build`.
