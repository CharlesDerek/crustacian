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

Stage 2: Ingest bearer-token authentication.

- Status: Complete; ready for Stage 3 selection.
- Completed task: Add ingest authentication validation for bearer-token protected intake.
- Selected next task: Add CI target matrix for Windows, Linux, and macOS Rust checks.
- Rationale: A target matrix showcases Rust CI discipline, makes the README's cross-platform direction measurable, and should surface platform-specific gaps before larger endpoint work expands.

## Task List

- [ ] Add CI target matrix for Windows, Linux, and macOS Rust checks

## Active Attempt

- Task: Add CI target matrix for Windows, Linux, and macOS Rust checks.
- Stage: Selected for Stage 3
- Last result: Stage 2 completed opt-in server-side bearer-token enforcement for `POST /v1/ingest`, updated docs, and added unit tests for missing, invalid, and valid authorization headers. Verification passed with `cargo fmt --check`, `cargo test`, `cargo build`, and `cargo clippy --locked --bin crustacian-ingest -- -D warnings`.
- Last failure: None.
- Next attempt: Update the Rust CI workflow to run appropriate checks across Windows, Linux, and macOS, accounting for platform-specific runtime behavior without claiming unsupported features.

## Completed Log

- Completed ingest bearer-token authentication in `src/bin/crustacian-ingest.rs`: `CRUSTACIAN_INGEST_TOKEN` and `--bearer-token` now enable opt-in `Authorization: Bearer <token>` enforcement for `POST /v1/ingest`; missing or invalid tokens return HTTP `401`, `/health` remains open for liveness checks, docs describe the configuration, and tests cover no-token local mode plus missing, invalid, valid, and case-insensitive bearer headers. Verified with `cargo fmt --check`, `cargo test`, `cargo build`, and `cargo clippy --locked --bin crustacian-ingest -- -D warnings`.
- Completed Stage 1 hygiene: confirmed `.mrgi` is ignored, normalized the tracked readme filename to `README.md` for MRGI compatibility, and selected exactly one next task.
- Completed stricter ingest telemetry validation in `src/edr_transport.rs`: batch metadata now enforces minimum/non-empty values, endpoint events require the schema fields from `schemas/endpoint-event.schema.json`, boolean recommendation flags must be booleans, confidence must be 0..=1, event schema version is checked, and event endpoint IDs must match the batch endpoint ID. Verified with `cargo fmt --check`, `cargo test`, and `cargo build`.
