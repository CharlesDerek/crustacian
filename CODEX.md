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

Stage 4: configurable retry policy and replay-safe ingest.

- Status: Complete; ready for Stage 5 selection.
- Completed task: Add bounded endpoint retry policy, strict acknowledgements,
  serialized spool delivery, and replay-safe server persistence.
- Selected next task: Replace the file-backed ingest event ID scan with a
  transactional indexed store once ingest volume requires it.

## Task List

- [x] Add configurable endpoint retry policy through environment variables

## Active Attempt

- Task: Add configurable endpoint retry policy and replay-safe ingest.
- Stage: Completed Stage 4
- Last result: Added bounded environment settings, refused incomplete success
  acknowledgements, serialized send attempts, retained changed spool prefixes,
  and deduplicated ingested event IDs under an exclusive lock.
- Last failure: None.
- Next attempt: Measure ingest data volume and choose an indexed transactional
  store if the NDJSON scan becomes the limiting factor.

## Completed Log

- 2026-09-24: Completed Stage 4 endpoint delivery reliability. Configurable
  retry settings are bounded and validated; full server acknowledgement is
  required before compaction; delivery attempts are serialized; the server
  deduplicates replayed event IDs, repairs incomplete trailing records, and
  rejects oversized or ambiguous HTTP request bodies.
  Verified with `cargo build`, `cargo test --all-targets`, and
  `cargo clippy --all-targets -- -D warnings`.
- Repaired Windows CI matrix failures in `src/main.rs`: removed unused `run_silent`, replaced Windows-only `io::ErrorKind::Other` constructions with `io::Error::other`, and moved the test module after config templates to satisfy `clippy::items-after-test-module`. Verified with `cargo fmt --check`, `cargo test`, `cargo build`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings`.
- Completed CI target matrix in `.github/workflows/rust.yml`: Rust format, clippy, check, and test now run across `ubuntu-latest`, `windows-latest`, and `macos-latest`; repository-wide non-mutating validation remains Ubuntu-only with OpenTofu setup, and the docs-site workflow now watches `README.md`. Verified with PyYAML parsing for all workflow files, `make validate-github-actions`, `make validate-files`, and `git diff --check`; `actionlint` is not installed, so Makefile validation used its basic workflow checks.
- Completed ingest bearer-token authentication in `src/bin/crustacian-ingest.rs`: `CRUSTACIAN_INGEST_TOKEN` and `--bearer-token` now enable opt-in `Authorization: Bearer <token>` enforcement for `POST /v1/ingest`; missing or invalid tokens return HTTP `401`, `/health` remains open for liveness checks, docs describe the configuration, and tests cover no-token local mode plus missing, invalid, valid, and case-insensitive bearer headers. Verified with `cargo fmt --check`, `cargo test`, `cargo build`, and `cargo clippy --locked --bin crustacian-ingest -- -D warnings`.
- Completed Stage 1 hygiene: confirmed `.mrgi` is ignored, normalized the tracked readme filename to `README.md` for MRGI compatibility, and selected exactly one next task.
- Completed stricter ingest telemetry validation in `src/edr_transport.rs`: batch metadata now enforces minimum/non-empty values, endpoint events require the schema fields from `schemas/endpoint-event.schema.json`, boolean recommendation flags must be booleans, confidence must be 0..=1, event schema version is checked, and event endpoint IDs must match the batch endpoint ID. Verified with `cargo fmt --check`, `cargo test`, and `cargo build`.
