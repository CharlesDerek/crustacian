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

- [x] Hygiene: inspect repo state, clean stale task notes, identify the next best task
- [x] Execute: implement one focused task to working state
- [x] Test: verify deeply enough to decide whether the task deserves a checkmark

## Task List

- [ ] Add ingest authentication validation for bearer-token protected intake

## Active Attempt

- Task: Tighten Rust-side ingest endpoint event validation to match the checked-in telemetry schema.
- Stage: Complete
- Last result: Implemented stricter batch/event validation and regression tests; `cargo fmt --check`, `cargo test`, and `cargo build` pass.
- Last failure: None.
- Next attempt: Add bearer-token validation on `crustacian-ingest` using `CRUSTACIAN_INGEST_TOKEN` or a CLI option, with tests for missing/invalid tokens.

## Completed Log

- Completed stricter ingest telemetry validation in `src/edr_transport.rs`: batch metadata now enforces minimum/non-empty values, endpoint events require the schema fields from `schemas/endpoint-event.schema.json`, boolean recommendation flags must be booleans, confidence must be 0..=1, event schema version is checked, and event endpoint IDs must match the batch endpoint ID. Verified with `cargo fmt --check`, `cargo test`, and `cargo build`.
