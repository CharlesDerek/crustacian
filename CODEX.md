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

Stage 1: Hygiene and next-task selection.

- Status: Ready for Stage 2 implementation.
- Selected next task: Add ingest authentication validation for bearer-token protected intake.
- Rationale: This is the smallest security-focused feature that strengthens the current EDR ingest path, exercises Rust networking and validation work, and supports the README roadmap without starting the larger dashboard, ML, or mesh efforts.

## Task List

- [ ] Add ingest authentication validation for bearer-token protected intake

## Active Attempt

- Task: Add ingest authentication validation for bearer-token protected intake.
- Stage: Selected for Stage 2
- Last result: Stage 1 selected bearer-token ingest authentication as the next small showcase task after inspecting the repo, README, CODEX.md, docs, workflows, and ingest server code.
- Last failure: None.
- Next attempt: Implement bearer-token validation on `crustacian-ingest` using `CRUSTACIAN_INGEST_TOKEN` or a CLI option, keep `/health` unauthenticated if desired for local liveness checks, and add tests for missing, invalid, and valid authorization headers.

## Completed Log

- Completed Stage 1 hygiene: confirmed `.mrgi` is ignored, normalized the tracked readme filename to `README.md` for MRGI compatibility, and selected exactly one next task.
- Completed stricter ingest telemetry validation in `src/edr_transport.rs`: batch metadata now enforces minimum/non-empty values, endpoint events require the schema fields from `schemas/endpoint-event.schema.json`, boolean recommendation flags must be booleans, confidence must be 0..=1, event schema version is checked, and event endpoint IDs must match the batch endpoint ID. Verified with `cargo fmt --check`, `cargo test`, and `cargo build`.
