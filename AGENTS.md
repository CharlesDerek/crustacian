# AGENTS.md

## Project Omniplexs Standard

This repository follows the Project Omniplexs agent standard: preserve the checked-in architecture, keep changes scoped, document build and test commands, and avoid broad rewrites unless the task explicitly requires them.

## Project Overview

Crustacian is a Rust command-line application for managing ClamAV on Windows. The current implementation is a single interactive binary that can initialize or repair a ClamAV environment, update signatures through FreshClam, run scans through `clamdscan.exe`, and view previous scan summaries.

The README describes a broader cross-platform roadmap, but the checked-in code currently exits on non-Windows platforms and uses Windows paths, services, and package managers.

## Architecture

- `Cargo.toml`: Rust package manifest for the `crustacean` binary crate.
- `Cargo.lock`: Locked dependency graph. Keep this committed for reproducible binary builds.
- `src/main.rs`: Main application entrypoint and all current runtime logic.
- `.github/workflows/rust.yml`: CI workflow that runs `cargo build --verbose` and `cargo test --verbose`.
- `assets/logo/`: Project logo assets used by documentation.

### Runtime Flow

- `main` validates Windows at startup, then presents the interactive menu.
- `init_cmd` prepares `C:\Program Files\ClamAV`, writes ClamAV/FreshClam configs, updates signatures, and ensures the `clamd` service is installed and running.
- `scan_cmd` supports quick, full, and custom-path scans, optionally pre-counts files for ETA, runs `clamdscan.exe`, and writes scan artifacts.
- `history_menu` lists prior scan directories and displays `summary.txt` and `infected.txt`.
- Helper functions cover Windows package-manager install attempts, service checks, file counting, output formatting, scan history, and ClamAV config templates.

## Main Features

- Interactive Windows CLI menu.
- ClamAV binary detection with `winget` and `choco` install attempts.
- ClamAV and FreshClam config generation.
- FreshClam signature database update and presence checks.
- Windows `clamd` service installation/startup checks.
- Quick, full, and custom scan targets.
- Report-only, quarantine, and delete modes for infected files.
- Progress display with file count, throughput, and ETA.
- Scan history saved under the user Documents directory.

## Build and Test Commands

Run these from the repository root:

```bash
cargo build
cargo test
```

Useful variants:

```bash
cargo build --release
cargo build --verbose
cargo test --verbose
```

## Development Notes

- Prefer small, focused changes in `src/main.rs` until the project is intentionally split into modules.
- Keep Windows-specific behavior explicit. Do not claim cross-platform support in code paths unless those paths are implemented and tested.
- Preserve user-facing safety around destructive scan actions. Delete mode should remain opt-in and obvious.
- Treat generated ClamAV config templates as operational security-sensitive text; review changes carefully.
- Keep path handling through `Path` and `PathBuf` where practical.
- Do not remove `Cargo.lock` from this binary application.

## Verification Expectations

- Run `cargo build` after code changes.
- Run `cargo test` after code changes, even if the project currently has no tests.
- If Cargo is unavailable in the local environment, state that verification could not be run and include the exact failure.
