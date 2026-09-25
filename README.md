# 🦀 **Project Crustacian**

### **An enterprise-ready Rust AV endpoint and EDR telemetry starter for automated ClamAV deployment, local evidence capture, and server-side ingest.**

---
  <p>
    <img alt="Crustacian Logo" height="300px" style="border-radius:5%;border:1px solid cyan" src="./assets/file_00000000492c81f5a9b02f078e90a64d.png" />
  </p>
---

## 🌐 Overview

**Crustacian** is an open-source, vendor-neutral endpoint security project written in **Rust**, designed to simplify deployment and operation of the **ClamAV** antivirus engine while adding local EDR telemetry and a lightweight server-side ingest path.

It provides a consistent, secure, and predictable interface for:

* Installing ClamAV
* Managing FreshClam signature updates
* Running quick, full, or custom scans
* Viewing detailed results with throughput, progress, and ETA metrics
* Exporting structured logs for integration into SIEM/SOAR/automation pipelines
* Generating endpoint telemetry and disabled response plans for EDR R&D
* Shipping local NDJSON telemetry batches to a built-in ingest server over HTTP or HTTPS
* Applying ingest backpressure with retry hints, exponential backoff, jitter, durable retry scheduling, and retained endpoint spool data

Crustacian is designed for **individuals, developers, sysadmins, SOC teams, and enterprise environments** where cross-platform consistency and automation matter.

---

## ✨ Features

| Capability                  | Description                                                             |
| --------------------------- | ----------------------------------------------------------------------- |
| **Cross-Platform**          | Rust CI covers Windows, macOS, and Linux; ClamAV install and service behavior still varies by OS |
| **Installer Helper**        | Assists in installing ClamAV (local package managers or manual paths)   |
| **Signature Management**    | Runs FreshClam updates automatically or on demand                       |
| **Interactive Scan CLI**    | Quick / full / folder-targeted scans                                    |
| **Live Metrics**            | Progress %, files/sec, ETA, infected count, skipped files               |
| **Structured Logging**      | JSON + human-readable summary logs for automation systems               |
| **Endpoint R&D Telemetry**  | Local NDJSON event spool, endpoint snapshots, dry-run integration checks, response plan drafts, and ingest shipping |
| **Server-Side Ingest**      | `crustacian-ingest` accepts endpoint batches and persists telemetry NDJSON |
| **Backpressure Controls**   | Server returns `429` with retry/max-batch hints; endpoint schedules retry with backoff and retains spool |
| **Crash-safe Spooling**     | Producer/acknowledgement locking, synced appends, and atomic-prefix compaction protect queued telemetry |
| **Replay-safe Ingest**      | SQLite transactions and a composite primary key deduplicate endpoint/event IDs before acknowledgement |
| **Config Management**       | Auto-generates safe default ClamAV and FreshClam configs                |
| **Extensible Architecture** | Designed for future modules (scheduling, remote scanning, local agents) |

---

## 🚀 Getting Started

### **Prerequisites**

* Rust **1.75+**
* Windows 10/11, macOS Ventura+, or any modern Linux distribution
* ClamAV installed (Crustacian can assist with this)

---

## 📥 Installation

### **Clone the repository**

```bash
git clone https://github.com/CharlesDerek/crustacian.git
cd crustacian
```

### **Build the CLI**

```bash
cargo build --release
```

The optimized binaries will appear at:

```
target/release/crustacian
target/release/crustacian-ingest
```

(Windows: `.exe` suffix)

---

## 🧪 Usage

### **Start the interactive CLI**

```bash
./crustacian
```

You’ll see a menu similar to:

```
==================== Crustacian CLI ====================
1. Initialize / repair ClamAV environment
2. Run a scan (quick / full / custom)
3. View previous scan results
4. Endpoint EDR R&D preview
5. Exit
```

The EDR preview menu can show the local telemetry spool and ship it to the
server-side ingest API.

### **Start the ingest server**

```bash
target/release/crustacian-ingest \
  --bind 127.0.0.1:8080 \
  --data-dir target/crustacian-ingest \
  --bearer-token "$CRUSTACIAN_INGEST_TOKEN"
```

Endpoints submit batches to:

```text
POST http://127.0.0.1:8080/v1/ingest
POST https://ingest.example.com/v1/ingest
GET  http://127.0.0.1:8080/health
```

When `CRUSTACIAN_INGEST_TOKEN` or `--bearer-token` is configured, ingest
requests must include `Authorization: Bearer <token>`. `GET /health` remains
available for local liveness checks.

Endpoint retry settings are optional environment variables:
`CRUSTACIAN_RETRY_MAX_ATTEMPTS` (1–10, default 4),
`CRUSTACIAN_RETRY_INITIAL_BACKOFF_MS` (100–60000, default 1000),
`CRUSTACIAN_RETRY_MAX_BACKOFF_MS` (at least the initial delay, at most 300000,
default 30000), and `CRUSTACIAN_RETRY_JITTER` (`true`/`false` or `1`/`0`,
default true). Invalid settings stop delivery with a clear error. A successful
HTTP status only removes queued events when the server confirms accepting the
entire batch. The durable sender uses the configured number of immediate
attempts before recording the next retry time.

Accepted telemetry is persisted as:

```text
target/crustacian-ingest/telemetry.sqlite3
```

The ingest server commits a batch in an SQLite transaction before acknowledging
it. Replays with the same event body are acknowledged without a second row;
reuse of an endpoint/event ID with a different body is rejected. The indexed
primary key keeps deduplication independent of history scans.
If `telemetry.ndjson` exists and no database has been created, ingest refuses
new writes until the legacy file is imported. The importer leaves that file in
place and refuses to commit if it finds malformed lines:

```bash
crustacian-ingest --import-legacy target/crustacian-ingest --dry-run
crustacian-ingest --import-legacy target/crustacian-ingest
```
Endpoint senders serialize delivery attempts for the same spool and check the
acknowledged prefix before compaction; concurrent producers may continue
appending while a batch is in flight.
The ingest listener caps HTTP bodies at 8 MiB, rejects ambiguous content
lengths, and times out slow connections after 15 seconds.

### **Running a scan directly (non-interactive)**

```bash
crustacian telemetry-status --json
crustacian ship --json
crustacian scan --path /path/to/check --json
crustacian signature-update --json
```

The scan command is report-only and calls the local `clamscan` binary. Exit
status 0 means success or clean, 10 means malware found, and 20 means an
operational error. `ship` reads `CRUSTACIAN_INGEST_URL` and the optional token
from the environment; it exits 20 if an attempted batch was not fully
acknowledged. These commands do not install ClamAV or perform quarantine/delete.

---

## 📂 Folder Structure

```
crustacian/
│
├── src/
│   ├── main.rs                  # AV endpoint CLI and EDR preview menu
│   ├── lib.rs                   # Shared library exports
│   ├── edr_transport.rs         # Telemetry batching, HTTP sender, validation
│   └── bin/crustacian-ingest.rs # Server-side ingest API
├── schemas/                     # Endpoint event and ingest batch contracts
├── docs/                # Additional developer docs
└── README.md
```

---

## 🧠 Architecture Summary

Crustacian separates responsibilities into simple, testable modules:

* **Platform Layer**
  Detects OS, locates ClamAV binaries, validates config paths.

* **Signature Layer**
  Runs FreshClam, tracks update timestamps, and handles update failures.

* **Scan Engine Layer**
  Executes scans, tracks throughput, calculates ETA using adaptive models.

* **Logging & Output Layer**
  Stores results in both human-readable and structured JSON formats.

* **CLI Layer**
  Provides interactive AV operations and EDR preview controls.

* **Endpoint Transport Layer**
  Batches local `siem-spool.ndjson` telemetry, sends it to an HTTP or HTTPS
  ingest endpoint, retries transient delivery failures with bounded exponential
  backoff and jitter, persists the next retry time for interactive use, and
  retains events when delivery fails or the server applies backpressure.

* **Server Ingest Layer**
  Accepts `/v1/ingest` batches, validates required telemetry fields, persists
  accepted events as NDJSON, and returns retry/max-batch hints under load.

This modular approach ensures Crustacian can be embedded into:

* Automation pipelines
* SIEM or SOAR workflows
* CI/CD environments
* Custom security tooling
* Endpoint agent frameworks

See [docs/endpoint-edr-rd.md](docs/endpoint-edr-rd.md) for the current
endpoint telemetry schema, SIEM delivery stages, authentik/LDAP planning notes,
and containment safety boundaries.

---

## 🔐 Security Considerations

Crustacian emphasizes:

* **No external telemetry by default**
* **No network connectivity except FreshClam updates**
* **No local persistence beyond logs/results**
* **No proprietary or closed-source components**
* **No remote execution or network scanning** (by design)
* **No active account lockout, host isolation, or destructive shutdown in the
  current EDR R&D implementation**

All operations are **local and transparent**.

---

## 🧭 Roadmap

Crustacian aims to remain lightweight, platform-agnostic, and transparent.
Upcoming milestones include:

### **Short Term**

* Non-interactive scan commands (`scan --full`, `scan --path`, etc.)
* Improved OS detection and ClamAV auto-installation helpers
* Enhanced logging (CSV, NDJSON, syslog integration)
* SIEM-ready endpoint event schema validation
* Dry-run SIEM/authentik/LDAP/containment readiness checks
* Configurable retry policy

### **Medium Term**

* Scheduled scan module
* Plugin-based output formatting
* Remote-report mode (print-only vs write-to-log modes)
* Configurable retry policy through environment or endpoint config
* Server-side ingest authorization policy for endpoint identity and replay protection
* Optional syslog SIEM transport with authenticated delivery and retry queue
* authentik/LDAP response connector in dry-run mode
* Durable server queue and exporter workers for OpenSearch, Splunk HEC, Elastic, and Sentinel-compatible collectors

### **Long Term**

* Distributed scanning API
* Local agent mode for large-scale fleet scenarios
* Optional sandboxing for file pre-processing before scan
* Pluggable detection layers (YARA support, heuristic pre-checks)
* Reversible, approval-gated containment workflows for managed fleets
* Optional Langfuse/Paperclip ML integrations, Suricata intake, a React
  dashboard, and an ad hoc mesh broker for endpoint-to-server telemetry delivery

See
[docs/ml-suricata-dashboard-checklist.md](docs/ml-suricata-dashboard-checklist.md)
for the implementation checklist covering Rust backend APIs, TypeScript/React
dashboard work, Suricata event normalization, mesh retry behavior, and optional
ML service boundaries.

---

## 🤝 Contributing

Crustacian welcomes contributions that:

* Improve portability
* Enhance reliability
* Strengthen security
* Add vendor-neutral integrations
* Improve test coverage

---

## 📜 License

Crustacian is released under the **MIT License**.

This allows:

* Commercial use
* Modification
* Distribution
* Private or enterprise deployment

---

## ⭐ Support the Project

If Crustacian helps you secure your systems, please consider:

* Starring the repository
* Opening issues or feature requests
* Contributing improvements
