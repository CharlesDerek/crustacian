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
| **Cross-Platform**          | Works on Windows, macOS, and Linux distributions                        |
| **Installer Helper**        | Assists in installing ClamAV (local package managers or manual paths)   |
| **Signature Management**    | Runs FreshClam updates automatically or on demand                       |
| **Interactive Scan CLI**    | Quick / full / folder-targeted scans                                    |
| **Live Metrics**            | Progress %, files/sec, ETA, infected count, skipped files               |
| **Structured Logging**      | JSON + human-readable summary logs for automation systems               |
| **Endpoint R&D Telemetry**  | Local NDJSON event spool, endpoint snapshots, dry-run integration checks, response plan drafts, and ingest shipping |
| **Server-Side Ingest**      | `crustacian-ingest` accepts endpoint batches and persists telemetry NDJSON |
| **Backpressure Controls**   | Server returns `429` with retry/max-batch hints; endpoint schedules retry with backoff and retains spool |
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

Accepted telemetry is persisted as:

```text
target/crustacian-ingest/telemetry.ndjson
```

### **Running a scan directly (non-interactive)**

*(Planned — see Roadmap)*

```
crustacian scan --path /home/user/downloads
crustacian scan --quick
crustacian scan --full
```

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
* Configurable retry policy and CI target checks

### **Medium Term**

* Scheduled scan module
* Plugin-based output formatting
* Remote-report mode (print-only vs write-to-log modes)
* Configurable retry policy through environment or endpoint config
* Server-side ingest authorization policy for endpoint identity and replay protection
* CI target matrix for Windows, Linux, and macOS checks
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
