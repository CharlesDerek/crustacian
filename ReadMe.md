# 🦀 **Project Crustacian**

### **An enterprise-ready, cross-platform Rust CLI for automated ClamAV deployment, endpoint telemetry, and blue-team security operations.**

---
  <p>
    <img alt="Crustacian Logo" height="300px" style="border-radius:5%;border:1px solid cyan" src="./assets/file_00000000492c81f5a9b02f078e90a64d.png" />
  </p>
---

## 🌐 Overview

**Crustacian** is an open-source, vendor-neutral command-line tool written in **Rust**, designed to simplify deployment and operation of the **ClamAV** antivirus engine while growing into a local-first endpoint security and EDR research toolkit.

It provides a consistent, secure, and predictable interface for:

* Installing ClamAV
* Managing FreshClam signature updates
* Running quick, full, or custom scans
* Viewing detailed results with throughput, progress, and ETA metrics
* Exporting structured logs for integration into SIEM/SOAR/automation pipelines
* Generating endpoint telemetry, snapshot hashes, and disabled response plans for EDR R&D
* Planning server-side ingest, telemetry storage, backpressure, and CI/CD lanes for endpoint and server components

Crustacian is designed for **developers, sysadmins, SOC teams, blue-team operators, and enterprise environments** where endpoint consistency, evidence capture, and controlled automation matter.

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
| **Endpoint R&D Telemetry**  | Local NDJSON event spool, endpoint snapshots, and response plan drafts  |
| **EDR + AV Integrations**   | Proposed endpoint, SIEM/SOAR, identity, and containment connectors      |
| **Server-Side Ingest**      | Planned telemetry receiver, validation queue, storage, and exporters    |
| **Backpressure Controls**   | Planned local spool, retry, rate-limit, and priority delivery behavior  |
| **CI/CD Separation**        | Endpoint, server, docs, and release workflow lanes                      |
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
target/release/crustacian-endpoint
target/release/crustacian-server
```

(Windows: `.exe` suffix)

---

## 🧪 Usage

### **Start the ingest server**

```bash
cargo run -p crustacian-server -- --bind 127.0.0.1:8080
```

### **Emit and send endpoint telemetry**

In another terminal:

```bash
cargo run -p crustacian-endpoint -- \
  --endpoint-id lab-endpoint-01 \
  run-once \
  --ingest-url http://127.0.0.1:8080
```

### **Inspect local spool status**

```bash
cargo run -p crustacian-endpoint -- \
  --endpoint-id lab-endpoint-01 \
  status
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
├── crates/
│   └── crustacian-core/ # Shared telemetry models and ingest contracts
├── endpoint/            # Endpoint agent: local spool and ingest sender
├── server/              # Server-side ingest API and backpressure responses
├── schemas/             # Versioned JSON schemas for events and batches
├── docs/                # Integration and developer docs
├── .github/workflows/   # Endpoint, server, docs, and release CI lanes
└── README.md
```

---

## 🧠 Architecture Summary

Crustacian separates responsibilities into simple, testable modules:

* **Platform Layer** *(planned endpoint expansion)*
  Detects OS, locates ClamAV binaries, validates config paths.

* **Signature Layer** *(planned endpoint expansion)*
  Runs FreshClam, tracks update timestamps, and handles update failures.

* **Scan Engine Layer** *(planned endpoint expansion)*
  Executes scans, tracks throughput, calculates ETA using adaptive models.

* **Logging & Output Layer**
  Stores results in both human-readable and structured JSON formats.

* **Endpoint Agent**
  Emits local health telemetry, maintains an NDJSON spool, and sends batches to the ingest API with retry-aware responses.

* **Server Ingest Layer**
  Accepts telemetry batches, validates schema versions, deduplicates by endpoint sequence, and returns backpressure hints.

This modular approach ensures Crustacian can be embedded into:

* Automation pipelines
* SIEM or SOAR workflows
* CI/CD environments
* Custom security tooling
* Endpoint agent frameworks
* Local-first EDR research pipelines

---

## 🔌 EDR + AV Integration Architecture

Crustacian should treat the endpoint as the source of local evidence and the server as the control point for fleet visibility. The split keeps endpoint behavior auditable while enabling EDR-style correlation and response workflows.

### Endpoint AV layer

* Manage ClamAV and FreshClam installation, configuration, signature freshness, and scan policy
* Run quick, full, and targeted scans
* Record infection findings, quarantine metadata, file hashes, scan timing, skipped files, and engine versions
* Keep destructive actions disabled unless explicit policy and rollback behavior exist

### Endpoint EDR layer

* Emit normalized NDJSON events for scan results, file evidence, process context, policy decisions, endpoint health, and agent status
* Assign a stable endpoint ID and monotonic sequence numbers to support deduplication
* Maintain a bounded local spool for offline operation and delayed delivery
* Add dry-run response plans for identity actions, network containment, ticket creation, and quarantine workflows

### External integrations

| Integration                 | Purpose                                                        | Initial Mode |
| --------------------------- | -------------------------------------------------------------- | ------------ |
| **Syslog / OpenSearch**     | Vendor-neutral telemetry forwarding                            | Write events |
| **Splunk HEC / Elastic**    | SIEM search, detection engineering, dashboards, and alerting    | Write events |
| **Microsoft Sentinel**      | Cloud SIEM ingestion through compatible collectors or webhooks  | Write events |
| **SOAR webhooks**           | Case creation and response review queues                       | Dry-run first |
| **authentik / LDAP**        | Identity lookup and account-response planning                  | Dry-run first |
| **YARA**                    | Additional local detection rules before or after AV scanning    | Detection only |
| **Ticketing systems**       | Evidence-backed incident handoff                               | Draft/create |

---

## 🛰️ Server-Side Ingest and Telemetry

The server-side segment should be separate from the endpoint agent and optimized for reliable intake, schema validation, storage, and downstream export.

```text
endpoint agent
  -> local spool
  -> batch sender with retry and rate-limit handling
  -> ingest API
  -> validation queue
  -> telemetry store
  -> SIEM exporters + alert queue + response review queue
```

### Ingest API

* Accept signed event batches over mTLS or token-authenticated HTTPS
* Validate event schema versions and reject unknown or malformed payloads
* Deduplicate by endpoint ID, sequence number, and event hash
* Return retry hints, accepted offsets, and rate-limit headers

### Telemetry pipeline

* Store raw events for forensic review
* Normalize hot events into searchable storage
* Route detection events to alert queues
* Export selected telemetry to SIEM/SOAR integrations
* Track endpoint health, missed check-ins, signature age, and failed delivery attempts

### Backpressure strategy

* Use a bounded endpoint spool with disk limits and explicit retention policy
* Prioritize detections, infection evidence, and endpoint health over low-value progress events
* Apply exponential retry with jitter for network or server failures
* Honor server rate-limit headers and reduce batch size when requested
* Emit roll-up summaries when low-priority events must be dropped
* Keep server workers queue-backed so ingest remains fast even when exporters are slow

---

## ⚙️ CI/CD Plan

Crustacian should use separate CI/CD lanes for each side of the system. The repository now includes placeholder GitHub Actions workflows that activate when matching component paths exist, plus initial ingest contracts in [`schemas/`](schemas/) and an integration guide in [`docs/integrations.md`](docs/integrations.md).

| Lane                      | Checks                                                                 |
| ------------------------- | ---------------------------------------------------------------------- |
| **Endpoint agent**        | `cargo fmt`, `cargo clippy`, tests, dependency audit, release builds   |
| **Server ingest**         | API tests, schema compatibility checks, container build, image scan    |
| **Docs/site**             | Static HTML checks and architecture documentation validation           |
| **Release**               | Cross-platform endpoint artifacts, checksums, signed release packages  |

Suggested future layout:

```text
crustacian/
├── endpoint/              # Rust endpoint agent or workspace crate
├── server/                # Ingest API, workers, schemas, deployment assets
├── schemas/               # Versioned event and API schemas
├── docs/                  # Architecture, runbooks, deployment notes
└── .github/workflows/     # Endpoint, server, docs, and release automation
```

---

## 🔐 Security Considerations

Crustacian emphasizes:

* **No external telemetry by default**
* **No network connectivity except FreshClam updates**
* **No local persistence beyond logs/results**
* **No proprietary or closed-source components**
* **No remote execution or network scanning** (by design)
* **No active account lockout, host isolation, or destructive shutdown in the current EDR R&D implementation**

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
* Initial event schema files for endpoint and server ingest contracts
* GitHub Actions validation for static site and documentation

### **Medium Term**

* Scheduled scan module
* Plugin-based output formatting
* Remote-report mode (print-only vs write-to-log modes)
* Optional SIEM transport with authenticated delivery and retry queue
* authentik/LDAP response connector in dry-run mode
* Server ingest API with queue-backed telemetry validation
* Endpoint spool with bounded retry and backpressure handling

### **Long Term**

* Distributed scanning API
* Local agent mode for large-scale fleet scenarios
* Optional sandboxing for file pre-processing before scan
* Pluggable detection layers (YARA support, heuristic pre-checks)
* Reversible, approval-gated containment workflows for managed fleets
* Release signing, SBOM generation, and fleet deployment artifacts

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
