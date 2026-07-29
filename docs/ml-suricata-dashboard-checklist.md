# ML, Suricata, Mesh Broker, and Dashboard Checklist

This checklist tracks the planned expansion of Crustacian into a Rust-backed
endpoint telemetry broker with optional ML integrations, Suricata event intake,
and a TypeScript/React dashboard for endpoint and ingest management.

The current project should keep ClamAV endpoint scanning and the existing
`crustacian-ingest` contract stable while these items are designed and built.

## Integration Boundaries

- [ ] Treat `git@github.com:langfuse/langfuse.git` as an optional third-party ML
  observability dependency, not a required endpoint runtime component.
- [ ] Treat `git@github.com:paperclipai/paperclip.git` as an optional
  third-party ML workflow dependency, not a required endpoint runtime component.
- [ ] Pin third-party integrations by release tag or commit SHA before any build
  or deployment path depends on them.
- [ ] Document each third-party license, runtime service requirement, data
  retention behavior, and security boundary before enabling it.
- [ ] Keep Rust as the implementation language for Crustacian backends,
  endpoint transports, broker services, and HTTP APIs.
- [ ] Keep dashboard UI components in TypeScript and React.
- [ ] Keep ML integration calls server-side by default; endpoints should ship
  telemetry and receive policy, not call ML services directly.
- [ ] Add feature flags or config gates for every optional ML, Suricata, and mesh
  broker integration.

## Repository And Dependency Setup

- [ ] Decide whether Langfuse and Paperclip are referenced through deployment
  documentation, Git submodules, container images, or externally managed service
  URLs.
- [ ] Add a dependency architecture note for the selected approach.
- [ ] Add example environment variables for optional ML service endpoints,
  tokens, project IDs, and dataset names.
- [ ] Add local-development instructions that allow Crustacian to run without
  either third-party ML service.
- [ ] Add CI checks that fail only for required Crustacian code and skip optional
  external service checks unless credentials are intentionally configured.
- [ ] Add non-mutating validation for config templates and dashboard build
  artifacts.

## Rust Backend API Work

- [ ] Split shared ingest types into stable Rust modules before expanding the API
  surface.
- [ ] Add a server-side endpoint registry model with endpoint ID, hostname,
  platform, last seen time, health status, queued event count, retry state, and
  active policy version.
- [ ] Add a persisted endpoint state store for local lab use.
- [ ] Define upgrade path from file-backed state to a database-backed state store.
- [ ] Add `GET /v1/endpoints` for dashboard endpoint inventory.
- [ ] Add `GET /v1/endpoints/{endpoint_id}` for endpoint detail.
- [ ] Add `GET /v1/endpoints/{endpoint_id}/events` with pagination and severity
  filtering.
- [ ] Add `GET /v1/ingest/status` for queue depth, active requests, dropped event
  counts, retry hints, and exporter status.
- [ ] Add authenticated admin API paths before enabling mutable dashboard actions.
- [ ] Add OpenAPI or schema documentation for every dashboard-facing endpoint.

## TypeScript And React Dashboard

- [ ] Create a dashboard workspace without changing the Rust endpoint runtime.
- [ ] Use TypeScript for API types, state models, and reusable UI components.
- [ ] Add an endpoint inventory view with health, last seen time, platform,
  severity counts, and queued logs.
- [ ] Add endpoint detail view with scan history, Suricata events, transport
  retry state, and recent telemetry.
- [ ] Add ingest status view with batch acceptance, backpressure, broker queue
  depth, and exporter health.
- [ ] Add policy/configuration view for endpoint ingest URL, log level, batch
  limits, retry policy, and enabled integrations.
- [ ] Add ML integration status view for Langfuse and Paperclip connectivity,
  last successful export, last error, and disabled/enabled state.
- [ ] Keep destructive or high-impact actions behind explicit confirmation and
  server-side authorization.
- [ ] Add dashboard build and lint commands to project documentation once the
  workspace exists.

## Suricata Integration

- [ ] Define the supported Suricata source modes: local `eve.json` tailing,
  file drop, syslog receiver, and HTTP forwarder.
- [ ] Add a Suricata event normalization schema that preserves original
  `eve.json` fields while mapping common fields into Crustacian telemetry.
- [ ] Add source metadata fields for sensor ID, interface, rule SID, alert
  category, flow tuple, packet timestamp, and ingestion timestamp.
- [ ] Add severity mapping from Suricata alert metadata into Crustacian severity
  levels.
- [ ] Add deduplication keys for repeated alerts and flow records.
- [ ] Add local spool retention rules for Suricata-derived events.
- [ ] Add tests with representative Suricata `eve.json` alert, DNS, HTTP, TLS,
  and flow records.
- [ ] Document privacy and data-volume risks before collecting packet-derived
  metadata at scale.

## Ad Hoc Mesh Broker

- [ ] Define broker roles: endpoint client, local mesh peer, relay broker, and
  central ingest server.
- [ ] Keep direct client-to-server delivery as the preferred path when available.
- [ ] Allow mesh forwarding only when explicitly configured and authenticated.
- [ ] Add broker envelope fields for source endpoint, previous hop, hop count,
  event count, compression state, priority, and signature/hash.
- [ ] Add loop prevention through hop limits and seen-batch IDs.
- [ ] Add exponential backoff with jitter for server delivery failures.
- [ ] Add separate retry policies by log priority or level, such as critical,
  warning, info, and debug.
- [ ] Add queue pressure behavior that preserves high-severity events before
  dropping or compacting lower-priority logs.
- [ ] Add durable retry state for broker queues, not only interactive endpoint
  shipment.
- [ ] Add broker health telemetry so the dashboard can show mesh peer status and
  retained queue depth.
- [ ] Add replay protection and batch authentication before any multi-hop
  forwarding is enabled.

## ML Pipeline Use Cases

- [ ] Define which telemetry is eligible for ML export and which fields must be
  redacted or hashed.
- [ ] Add a server-side exporter that can send normalized events to Langfuse for
  observability of scoring, prompts, traces, or analyst feedback loops.
- [ ] Add a server-side integration point for Paperclip-driven enrichment or
  retrieval workflows after its runtime contract is reviewed.
- [ ] Add a local dry-run mode that writes ML export payloads to disk instead of
  calling external services.
- [ ] Add event enrichment outputs as new events rather than mutating original
  endpoint evidence.
- [ ] Add confidence, model/provider, prompt/workflow version, and source event
  references to every ML-derived event.
- [ ] Require a disabled-by-default configuration for all ML enrichment.

## Security And Safety Gates

- [ ] Require TLS for production ingest, dashboard, and ML service traffic.
- [ ] Add bearer token or stronger authentication for endpoint ingest.
- [ ] Add dashboard authentication and authorization before mutable controls.
- [ ] Add audit logging for policy changes, integration toggles, and replayed
  broker batches.
- [ ] Add rate limits for ingest, dashboard API, Suricata intake, and ML export.
- [ ] Add bounded disk usage for every spool and broker queue.
- [ ] Add clear redaction policy for usernames, hostnames, paths, IP addresses,
  and packet-derived metadata.
- [ ] Add incident/change ticket fields before enabling response workflows.

## Verification Checklist

- [ ] Run `cargo build` after Rust changes.
- [ ] Run `cargo test` after Rust changes.
- [ ] Add dashboard package build, lint, and test commands once the React
  workspace exists.
- [ ] Add schema validation tests for endpoint, Suricata, broker, and ML export
  payloads.
- [ ] Add retry/backpressure tests for direct server delivery and mesh delivery.
- [ ] Add non-mutating integration tests that do not require real Langfuse,
  Paperclip, Suricata, or production ingest services.
- [ ] Document every skipped optional dependency check with the exact command and
  missing tool or credential.
