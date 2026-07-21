# Crustacian Endpoint EDR R&D Plan

This document defines the initial research and development shape for expanding
Crustacian from a local ClamAV driver into a lightweight endpoint telemetry and
response agent. The current implementation is intentionally non-destructive:
it writes local telemetry, snapshots, disabled response plans, and optionally
ships telemetry to a Crustacian ingest server.

## Goals

- Emit SIEM-ready endpoint telemetry with a stable schema.
- Attach a unique endpoint identifier to every event.
- Preserve scan evidence and local endpoint context for investigation.
- Define future authentik and LDAP account-lockout integration points.
- Define future network containment and recovery workflows.
- Keep all privileged or destructive actions behind explicit design, approval,
  and configuration gates.

## Current R&D Stage

The CLI exposes `Endpoint EDR R&D preview` with three safe actions:

- Write `endpoint-rd-config.toml` under the scan history directory.
- Generate a local endpoint metadata snapshot and SHA-256 hash.
- Generate a disabled response plan for security-team review.
- Run a first-stage integration dry run for SIEM, authentik, LDAP, and
  containment readiness.
- Show the local telemetry spool status.
- Ship the telemetry spool to `crustacian-ingest`.

Scan completion also writes `endpoint_event.ndjson` in the scan report directory
and appends the same event to the local SIEM spool:

```text
Documents/cyberplexs-scans/endpoint-rd/siem-spool.ndjson
```

## Telemetry Contract

Crustacian endpoint telemetry uses NDJSON. Each event has pre-defined fields so
SIEM parsers can validate events without guessing field names.

Required fields:

- `schema_version`
- `event_id`
- `timestamp`
- `endpoint_id`
- `asset_hostname`
- `platform`
- `event_kind`
- `severity`
- `classifier`
- `confidence`
- `actor`
- `auth_provider`
- `lockout_recommended`
- `isolation_recommended`
- `forensic_snapshot_sha256`
- `evidence`

Classification examples:

- `clamav.scan.clean`
- `clamav.scan.infected`
- `endpoint.snapshot.created`
- `response.plan.created`

## SIEM Integration Stages

1. Local spool: write validated NDJSON locally.
2. Built-in HTTP transport: batch events to `crustacian-ingest`.
3. Authenticated delivery: optional bearer-token header for the built-in sender.
4. Reliability controls: retry transient delivery failures with exponential
   backoff and jitter, retain failed batches, and record server backpressure.
5. Parser packs: publish field mappings for target SIEMs.

The current built-in sender supports `http://` ingest URLs for local labs and
controlled internal deployments. TLS termination should be placed in front of
the ingest server for production-style environments until native HTTPS/mTLS is
implemented.

The endpoint sender reads:

- `CRUSTACIAN_INGEST_URL`
- `CRUSTACIAN_INGEST_TOKEN`

The built-in sender retries transient transport failures, HTTP `408`, HTTP
`429`, and HTTP `5xx` responses. The default policy makes up to four delivery
attempts with bounded exponential backoff, full jitter, and a 30-second cap.
Server `retry_after_seconds` hints are honored up to that cap.

The dry-run action still does not open a network connection. Explicit spool
shipping from the EDR preview menu does.

## Server-Side Ingest

The `crustacian-ingest` binary provides the first server-side segment:

- `GET /health`
- `POST /v1/ingest`
- batch schema validation
- required endpoint event field validation
- NDJSON persistence under the configured data directory
- active-request backpressure using HTTP `429`

Run locally:

```bash
cargo run --bin crustacian-ingest -- \
  --bind 127.0.0.1:8080 \
  --data-dir target/crustacian-ingest
```

Then use the endpoint EDR preview menu to ship the local spool to:

```text
http://127.0.0.1:8080/v1/ingest
```

## Backpressure Behavior

When the server reaches `--max-in-flight`, it returns:

- HTTP `429`
- `retry_after_seconds`
- `max_batch_events`
- `accepted: false`

The endpoint keeps the original events in `siem-spool.ndjson` and records a
`transport.backpressure` event so operators can see that delivery was delayed.
The endpoint retries the same batch before returning control to the operator;
the CLI reports transport attempts, retry attempts, and accumulated retry
delay.

## authentik and LDAP Response Stages

Future identity response must be implemented as an approval-driven control plane
action, not an automatic local side effect.

Required controls:

- LDAPS or authentik API over TLS.
- Least-privilege bind identity.
- Explicit account allowlist and break-glass exclusions.
- Change ticket or incident ID on every write action.
- Dry-run mode with exact planned mutation output.
- Audit log written before and after any remote identity change.

Current code only writes response plans with `enabled: false`.

Stage-one identity readiness checks look for:

- `CRUSTACIAN_AUTHENTIK_URL`
- `CRUSTACIAN_LDAP_URL`

No authentik API request, LDAP bind, account disable, or account lockout is
performed.

## Containment and Lockdown Stages

Containment should mean restricting the asset to known recovery, SIEM, and
management paths. It must not destroy evidence or prevent authorized recovery.

Planned stages:

1. Recommend isolation in telemetry.
2. Write local response plan.
3. Collect local metadata snapshot and SHA-256 hash.
4. Send snapshot hash before any future containment action.
5. Apply reversible network isolation only after explicit authorization.
6. Require security-team recovery workflow to lift containment.

Destructive shutdown or device-kill behavior is out of scope for the current
implementation. Any future high-impact containment must be reversible,
operator-approved, audited, and tested in a lab first.

Stage-one containment readiness looks for
`CRUSTACIAN_RESPONSE_APPROVAL_TOKEN` and records whether the approval channel is
configured. It does not change firewall, routing, service, power, disk, or login
state.

## Snapshot Scope

The current snapshot is a local metadata manifest containing:

- creation time
- reason
- endpoint ID
- hostname
- OS and architecture
- scan history path
- latest scan path
- collection scope markers

Future forensic snapshots can add process, socket, service, persistence, file
hash, and signed evidence bundle sections after privacy and performance review.

## Build And Test

Run from the repository root:

```bash
cargo build
cargo test
```
