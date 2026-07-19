# Crustacian Endpoint EDR R&D Plan

This document defines the initial research and development shape for expanding
Crustacian from a local ClamAV driver into a lightweight endpoint telemetry and
response agent. The current implementation is intentionally non-destructive:
it writes local telemetry, snapshots, and disabled response plans only.

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

1. Local spool only: write validated NDJSON locally.
2. Transport abstraction: add HTTPS/syslog output interfaces.
3. Authenticated delivery: add bearer-token or mTLS support.
4. Reliability controls: retry queue, backoff, disk cap, and dead-letter files.
5. Parser packs: publish field mappings for target SIEMs.

No SIEM network delivery is active in the current code.

Stage-one SIEM readiness checks read these environment variables only to decide
whether a sender could be configured later:

- `CRUSTACIAN_SIEM_URL`
- `CRUSTACIAN_SIEM_TOKEN`

The dry run does not open a network connection.

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
