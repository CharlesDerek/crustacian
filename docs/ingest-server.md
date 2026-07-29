# Crustacian Ingest Server

`crustacian-ingest` is the server-side segment for endpoint telemetry intake.
It is intentionally small: accept endpoint batches, validate their shape, persist
accepted events, and return clear backpressure hints.

## Run

```bash
cargo run --bin crustacian-ingest -- \
  --bind 127.0.0.1:8080 \
  --data-dir target/crustacian-ingest \
  --bearer-token "$CRUSTACIAN_INGEST_TOKEN"
```

## Endpoints

```text
GET  /health
POST /v1/ingest
```

`POST /v1/ingest` expects `schemas/ingest-batch.schema.json`. Each event inside
the batch follows `schemas/endpoint-event.schema.json`.

Bearer-token enforcement is opt-in for local development. Set
`CRUSTACIAN_INGEST_TOKEN` or pass `--bearer-token` to require:

```text
Authorization: Bearer <token>
```

Requests missing the configured token, or using a different token, receive HTTP
`401`. `GET /health` does not require the bearer token.

Accepted events are appended to:

```text
target/crustacian-ingest/telemetry.ndjson
```

## Backpressure

The server limits active ingest requests with `--max-in-flight`. When saturated,
it returns HTTP `429` with:

- `retry_after_seconds`
- `max_batch_events`
- `accepted: false`

The endpoint sender retries transient transport failures, HTTP `408`, HTTP
`429`, and HTTP `5xx` responses with bounded exponential backoff and jitter. It
honors `retry_after_seconds` up to its local retry cap, keeps undelivered events
in the local spool, and appends a `transport.backpressure` event when the server
continues to reject a batch with `429`.

The interactive endpoint menu persists retry state beside the telemetry spool so
operators are not blocked while backoff is active. A later manual ship attempt
returns immediately until the saved next-attempt timestamp is due.

## Current Integrations

- Local endpoint AV telemetry from ClamAV scan completion
- Endpoint snapshot hash evidence
- Disabled response-plan records for identity and containment review
- HTTP/HTTPS batch ingest sender with optional bearer-token header
- Optional server-side bearer-token validation for protected ingest intake
- Server-side NDJSON telemetry persistence

## Planned Exporters

- Syslog
- OpenSearch
- Splunk HEC
- Elastic
- Microsoft Sentinel-compatible webhook or collector
- SOAR ticket/case creation in dry-run-first mode

See
[ML, Suricata, Mesh Broker, and Dashboard Checklist](ml-suricata-dashboard-checklist.md)
for the planned endpoint dashboard, Suricata intake, optional Langfuse/Paperclip
ML integrations, and ad hoc mesh broker work.
