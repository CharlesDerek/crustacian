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

## Authenticated remote deployment

The server binds only to a numeric loopback address. Put a TLS reverse proxy
on the same host in front of it for remote endpoints. Configure the proxy to
verify client certificates when using mTLS, allow only `/v1/ingest` and
`/health`, and forward to `127.0.0.1:8080`. Keep the direct listener unavailable
from the network.

For per-endpoint identity, provide `--endpoint-tokens-file /private/tokens.json`
or `CRUSTACIAN_ENDPOINT_TOKENS_FILE`. The JSON object maps endpoint IDs to
unique random bearer tokens of at least 32 bytes. A batch must present the
token assigned to its `endpoint_id`; an unknown or revoked ID is rejected.
Tokens must be distinct, and on Unix the file must have owner-only permissions
(for example, `chmod 600`).
Reload the server after rotating the file. This mode cannot be combined with
the shared bearer token setting. Never commit the token file.

The sender refuses remote `http://` URLs. Set `CRUSTACIAN_INGEST_URL` to the
proxy's `https://` address and set the endpoint's token. Private CAs can be
provided with `CRUSTACIAN_INGEST_CA_PEM`; a client certificate and PKCS#8 key
can be supplied with `CRUSTACIAN_CLIENT_CERT_PEM` and
`CRUSTACIAN_CLIENT_KEY_PEM`. Normal TLS hostname validation remains enabled.
Loopback HTTP remains available for local tests.

Accepted events are committed to:

```text
target/crustacian-ingest/telemetry.sqlite3
```

The `(endpoint_id, event_id)` primary key deduplicates replayed batches. The
server acknowledges only after the transaction commits. `GET /health` checks
the database and reports `durable_events` plus process counters for accepted,
duplicate, rejected, and malformed events; it returns 503 if the store cannot
be opened. Existing `telemetry.ndjson` files require an explicit import:

```bash
cargo run --bin crustacian-ingest -- --import-legacy target/crustacian-ingest --dry-run
cargo run --bin crustacian-ingest -- --import-legacy target/crustacian-ingest
```

The importer emits JSON counts for valid, duplicate, malformed, and imported
records. It leaves the source file intact and commits nothing when malformed
records are present. Keep a copy of the legacy file until the counts are
reviewed.

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
- Server-side transactional SQLite telemetry persistence

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
