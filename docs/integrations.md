# Crustacian EDR + AV Integrations

This document defines the integration surfaces for evolving Crustacian from a local ClamAV helper into a combined antivirus endpoint and EDR telemetry solution.

## Component split

| Component | Responsibility |
| --- | --- |
| Endpoint agent | ClamAV orchestration, scan telemetry, local event spool, retry-aware delivery |
| Ingest API | Authenticated batch intake, schema validation, deduplication, retry guidance |
| Telemetry workers | Queue processing, normalization, storage, alert routing, SIEM export |
| Response review | Dry-run response plans, approval gates, audit trail, rollback metadata |

## Endpoint events

Endpoint events should follow `schemas/endpoint-event.schema.json`.

Required routing fields:

* `schema_version`
* `event_id`
* `endpoint_id`
* `sequence`
* `event_type`
* `observed_at`

Recommended event types:

* `agent.health`
* `clamav.signature_update`
* `scan.started`
* `scan.completed`
* `detection.malware`
* `file.quarantine_planned`
* `response.plan_created`
* `transport.backpressure`

## Ingest batches

Endpoint agents should POST batches matching `schemas/ingest-batch.schema.json`.

The server should respond with:

* Accepted highest sequence per endpoint
* Per-event validation failures
* Retry-after seconds when overloaded
* Suggested maximum batch size when backpressure is active

## Backpressure contract

Endpoint behavior:

* Keep a bounded disk spool
* Send smaller batches when the server requests it
* Prioritize detection and endpoint health events
* Drop only low-priority progress telemetry after retention limits are hit
* Emit a roll-up event when telemetry is summarized or dropped

Server behavior:

* Return HTTP `429` with `Retry-After` when intake is saturated
* Return HTTP `202` when events are accepted for async processing
* Avoid slow exporter calls on the ingest request path
* Deduplicate retries by `endpoint_id`, `sequence`, and `event_id`

## CI/CD ownership

Endpoint CI should validate Rust agent quality and release artifacts.
Server CI should validate ingest contracts, API behavior, containers, and migrations.
Site/docs CI should keep architecture docs and static pages parseable.
