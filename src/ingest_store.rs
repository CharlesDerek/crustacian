use crate::edr_transport::IngestBatch;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

fn open(data_dir: &Path, allow_legacy: bool) -> io::Result<Connection> {
    std::fs::create_dir_all(data_dir)?;
    let db = data_dir.join("telemetry.sqlite3");
    if !allow_legacy && data_dir.join("telemetry.ndjson").exists() && !db.exists() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "legacy telemetry exists; run crustacian-ingest --import-legacy first",
        ));
    }
    let conn = Connection::open(db).map_err(io_error)?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(io_error)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS events (
            endpoint_id TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
            schema_version TEXT NOT NULL, accepted_ms INTEGER NOT NULL,
            PRIMARY KEY(endpoint_id, event_id));
        CREATE INDEX IF NOT EXISTS events_accepted ON events(accepted_ms);",
    )
    .map_err(io_error)?;
    Ok(conn)
}

pub fn write_accepted_events(data_dir: &Path, batch: &IngestBatch) -> io::Result<usize> {
    let mut conn = open(data_dir, false)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(io_error)?;
    let accepted_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io_error)?
        .as_millis() as i64;
    let mut count = 0;
    for event in &batch.events {
        let id = event
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "accepted event missing event_id",
                )
            })?;
        let schema = event
            .get("schema_version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "accepted event missing schema_version",
                )
            })?;
        let body = serde_json::to_string(event)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT body FROM events WHERE endpoint_id=?1 AND event_id=?2",
                params![batch.endpoint_id, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(io_error)?;
        match existing {
            Some(previous) if previous != body => return Err(io::Error::new(io::ErrorKind::InvalidData, "event ID reused with different body")),
            Some(_) => {},
            None => count += tx.execute("INSERT INTO events(endpoint_id,event_id,body,schema_version,accepted_ms) VALUES (?1,?2,?3,?4,?5)", params![batch.endpoint_id, id, body, schema, accepted_ms]).map_err(io_error)?,
        }
    }
    tx.commit().map_err(io_error)?;
    Ok(count)
}

#[derive(Debug, Default, serde::Serialize)]
pub struct ImportStats {
    pub valid: usize,
    pub duplicates: usize,
    pub malformed: usize,
    pub imported: usize,
}

pub fn import_legacy(data_dir: &Path, dry_run: bool) -> io::Result<ImportStats> {
    let source = data_dir.join("telemetry.ndjson");
    let file = File::open(&source)?;
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::new();
    let mut stats = ImportStats::default();
    for line in BufReader::new(file).lines() {
        let line = line?;
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                stats.malformed += 1;
                continue;
            }
        };
        let Some(endpoint) = value.get("endpoint_id").and_then(Value::as_str) else {
            stats.malformed += 1;
            continue;
        };
        let Some(id) = value.get("event_id").and_then(Value::as_str) else {
            stats.malformed += 1;
            continue;
        };
        let schema = value
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or("legacy");
        if endpoint.is_empty() || id.is_empty() {
            stats.malformed += 1;
            continue;
        }
        if !seen.insert((endpoint.to_owned(), id.to_owned())) {
            stats.duplicates += 1;
            continue;
        }
        stats.valid += 1;
        parsed.push((endpoint.to_owned(), id.to_owned(), line, schema.to_owned()));
    }
    if dry_run || stats.malformed > 0 {
        return Ok(stats);
    }
    // Opening after validation keeps malformed legacy input from creating a partial database.
    let mut conn = open(data_dir, true)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(io_error)?;
    let accepted_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io_error)?
        .as_millis() as i64;
    for (endpoint, id, body, schema) in parsed {
        stats.imported += tx.execute("INSERT OR IGNORE INTO events(endpoint_id,event_id,body,schema_version,accepted_ms) VALUES (?1,?2,?3,?4,?5)", params![endpoint,id,body,schema,accepted_ms]).map_err(io_error)?;
    }
    tx.commit().map_err(io_error)?;
    Ok(stats)
}

pub fn event_count(data_dir: &Path) -> io::Result<u64> {
    let conn = open(data_dir, false)?;
    conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr_transport::{IngestBatch, SpoolStats, INGEST_BATCH_SCHEMA};
    #[test]
    fn commit_survives_reopen_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let batch = IngestBatch {
            schema_version: INGEST_BATCH_SCHEMA.into(),
            batch_id: "batch-123".into(),
            endpoint_id: "endpoint-1".into(),
            sent_at: "now".into(),
            spool: SpoolStats::default(),
            events: vec![serde_json::json!({"event_id":"event-123", "schema_version":"v0"})],
        };
        assert_eq!(write_accepted_events(dir.path(), &batch).unwrap(), 1);
        assert_eq!(event_count(dir.path()).unwrap(), 1);
        assert_eq!(write_accepted_events(dir.path(), &batch).unwrap(), 0);
        assert_eq!(event_count(dir.path()).unwrap(), 1);
    }
    #[test]
    fn concurrent_replay_and_conflicting_id_are_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let batch = IngestBatch {
            schema_version: INGEST_BATCH_SCHEMA.into(),
            batch_id: "batch-123".into(),
            endpoint_id: "endpoint-1".into(),
            sent_at: "now".into(),
            spool: SpoolStats::default(),
            events: vec![serde_json::json!({"event_id":"event-123", "schema_version":"v0"})],
        };
        let threads = (0..8)
            .map(|_| {
                let path = path.clone();
                let batch = batch.clone();
                std::thread::spawn(move || write_accepted_events(&path, &batch).unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .sum::<usize>(),
            1
        );
        let mut changed = batch;
        changed.events[0]["schema_version"] = serde_json::json!("v1");
        assert!(write_accepted_events(&path, &changed).is_err());
        assert_eq!(event_count(&path).unwrap(), 1);
    }
    #[test]
    fn importer_preserves_legacy_and_fails_closed_on_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("telemetry.ndjson");
        std::fs::write(&source, "{\"endpoint_id\":\"e\",\"event_id\":\"1\"}\n{\"endpoint_id\":\"e\",\"event_id\":\"1\"}\ninvalid\n").unwrap();
        let stats = import_legacy(dir.path(), false).unwrap();
        assert_eq!(
            (
                stats.valid,
                stats.duplicates,
                stats.malformed,
                stats.imported
            ),
            (1, 1, 1, 0)
        );
        assert!(!dir.path().join("telemetry.sqlite3").exists());
        std::fs::write(&source, "{\"endpoint_id\":\"e\",\"event_id\":\"1\"}\n{\"endpoint_id\":\"e\",\"event_id\":\"1\"}\n").unwrap();
        let stats = import_legacy(dir.path(), false).unwrap();
        assert_eq!(stats.imported, 1);
        assert_eq!(event_count(dir.path()).unwrap(), 1);
        assert!(source.exists());
    }
}
