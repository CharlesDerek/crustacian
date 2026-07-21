use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const INGEST_BATCH_SCHEMA: &str = "crustacian.ingest.batch.v0";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpoolStats {
    pub queued_events: usize,
    pub disk_bytes: u64,
    pub dropped_low_priority_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestBatch {
    pub schema_version: String,
    pub batch_id: String,
    pub endpoint_id: String,
    pub sent_at: String,
    pub spool: SpoolStats,
    pub events: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted: bool,
    pub accepted_events: usize,
    pub message: String,
    pub retry_after_seconds: Option<u64>,
    pub max_batch_events: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DeliveryReport {
    pub attempted_events: usize,
    pub delivered_events: usize,
    pub retained_events: usize,
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, Clone)]
struct HttpTarget {
    host: String,
    port: u16,
    path: String,
}

pub fn spool_stats(spool_path: &Path) -> io::Result<SpoolStats> {
    if !spool_path.exists() {
        return Ok(SpoolStats::default());
    }

    let disk_bytes = fs::metadata(spool_path)?.len();
    let file = File::open(spool_path)?;
    let queued_events = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .count();

    Ok(SpoolStats {
        queued_events,
        disk_bytes,
        dropped_low_priority_events: 0,
    })
}

pub fn append_transport_event(
    spool_path: &Path,
    endpoint_id: &str,
    message: &str,
) -> io::Result<()> {
    let event = json!({
        "schema_version": "crustacian.endpoint.telemetry.v0",
        "event_id": stable_id(&format!("{endpoint_id}:{message}:{}", chrono::Utc::now().to_rfc3339())),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "endpoint_id": endpoint_id,
        "asset_hostname": hostname(),
        "platform": std::env::consts::OS,
        "event_kind": "transport.backpressure",
        "severity": "warning",
        "classifier": "transport.backpressure",
        "confidence": 0.80,
        "actor": "local_cli",
        "auth_provider": "none",
        "lockout_recommended": false,
        "isolation_recommended": false,
        "forensic_snapshot_sha256": "",
        "evidence": message
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(spool_path)?;
    writeln!(file, "{event}")?;
    Ok(())
}

pub fn send_spool(
    spool_path: &Path,
    endpoint_id: &str,
    ingest_url: &str,
    bearer_token: Option<&str>,
    max_batch_events: usize,
) -> io::Result<DeliveryReport> {
    if max_batch_events == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_batch_events must be greater than zero",
        ));
    }

    let lines = read_spool_lines(spool_path)?;
    let batch_lines: Vec<String> = lines.iter().take(max_batch_events).cloned().collect();
    let retained_before_send = lines.len().saturating_sub(batch_lines.len());
    if batch_lines.is_empty() {
        return Ok(DeliveryReport {
            attempted_events: 0,
            delivered_events: 0,
            retained_events: 0,
            status_code: 204,
            message: "spool is empty".to_string(),
        });
    }

    let mut events = Vec::with_capacity(batch_lines.len());
    for line in &batch_lines {
        let event = serde_json::from_str::<Value>(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("spool contains invalid JSON event: {error}"),
            )
        })?;
        events.push(event);
    }

    let batch = IngestBatch {
        schema_version: INGEST_BATCH_SCHEMA.to_string(),
        batch_id: stable_id(&format!(
            "{endpoint_id}:{}:{}",
            chrono::Utc::now().to_rfc3339(),
            batch_lines.len()
        )),
        endpoint_id: endpoint_id.to_string(),
        sent_at: chrono::Utc::now().to_rfc3339(),
        spool: spool_stats(spool_path)?,
        events,
    };

    let target = parse_http_url(ingest_url)?;
    let body = serde_json::to_vec(&batch)?;
    let (status_code, response_body) = post_json(&target, bearer_token, &body)?;
    let ingest_response = serde_json::from_slice::<IngestResponse>(&response_body).ok();

    if (200..300).contains(&status_code) {
        remove_delivered_lines(spool_path, batch_lines.len())?;
        return Ok(DeliveryReport {
            attempted_events: batch_lines.len(),
            delivered_events: batch_lines.len(),
            retained_events: retained_before_send,
            status_code,
            message: ingest_response
                .map(|response| response.message)
                .unwrap_or_else(|| "batch accepted".to_string()),
        });
    }

    if status_code == 429 {
        let message = ingest_response
            .as_ref()
            .map(|response| response.message.as_str())
            .unwrap_or("ingest backpressure active");
        let _ = append_transport_event(spool_path, endpoint_id, message);
    }

    Ok(DeliveryReport {
        attempted_events: batch_lines.len(),
        delivered_events: 0,
        retained_events: lines.len(),
        status_code,
        message: ingest_response
            .map(|response| response.message)
            .unwrap_or_else(|| "ingest rejected batch".to_string()),
    })
}

pub fn write_accepted_events(data_dir: &Path, batch: &IngestBatch) -> io::Result<()> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join("telemetry.ndjson");
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    for event in &batch.events {
        writeln!(file, "{event}")?;
    }
    Ok(())
}

pub fn validate_batch(batch: &IngestBatch, max_batch_events: usize) -> Result<(), String> {
    if batch.schema_version != INGEST_BATCH_SCHEMA {
        return Err(format!(
            "unsupported batch schema: {}",
            batch.schema_version
        ));
    }
    if batch.events.is_empty() {
        return Err("batch contains no events".to_string());
    }
    if batch.events.len() > max_batch_events {
        return Err(format!(
            "batch contains {} events; max is {}",
            batch.events.len(),
            max_batch_events
        ));
    }

    for event in &batch.events {
        for field in [
            "schema_version",
            "event_id",
            "timestamp",
            "endpoint_id",
            "event_kind",
            "severity",
            "classifier",
            "evidence",
        ] {
            if event.get(field).is_none() {
                return Err(format!("event missing required field: {field}"));
            }
        }
        if event.get("endpoint_id").and_then(Value::as_str) != Some(batch.endpoint_id.as_str()) {
            return Err("event endpoint_id does not match batch endpoint_id".to_string());
        }
    }

    Ok(())
}

fn read_spool_lines(spool_path: &Path) -> io::Result<Vec<String>> {
    if !spool_path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(spool_path)?;
    BufReader::new(file)
        .lines()
        .filter_map(|line| match line {
            Ok(value) if !value.trim().is_empty() => Some(Ok(value)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn remove_delivered_lines(spool_path: &Path, delivered_count: usize) -> io::Result<()> {
    let lines = read_spool_lines(spool_path)?;
    let remaining = lines.into_iter().skip(delivered_count).collect::<Vec<_>>();
    let mut file = File::create(spool_path)?;
    for line in remaining {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn post_json(
    target: &HttpTarget,
    bearer_token: Option<&str>,
    body: &[u8],
) -> io::Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    let auth_header = bearer_token
        .filter(|token| !token.trim().is_empty())
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();

    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        target.path,
        target.host,
        auth_header,
        body.len()
    )?;
    stream.write_all(body)?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    parse_http_response(&response)
}

fn parse_http_url(url: &str) -> io::Result<HttpTarget> {
    let without_scheme = url.strip_prefix("http://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "only http:// ingest URLs are supported by the built-in sender",
        )
    })?;
    let (host_port, path) = without_scheme
        .split_once('/')
        .map(|(host, path)| (host, format!("/{path}")))
        .unwrap_or((without_scheme, "/v1/ingest".to_string()));
    let (host, port) = host_port
        .split_once(':')
        .map(|(host, port)| (host.to_string(), port.parse::<u16>().unwrap_or(80)))
        .unwrap_or((host_port.to_string(), 80));

    if host.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ingest URL host is empty",
        ));
    }

    Ok(HttpTarget { host, port, path })
}

fn parse_http_response(response: &[u8]) -> io::Result<(u16, Vec<u8>)> {
    let separator = b"\r\n\r\n";
    let header_end = response
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response"))?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status_code = headers
        .lines()
        .next()
        .and_then(|status| status.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status code"))?;
    Ok((
        status_code,
        response[header_end + separator.len()..].to_vec(),
    ))
}

fn stable_id(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).take(16).collect()
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| String::from("unknown-host"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_url_with_default_path() {
        let target = parse_http_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 8080);
        assert_eq!(target.path, "/v1/ingest");
    }

    #[test]
    fn rejects_https_for_builtin_sender() {
        assert!(parse_http_url("https://example.com").is_err());
    }

    #[test]
    fn validates_matching_batch() {
        let batch = IngestBatch {
            schema_version: INGEST_BATCH_SCHEMA.to_string(),
            batch_id: "batch-1".to_string(),
            endpoint_id: "endpoint-1".to_string(),
            sent_at: chrono::Utc::now().to_rfc3339(),
            spool: SpoolStats::default(),
            events: vec![json!({
                "schema_version": "crustacian.endpoint.telemetry.v0",
                "event_id": "event-1",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "endpoint_id": "endpoint-1",
                "event_kind": "agent.health",
                "severity": "informational",
                "classifier": "agent.health",
                "evidence": "ok"
            })],
        };

        assert!(validate_batch(&batch, 10).is_ok());
    }
}
