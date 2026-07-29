use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    pub transport_attempts: usize,
    pub retry_attempts: usize,
    pub retry_delay_millis: u128,
    pub retry_after_seconds: Option<u64>,
    pub next_retry_at: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            jitter: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RetrySchedule {
    pub consecutive_failures: usize,
    pub next_attempt_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct HttpTarget {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    url: String,
}

#[derive(Debug, Clone)]
struct HttpAttempt {
    status_code: u16,
    response_body: Vec<u8>,
    attempts: usize,
    retry_attempts: usize,
    retry_delay: Duration,
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
    send_spool_with_retry(
        spool_path,
        endpoint_id,
        ingest_url,
        bearer_token,
        max_batch_events,
        &RetryPolicy::default(),
    )
}

pub fn send_spool_with_durable_retry(
    spool_path: &Path,
    retry_state_path: &Path,
    endpoint_id: &str,
    ingest_url: &str,
    bearer_token: Option<&str>,
    max_batch_events: usize,
    retry_policy: &RetryPolicy,
) -> io::Result<DeliveryReport> {
    let schedule = read_retry_schedule(retry_state_path)?;
    if let Some(next_attempt_at) = schedule.next_attempt_at.as_deref() {
        if retry_not_due(next_attempt_at) {
            let stats = spool_stats(spool_path)?;
            return Ok(DeliveryReport {
                attempted_events: 0,
                delivered_events: 0,
                retained_events: stats.queued_events,
                status_code: 425,
                transport_attempts: 0,
                retry_attempts: 0,
                retry_delay_millis: 0,
                retry_after_seconds: None,
                next_retry_at: Some(next_attempt_at.to_string()),
                message: format!("delivery retry paused until {next_attempt_at}"),
            });
        }
    }

    let single_attempt_policy = RetryPolicy {
        max_attempts: 1,
        initial_backoff: retry_policy.initial_backoff,
        max_backoff: retry_policy.max_backoff,
        jitter: retry_policy.jitter,
    };

    match send_spool_with_retry(
        spool_path,
        endpoint_id,
        ingest_url,
        bearer_token,
        max_batch_events,
        &single_attempt_policy,
    ) {
        Ok(mut report) => {
            if report.delivered_events > 0 || !is_retryable_status(report.status_code) {
                clear_retry_schedule(retry_state_path)?;
                return Ok(report);
            }

            if report.attempted_events > 0 {
                let next_retry_at = write_next_retry_schedule(
                    retry_state_path,
                    retry_policy,
                    &schedule,
                    &report.message,
                    report.retry_after_seconds,
                )?;
                report.next_retry_at = Some(next_retry_at);
            }

            Ok(report)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData
            ) =>
        {
            clear_retry_schedule(retry_state_path)?;
            Err(error)
        }
        Err(error) => {
            let stats = spool_stats(spool_path)?;
            let message = format!("transport delivery failed: {error}");
            let next_retry_at = write_next_retry_schedule(
                retry_state_path,
                retry_policy,
                &schedule,
                &message,
                None,
            )?;
            let _ = append_transport_event(spool_path, endpoint_id, &message);

            Ok(DeliveryReport {
                attempted_events: stats.queued_events.min(max_batch_events),
                delivered_events: 0,
                retained_events: stats.queued_events,
                status_code: 0,
                transport_attempts: 1,
                retry_attempts: 0,
                retry_delay_millis: 0,
                retry_after_seconds: None,
                next_retry_at: Some(next_retry_at),
                message,
            })
        }
    }
}

pub fn send_spool_with_retry(
    spool_path: &Path,
    endpoint_id: &str,
    ingest_url: &str,
    bearer_token: Option<&str>,
    max_batch_events: usize,
    retry_policy: &RetryPolicy,
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
            transport_attempts: 0,
            retry_attempts: 0,
            retry_delay_millis: 0,
            retry_after_seconds: None,
            next_retry_at: None,
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
    let http_attempt = post_json_with_retry(&target, bearer_token, &body, retry_policy)?;
    let status_code = http_attempt.status_code;
    let response_body = http_attempt.response_body;
    let ingest_response = serde_json::from_slice::<IngestResponse>(&response_body).ok();
    let retry_after_seconds = ingest_response
        .as_ref()
        .and_then(|response| response.retry_after_seconds);

    if (200..300).contains(&status_code) {
        remove_delivered_lines(spool_path, batch_lines.len())?;
        return Ok(DeliveryReport {
            attempted_events: batch_lines.len(),
            delivered_events: batch_lines.len(),
            retained_events: retained_before_send,
            status_code,
            transport_attempts: http_attempt.attempts,
            retry_attempts: http_attempt.retry_attempts,
            retry_delay_millis: http_attempt.retry_delay.as_millis(),
            retry_after_seconds,
            next_retry_at: None,
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
        transport_attempts: http_attempt.attempts,
        retry_attempts: http_attempt.retry_attempts,
        retry_delay_millis: http_attempt.retry_delay.as_millis(),
        retry_after_seconds,
        next_retry_at: None,
        message: ingest_response
            .map(|response| response.message)
            .unwrap_or_else(|| "ingest rejected batch".to_string()),
    })
}

fn read_retry_schedule(retry_state_path: &Path) -> io::Result<RetrySchedule> {
    if !retry_state_path.exists() {
        return Ok(RetrySchedule::default());
    }

    let content = fs::read_to_string(retry_state_path)?;
    serde_json::from_str(&content).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("retry state contains invalid JSON: {error}"),
        )
    })
}

fn clear_retry_schedule(retry_state_path: &Path) -> io::Result<()> {
    if retry_state_path.exists() {
        fs::remove_file(retry_state_path)?;
    }
    Ok(())
}

fn write_next_retry_schedule(
    retry_state_path: &Path,
    retry_policy: &RetryPolicy,
    previous: &RetrySchedule,
    message: &str,
    retry_after_seconds: Option<u64>,
) -> io::Result<String> {
    if let Some(parent) = retry_state_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let consecutive_failures = previous.consecutive_failures.saturating_add(1);
    let delay = retry_delay_for_schedule(retry_policy, consecutive_failures, retry_after_seconds);
    let chrono_delay =
        chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::seconds(0));
    let next_retry_at = (chrono::Utc::now() + chrono_delay).to_rfc3339();
    let schedule = RetrySchedule {
        consecutive_failures,
        next_attempt_at: Some(next_retry_at.clone()),
        last_error: Some(message.to_string()),
    };
    let content = serde_json::to_string_pretty(&schedule)?;
    fs::write(retry_state_path, content)?;
    Ok(next_retry_at)
}

fn retry_not_due(next_attempt_at: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(next_attempt_at)
        .map(|value| value.with_timezone(&chrono::Utc) > chrono::Utc::now())
        .unwrap_or(false)
}

fn retry_delay_for_schedule(
    retry_policy: &RetryPolicy,
    failed_attempt: usize,
    retry_after_seconds: Option<u64>,
) -> Duration {
    if let Some(seconds) = retry_after_seconds {
        return clamp_duration(Duration::from_secs(seconds), retry_policy.max_backoff);
    }

    retry_delay_for_attempt(retry_policy, failed_attempt, None)
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
    if batch.batch_id.trim().len() < 8 {
        return Err("batch_id must be at least 8 characters".to_string());
    }
    if batch.endpoint_id.trim().len() < 3 {
        return Err("endpoint_id must be at least 3 characters".to_string());
    }
    if batch.sent_at.trim().is_empty() {
        return Err("sent_at must not be empty".to_string());
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
            "asset_hostname",
            "platform",
            "event_kind",
            "severity",
            "classifier",
            "actor",
            "auth_provider",
            "forensic_snapshot_sha256",
            "evidence",
        ] {
            require_string_field(event, field)?;
        }
        for field in ["lockout_recommended", "isolation_recommended"] {
            require_bool_field(event, field)?;
        }

        if event.get("schema_version").and_then(Value::as_str)
            != Some("crustacian.endpoint.telemetry.v0")
        {
            return Err("event has unsupported schema_version".to_string());
        }
        if require_string_field(event, "event_id")?.len() < 8 {
            return Err("event_id must be at least 8 characters".to_string());
        }
        if event.get("endpoint_id").and_then(Value::as_str) != Some(batch.endpoint_id.as_str()) {
            return Err("event endpoint_id does not match batch endpoint_id".to_string());
        }
        let confidence = event
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or_else(|| "event missing required numeric field: confidence".to_string())?;
        if !(0.0..=1.0).contains(&confidence) {
            return Err("event confidence must be between 0 and 1".to_string());
        }
    }

    Ok(())
}

fn require_string_field<'a>(event: &'a Value, field: &str) -> Result<&'a str, String> {
    let value = event
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("event missing required string field: {field}"))?;
    if value.trim().is_empty() && field != "forensic_snapshot_sha256" {
        return Err(format!("event string field must not be empty: {field}"));
    }
    Ok(value)
}

fn require_bool_field(event: &Value, field: &str) -> Result<(), String> {
    event
        .get(field)
        .and_then(Value::as_bool)
        .map(|_| ())
        .ok_or_else(|| format!("event missing required boolean field: {field}"))
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
    if target.scheme == "https" {
        return post_json_https(target, bearer_token, body);
    }

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

fn post_json_https(
    target: &HttpTarget,
    bearer_token: Option<&str>,
    body: &[u8],
) -> io::Result<(u16, Vec<u8>)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(io::Error::other)?;
    let mut request = client
        .post(&target.url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec());

    if let Some(token) = bearer_token.filter(|token| !token.trim().is_empty()) {
        request = request.bearer_auth(token);
    }

    let response = request.send().map_err(io::Error::other)?;
    let status_code = response.status().as_u16();
    let response_body = response.bytes().map_err(io::Error::other)?.to_vec();

    Ok((status_code, response_body))
}

fn post_json_with_retry(
    target: &HttpTarget,
    bearer_token: Option<&str>,
    body: &[u8],
    policy: &RetryPolicy,
) -> io::Result<HttpAttempt> {
    let max_attempts = policy.max_attempts.max(1);
    let mut attempts = 0;
    let mut retry_delay = Duration::ZERO;

    loop {
        attempts += 1;
        match post_json(target, bearer_token, body) {
            Ok((status_code, response_body)) => {
                if !is_retryable_status(status_code) || attempts >= max_attempts {
                    return Ok(HttpAttempt {
                        status_code,
                        response_body,
                        attempts,
                        retry_attempts: attempts.saturating_sub(1),
                        retry_delay,
                    });
                }

                let ingest_response = serde_json::from_slice::<IngestResponse>(&response_body).ok();
                let delay = retry_delay_for_attempt(policy, attempts, ingest_response.as_ref());
                retry_delay += delay;
                thread::sleep(delay);
            }
            Err(error) => {
                if attempts >= max_attempts {
                    return Err(error);
                }

                let delay = retry_delay_for_attempt(policy, attempts, None);
                retry_delay += delay;
                thread::sleep(delay);
            }
        }
    }
}

fn is_retryable_status(status_code: u16) -> bool {
    status_code == 408 || status_code == 429 || (500..600).contains(&status_code)
}

fn retry_delay_for_attempt(
    policy: &RetryPolicy,
    failed_attempt: usize,
    ingest_response: Option<&IngestResponse>,
) -> Duration {
    if let Some(seconds) = ingest_response.and_then(|response| response.retry_after_seconds) {
        return clamp_duration(Duration::from_secs(seconds), policy.max_backoff);
    }

    let backoff = exponential_backoff(policy.initial_backoff, policy.max_backoff, failed_attempt);
    if policy.jitter {
        jitter_duration(backoff)
    } else {
        backoff
    }
}

fn exponential_backoff(initial: Duration, max: Duration, failed_attempt: usize) -> Duration {
    if initial.is_zero() {
        return Duration::ZERO;
    }

    let shift = failed_attempt.saturating_sub(1).min(31) as u32;
    let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
    clamp_duration(initial.saturating_mul(multiplier), max)
}

fn jitter_duration(max_delay: Duration) -> Duration {
    if max_delay.is_zero() {
        return Duration::ZERO;
    }

    let max_millis = max_delay.as_millis();
    let jitter_millis = pseudo_random_u128() % (max_millis + 1);
    Duration::from_millis(jitter_millis.min(u64::MAX as u128) as u64)
}

fn pseudo_random_u128() -> u128 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let seed = nanos ^ ((std::process::id() as u128) << 32);
    let mut value = seed ^ (seed << 13);
    value ^= value >> 7;
    value ^ (value << 17)
}

fn clamp_duration(value: Duration, max: Duration) -> Duration {
    if value > max {
        max
    } else {
        value
    }
}

fn parse_http_url(url: &str) -> io::Result<HttpTarget> {
    let (scheme, without_scheme, default_port) =
        if let Some(without_scheme) = url.strip_prefix("http://") {
            ("http", without_scheme, 80)
        } else if let Some(without_scheme) = url.strip_prefix("https://") {
            ("https", without_scheme, 443)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only http:// and https:// ingest URLs are supported by the built-in sender",
            ));
        };
    let (host_port, path) = without_scheme
        .split_once('/')
        .map(|(host, path)| (host, format!("/{path}")))
        .unwrap_or((without_scheme, "/v1/ingest".to_string()));
    let (host, port) = host_port
        .split_once(':')
        .map(|(host, port)| {
            (
                host.to_string(),
                port.parse::<u16>().unwrap_or(default_port),
            )
        })
        .unwrap_or((host_port.to_string(), default_port));

    if host.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ingest URL host is empty",
        ));
    }

    let normalized_url = format!("{scheme}://{host_port}{path}");

    Ok(HttpTarget {
        scheme: scheme.to_string(),
        host,
        port,
        path,
        url: normalized_url,
    })
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
    use std::path::PathBuf;

    #[test]
    fn parses_http_url_with_default_path() {
        let target = parse_http_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 8080);
        assert_eq!(target.path, "/v1/ingest");
        assert_eq!(target.url, "http://127.0.0.1:8080/v1/ingest");
    }

    #[test]
    fn parses_https_url_with_default_path() {
        let target = parse_http_url("https://ingest.example.com").unwrap();
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "ingest.example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.path, "/v1/ingest");
        assert_eq!(target.url, "https://ingest.example.com/v1/ingest");
    }

    #[test]
    fn rejects_unsupported_ingest_url_scheme() {
        assert!(parse_http_url("ftp://example.com").is_err());
    }

    #[test]
    fn validates_matching_batch() {
        let batch = valid_test_batch();

        assert!(validate_batch(&batch, 10).is_ok());
    }

    #[test]
    fn rejects_event_missing_schema_required_field() {
        let mut batch = valid_test_batch();
        batch.events[0]
            .as_object_mut()
            .unwrap()
            .remove("asset_hostname");

        assert_eq!(
            validate_batch(&batch, 10),
            Err("event missing required string field: asset_hostname".to_string())
        );
    }

    #[test]
    fn rejects_confidence_outside_schema_range() {
        let mut batch = valid_test_batch();
        batch.events[0]["confidence"] = json!(1.5);

        assert_eq!(
            validate_batch(&batch, 10),
            Err("event confidence must be between 0 and 1".to_string())
        );
    }

    #[test]
    fn rejects_mismatched_event_endpoint_id() {
        let mut batch = valid_test_batch();
        batch.events[0]["endpoint_id"] = json!("endpoint-2");

        assert_eq!(
            validate_batch(&batch, 10),
            Err("event endpoint_id does not match batch endpoint_id".to_string())
        );
    }

    #[test]
    fn computes_bounded_exponential_backoff() {
        let initial = Duration::from_secs(2);
        let max = Duration::from_secs(10);

        assert_eq!(exponential_backoff(initial, max, 1), Duration::from_secs(2));
        assert_eq!(exponential_backoff(initial, max, 2), Duration::from_secs(4));
        assert_eq!(
            exponential_backoff(initial, max, 4),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn retry_after_hint_is_capped_by_policy() {
        let policy = RetryPolicy {
            max_attempts: 4,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            jitter: false,
        };
        let response = IngestResponse {
            accepted: false,
            accepted_events: 0,
            message: "retry later".to_string(),
            retry_after_seconds: Some(60),
            max_batch_events: Some(100),
        };

        assert_eq!(
            retry_delay_for_attempt(&policy, 1, Some(&response)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn durable_schedule_honors_retry_after_hint_with_cap() {
        let policy = RetryPolicy {
            max_attempts: 1,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10),
            jitter: false,
        };

        assert_eq!(
            retry_delay_for_schedule(&policy, 3, Some(60)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn classifies_transient_http_statuses() {
        assert!(is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(503));
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(202));
    }

    #[test]
    fn durable_retry_state_pauses_delivery_until_next_attempt() {
        let dir = test_temp_dir("durable-retry-pauses");
        fs::create_dir_all(&dir).unwrap();
        let spool_path = dir.join("spool.ndjson");
        let retry_state_path = dir.join("spool-retry.json");
        fs::write(&spool_path, "{}\n").unwrap();
        let next_attempt_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        let schedule = RetrySchedule {
            consecutive_failures: 2,
            next_attempt_at: Some(next_attempt_at.clone()),
            last_error: Some("previous failure".to_string()),
        };
        fs::write(
            &retry_state_path,
            serde_json::to_string_pretty(&schedule).unwrap(),
        )
        .unwrap();

        let report = send_spool_with_durable_retry(
            &spool_path,
            &retry_state_path,
            "endpoint-1",
            "http://127.0.0.1:8080/v1/ingest",
            None,
            100,
            &RetryPolicy::default(),
        )
        .unwrap();

        assert_eq!(report.status_code, 425);
        assert_eq!(report.attempted_events, 0);
        assert_eq!(report.retained_events, 1);
        assert_eq!(report.next_retry_at, Some(next_attempt_at));

        let _ = fs::remove_dir_all(dir);
    }

    fn test_temp_dir(name: &str) -> PathBuf {
        let unique = format!(
            "crustacian-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        std::env::temp_dir().join(unique)
    }

    fn valid_test_batch() -> IngestBatch {
        IngestBatch {
            schema_version: INGEST_BATCH_SCHEMA.to_string(),
            batch_id: "batch-0001".to_string(),
            endpoint_id: "endpoint-1".to_string(),
            sent_at: chrono::Utc::now().to_rfc3339(),
            spool: SpoolStats::default(),
            events: vec![json!({
                "schema_version": "crustacian.endpoint.telemetry.v0",
                "event_id": "event-0001",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "endpoint_id": "endpoint-1",
                "asset_hostname": "workstation-1",
                "platform": "linux",
                "event_kind": "agent.health",
                "severity": "informational",
                "classifier": "agent.health",
                "confidence": 0.99,
                "actor": "unit_test",
                "auth_provider": "none",
                "lockout_recommended": false,
                "isolation_recommended": false,
                "forensic_snapshot_sha256": "",
                "evidence": "ok"
            })],
        }
    }
}
