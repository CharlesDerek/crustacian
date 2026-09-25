use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crustacian::edr_transport::{
    validate_batch, write_accepted_events, IngestBatch, IngestResponse,
};

const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct ServerConfig {
    bind: String,
    data_dir: PathBuf,
    max_batch_events: usize,
    max_in_flight: usize,
    retry_after_seconds: u64,
    bearer_token: Option<String>,
}

fn main() -> io::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--import-legacy") {
        let dir = args.get(2).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: crustacian-ingest --import-legacy DATA_DIR [--dry-run]",
            )
        })?;
        let dry_run = args.iter().any(|arg| arg == "--dry-run");
        let stats = crustacian::ingest_store::import_legacy(std::path::Path::new(dir), dry_run)?;
        println!("{}", serde_json::to_string(&stats)?);
        if stats.malformed > 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy telemetry contains malformed entries; no events imported",
            ));
        }
        return Ok(());
    }
    let config = parse_args();
    let listener = TcpListener::bind(&config.bind)?;
    println!("Crustacian ingest server listening on {}", config.bind);

    let in_flight = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = stream?;
        let config = config.clone();
        let in_flight = Arc::clone(&in_flight);
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, config, in_flight) {
                eprintln!("ingest connection failed: {error}");
            }
        });
    }

    Ok(())
}

fn parse_args() -> ServerConfig {
    let mut bind =
        env::var("CRUSTACIAN_INGEST_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let mut data_dir = env::var("CRUSTACIAN_INGEST_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/crustacian-ingest"));
    let mut max_batch_events = env::var("CRUSTACIAN_INGEST_MAX_BATCH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1000);
    let mut max_in_flight = env::var("CRUSTACIAN_INGEST_MAX_IN_FLIGHT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32);
    let mut retry_after_seconds = env::var("CRUSTACIAN_INGEST_RETRY_AFTER")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10);
    let mut bearer_token = env::var("CRUSTACIAN_INGEST_TOKEN")
        .ok()
        .and_then(non_empty_string);

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => bind = args.next().unwrap_or(bind),
            "--data-dir" => data_dir = args.next().map(PathBuf::from).unwrap_or(data_dir),
            "--max-batch-events" => {
                max_batch_events = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(max_batch_events);
            }
            "--max-in-flight" => {
                max_in_flight = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(max_in_flight);
            }
            "--retry-after-seconds" => {
                retry_after_seconds = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(retry_after_seconds);
            }
            "--bearer-token" => {
                bearer_token = args.next().and_then(non_empty_string);
            }
            _ => {}
        }
    }

    ServerConfig {
        bind,
        data_dir,
        max_batch_events,
        max_in_flight,
        retry_after_seconds,
        bearer_token,
    }
}

fn handle_connection(
    mut stream: TcpStream,
    config: ServerConfig,
    in_flight: Arc<AtomicUsize>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let active = in_flight.fetch_add(1, Ordering::SeqCst);
    if active >= config.max_in_flight {
        in_flight.fetch_sub(1, Ordering::SeqCst);
        let response = IngestResponse {
            accepted: false,
            accepted_events: 0,
            message: "ingest backpressure active".to_string(),
            retry_after_seconds: Some(config.retry_after_seconds),
            max_batch_events: Some(config.max_batch_events),
        };
        return write_json_response(&mut stream, 429, &response);
    }
    let _guard = InFlightGuard::new(Arc::clone(&in_flight));

    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let status = if error.to_string().contains("body exceeds") {
                413
            } else {
                400
            };
            let response = IngestResponse {
                accepted: false,
                accepted_events: 0,
                message: error.to_string(),
                retry_after_seconds: None,
                max_batch_events: Some(config.max_batch_events),
            };
            return write_json_response(&mut stream, status, &response);
        }
        Err(error) => return Err(error),
    };
    let request_text = String::from_utf8_lossy(&request);
    let request_line = request_text.lines().next().unwrap_or_default();

    if request_line.starts_with("GET /health ") {
        let store = crustacian::ingest_store::event_count(&config.data_dir);
        let body = serde_json::json!({
            "status": if store.is_ok() { "ok" } else { "degraded" },
            "durable_events": store.as_ref().ok(),
            "max_batch_events": config.max_batch_events,
            "max_in_flight": config.max_in_flight,
            "in_flight": in_flight.load(Ordering::SeqCst)
        });
        return write_json_response(&mut stream, if store.is_ok() { 200 } else { 503 }, &body);
    }

    if !request_line.starts_with("POST /v1/ingest ") {
        let response = IngestResponse {
            accepted: false,
            accepted_events: 0,
            message: "not found".to_string(),
            retry_after_seconds: None,
            max_batch_events: None,
        };
        return write_json_response(&mut stream, 404, &response);
    }

    if !authorized_ingest_request(&request_text, config.bearer_token.as_deref()) {
        let response = IngestResponse {
            accepted: false,
            accepted_events: 0,
            message: "missing or invalid bearer token".to_string(),
            retry_after_seconds: None,
            max_batch_events: Some(config.max_batch_events),
        };
        return write_json_response(&mut stream, 401, &response);
    }

    let body = split_http_body(&request)?;
    let batch = match serde_json::from_slice::<IngestBatch>(body) {
        Ok(batch) => batch,
        Err(error) => {
            let response = IngestResponse {
                accepted: false,
                accepted_events: 0,
                message: format!("invalid ingest JSON: {error}"),
                retry_after_seconds: None,
                max_batch_events: Some(config.max_batch_events),
            };
            return write_json_response(&mut stream, 400, &response);
        }
    };

    if let Err(error) = validate_batch(&batch, config.max_batch_events) {
        let response = IngestResponse {
            accepted: false,
            accepted_events: 0,
            message: error,
            retry_after_seconds: None,
            max_batch_events: Some(config.max_batch_events),
        };
        return write_json_response(&mut stream, 400, &response);
    }

    let newly_persisted = write_accepted_events(&config.data_dir, &batch)?;
    let response = IngestResponse {
        accepted: true,
        accepted_events: batch.events.len(),
        message: format!("batch accepted; {newly_persisted} new events persisted"),
        retry_after_seconds: None,
        max_batch_events: Some(config.max_batch_events),
    };
    write_json_response(&mut stream, 202, &response)
}

fn non_empty_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn authorized_ingest_request(request_text: &str, expected_token: Option<&str>) -> bool {
    let Some(expected_token) = expected_token.filter(|token| !token.trim().is_empty()) else {
        return true;
    };

    bearer_token_from_request(request_text)
        .map(|actual_token| constant_time_eq(actual_token.as_bytes(), expected_token.as_bytes()))
        .unwrap_or(false)
}

fn bearer_token_from_request(request_text: &str) -> Option<&str> {
    let headers = request_text
        .split("\r\n\r\n")
        .next()
        .unwrap_or(request_text);
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("authorization") {
            return None;
        }

        let value = value.trim();
        let (scheme, token) = value.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() {
            Some(token.trim())
        } else {
            None
        }
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn split_http_body(request: &[u8]) -> io::Result<&[u8]> {
    let separator = b"\r\n\r\n";
    let header_end = request
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP body"))?;
    Ok(&request[header_end + separator.len()..])
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.push(buffer[0]);
        if request.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers exceed 64 KiB",
            ));
        }
    }

    let header_text = String::from_utf8_lossy(&request);
    let content_length = parse_content_length(&header_text)?;

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body)?;
        request.extend_from_slice(&body);
    }

    Ok(request)
}

fn parse_content_length(headers: &str) -> io::Result<usize> {
    let mut length = None;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Content-Length header",
                ));
            }
            let parsed = value.trim().parse::<usize>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length header")
            })?;
            if parsed > MAX_REQUEST_BODY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request body exceeds 8 MiB limit",
                ));
            }
            length = Some(parsed);
        }
    }
    Ok(length.unwrap_or(0))
}

fn write_json_response<T: serde::Serialize>(
    stream: &mut TcpStream,
    status_code: u16,
    body: &T,
) -> io::Result<()> {
    let reason = match status_code {
        200 => "OK",
        202 => "Accepted",
        401 => "Unauthorized",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let body = serde_json::to_vec(body)?;
    write!(
        stream,
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)
}

struct InFlightGuard {
    in_flight: Arc<AtomicUsize>,
}

impl InFlightGuard {
    fn new(in_flight: Arc<AtomicUsize>) -> Self {
        Self { in_flight }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_WITH_VALID_TOKEN: &str = concat!(
        "POST /v1/ingest HTTP/1.1\r\n",
        "Host: 127.0.0.1:8080\r\n",
        "Authorization: Bearer expected-token\r\n",
        "Content-Length: 2\r\n",
        "\r\n",
        "{}"
    );

    #[test]
    fn allows_ingest_when_no_token_is_configured() {
        assert!(authorized_ingest_request(
            "POST /v1/ingest HTTP/1.1\r\n\r\n{}",
            None
        ));
    }

    #[test]
    fn accepts_matching_bearer_token() {
        assert!(authorized_ingest_request(
            REQUEST_WITH_VALID_TOKEN,
            Some("expected-token")
        ));
    }

    #[test]
    fn rejects_missing_bearer_token_when_configured() {
        assert!(!authorized_ingest_request(
            "POST /v1/ingest HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n{}",
            Some("expected-token")
        ));
    }

    #[test]
    fn rejects_invalid_bearer_token() {
        let request = REQUEST_WITH_VALID_TOKEN.replace("expected-token", "wrong-token");

        assert!(!authorized_ingest_request(&request, Some("expected-token")));
    }

    #[test]
    fn parses_authorization_header_case_insensitively() {
        let request = concat!(
            "POST /v1/ingest HTTP/1.1\r\n",
            "authorization: bearer expected-token\r\n",
            "\r\n"
        );

        assert_eq!(bearer_token_from_request(request), Some("expected-token"));
    }

    #[test]
    fn ignores_authorization_text_in_body() {
        let request = concat!(
            "POST /v1/ingest HTTP/1.1\r\n",
            "Content-Length: 36\r\n",
            "\r\n",
            "Authorization: Bearer expected-token"
        );

        assert_eq!(bearer_token_from_request(request), None);
    }

    #[test]
    fn ignores_blank_configured_token() {
        assert!(authorized_ingest_request(
            "POST /v1/ingest HTTP/1.1\r\n\r\n{}",
            Some("  ")
        ));
    }

    #[test]
    fn request_body_limit_rejects_oversized_and_ambiguous_lengths() {
        assert_eq!(
            parse_content_length("Content-Length: 1024\r\n").unwrap(),
            1024
        );
        assert!(parse_content_length("Content-Length: 8388609\r\n").is_err());
        assert!(parse_content_length("Content-Length: 1\r\ncontent-length: 2\r\n").is_err());
        assert!(parse_content_length("Content-Length: not-a-number\r\n").is_err());
    }
}
