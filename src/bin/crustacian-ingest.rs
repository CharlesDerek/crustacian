use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use crustacian::edr_transport::{
    validate_batch, write_accepted_events, IngestBatch, IngestResponse,
};

#[derive(Clone)]
struct ServerConfig {
    bind: String,
    data_dir: PathBuf,
    max_batch_events: usize,
    max_in_flight: usize,
    retry_after_seconds: u64,
}

fn main() -> io::Result<()> {
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
            _ => {}
        }
    }

    ServerConfig {
        bind,
        data_dir,
        max_batch_events,
        max_in_flight,
        retry_after_seconds,
    }
}

fn handle_connection(
    mut stream: TcpStream,
    config: ServerConfig,
    in_flight: Arc<AtomicUsize>,
) -> io::Result<()> {
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
    let _guard = InFlightGuard::new(in_flight);

    let request = read_http_request(&mut stream)?;
    let request_text = String::from_utf8_lossy(&request);
    let request_line = request_text.lines().next().unwrap_or_default();

    if request_line.starts_with("GET /health ") {
        let body = serde_json::json!({
            "status": "ok",
            "max_batch_events": config.max_batch_events,
            "max_in_flight": config.max_in_flight,
            "in_flight": 0
        });
        return write_json_response(&mut stream, 200, &body);
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

    write_accepted_events(&config.data_dir, &batch)?;
    let response = IngestResponse {
        accepted: true,
        accepted_events: batch.events.len(),
        message: "batch accepted".to_string(),
        retry_after_seconds: None,
        max_batch_events: Some(config.max_batch_events),
    };
    write_json_response(&mut stream, 202, &response)
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
    let content_length = header_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body)?;
        request.extend_from_slice(&body);
    }

    Ok(request)
}

fn write_json_response<T: serde::Serialize>(
    stream: &mut TcpStream,
    status_code: u16,
    body: &T,
) -> io::Result<()> {
    let reason = match status_code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
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
