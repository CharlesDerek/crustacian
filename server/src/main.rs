use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use crustacian_core::{IngestBatch, IngestResponse};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "crustacian-server")]
#[command(about = "Crustacian telemetry ingest API")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8080", env = "CRUSTACIAN_BIND_ADDR")]
    bind: SocketAddr,

    #[arg(long, default_value_t = 1000, env = "CRUSTACIAN_MAX_BATCH_SIZE")]
    max_batch_size: usize,

    #[arg(long, default_value_t = 10000, env = "CRUSTACIAN_QUEUE_LIMIT")]
    queue_limit: usize,

    #[arg(long, default_value_t = 10, env = "CRUSTACIAN_RETRY_AFTER_SECONDS")]
    retry_after_seconds: u64,
}

#[derive(Clone)]
struct AppState {
    total_accepted_events: Arc<AtomicUsize>,
    in_flight_requests: Arc<AtomicUsize>,
    max_batch_size: usize,
    queue_limit: usize,
    retry_after_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let state = AppState {
        total_accepted_events: Arc::new(AtomicUsize::new(0)),
        in_flight_requests: Arc::new(AtomicUsize::new(0)),
        max_batch_size: cli.max_batch_size,
        queue_limit: cli.queue_limit,
        retry_after_seconds: cli.retry_after_seconds,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/ingest", post(ingest))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    info!("crustacian ingest listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "accepted_events": state.total_accepted_events.load(Ordering::Relaxed),
        "in_flight_requests": state.in_flight_requests.load(Ordering::Relaxed),
        "max_batch_size": state.max_batch_size,
        "queue_limit": state.queue_limit
    }))
}

async fn ingest(
    State(state): State<AppState>,
    Json(batch): Json<IngestBatch>,
) -> impl IntoResponse {
    let current_depth = state.in_flight_requests.fetch_add(1, Ordering::Relaxed);
    if current_depth >= state.queue_limit {
        state.in_flight_requests.fetch_sub(1, Ordering::Relaxed);
        let response =
            IngestResponse::backpressure(state.retry_after_seconds, state.max_batch_size);
        let mut headers = HeaderMap::new();
        headers.insert(
            "retry-after",
            HeaderValue::from_str(&state.retry_after_seconds.to_string())
                .expect("numeric header is valid"),
        );
        headers.insert(
            "x-crustacian-max-batch-size",
            HeaderValue::from_str(&state.max_batch_size.to_string())
                .expect("numeric header is valid"),
        );
        warn!("backpressure active at queue depth {}", current_depth);
        return (StatusCode::TOO_MANY_REQUESTS, headers, Json(response));
    }
    let _guard = InFlightGuard::new(Arc::clone(&state.in_flight_requests));

    if let Err(error) = batch.validate(state.max_batch_size) {
        let response = IngestResponse::rejected(error.to_string(), Vec::new());
        return (StatusCode::BAD_REQUEST, HeaderMap::new(), Json(response));
    }

    let accepted_count = batch.events.len();
    let accepted_sequence = batch.accepted_sequence();
    state
        .total_accepted_events
        .fetch_add(accepted_count, Ordering::Relaxed);

    info!(
        endpoint_id = %batch.endpoint_id,
        accepted_count,
        accepted_sequence = ?accepted_sequence,
        "accepted ingest batch"
    );

    (
        StatusCode::ACCEPTED,
        HeaderMap::new(),
        Json(IngestResponse::accepted(accepted_sequence)),
    )
}

struct InFlightGuard {
    counter: Arc<AtomicUsize>,
}

impl InFlightGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        Self { counter }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}
