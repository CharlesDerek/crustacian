use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use crustacian_core::{EndpointEvent, IngestBatch, IngestResponse, SpoolInfo};
use reqwest::blocking::Client;

const DEFAULT_SPOOL_DIR: &str = ".crustacian/spool";
const EVENTS_FILE: &str = "events.ndjson";
const SEQUENCE_FILE: &str = "sequence";

#[derive(Debug, Parser)]
#[command(name = "crustacian-endpoint")]
#[command(about = "Crustacian endpoint telemetry agent")]
struct Cli {
    #[arg(long, env = "CRUSTACIAN_ENDPOINT_ID")]
    endpoint_id: String,

    #[arg(long, default_value = DEFAULT_SPOOL_DIR)]
    spool_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit a local health event into the endpoint spool.
    EmitHealth,
    /// Send spooled events to the ingest API.
    Send {
        #[arg(long, env = "CRUSTACIAN_INGEST_URL")]
        ingest_url: String,

        #[arg(long, env = "CRUSTACIAN_INGEST_TOKEN")]
        token: Option<String>,

        #[arg(long, default_value_t = 100)]
        max_batch: usize,
    },
    /// Emit a health event and immediately try to send the spool.
    RunOnce {
        #[arg(long, env = "CRUSTACIAN_INGEST_URL")]
        ingest_url: String,

        #[arg(long, env = "CRUSTACIAN_INGEST_TOKEN")]
        token: Option<String>,

        #[arg(long, default_value_t = 100)]
        max_batch: usize,
    },
    /// Print local spool status.
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    fs::create_dir_all(&cli.spool_dir).context("failed to create spool directory")?;

    match cli.command {
        Command::EmitHealth => {
            let event = EndpointEvent::health(&cli.endpoint_id, next_sequence(&cli.spool_dir)?);
            append_event(&cli.spool_dir, &event)?;
            println!("queued health event {}", event.event_id);
        }
        Command::Send {
            ingest_url,
            token,
            max_batch,
        } => {
            let sent = send_batch(
                &cli.endpoint_id,
                &cli.spool_dir,
                &ingest_url,
                token.as_deref(),
                max_batch,
            )?;
            println!("sent {sent} event(s)");
        }
        Command::RunOnce {
            ingest_url,
            token,
            max_batch,
        } => {
            let event = EndpointEvent::health(&cli.endpoint_id, next_sequence(&cli.spool_dir)?);
            append_event(&cli.spool_dir, &event)?;
            let sent = send_batch(
                &cli.endpoint_id,
                &cli.spool_dir,
                &ingest_url,
                token.as_deref(),
                max_batch,
            )?;
            println!(
                "queued health event {}; sent {sent} event(s)",
                event.event_id
            );
        }
        Command::Status => {
            let status = spool_info(&cli.spool_dir)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
    }

    Ok(())
}

fn next_sequence(spool_dir: &Path) -> Result<u64> {
    let path = spool_dir.join(SEQUENCE_FILE);
    let current = fs::read_to_string(&path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let next = current + 1;
    fs::write(path, next.to_string()).context("failed to write sequence file")?;
    Ok(next)
}

fn append_event(spool_dir: &Path, event: &EndpointEvent) -> Result<()> {
    let path = spool_dir.join(EVENTS_FILE);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context("failed to open spool events file")?;
    serde_json::to_writer(&mut file, event).context("failed to serialize endpoint event")?;
    writeln!(file).context("failed to append newline to spool")?;
    Ok(())
}

fn read_events(spool_dir: &Path, limit: usize) -> Result<Vec<EndpointEvent>> {
    if limit == 0 {
        bail!("max_batch must be greater than zero");
    }

    let path = spool_dir.join(EVENTS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).context("failed to open spool events file")?;
    let mut events = Vec::new();
    for line in BufReader::new(file).lines().take(limit) {
        let line = line.context("failed to read spooled event")?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str(&line).context("failed to parse spooled event")?);
    }
    Ok(events)
}

fn remove_accepted(spool_dir: &Path, accepted_sequence: u64) -> Result<()> {
    let path = spool_dir.join(EVENTS_FILE);
    if !path.exists() {
        return Ok(());
    }

    let file = File::open(&path).context("failed to open spool for rewrite")?;
    let mut remaining = Vec::new();

    for line in BufReader::new(file).lines() {
        let line = line.context("failed to read spooled event")?;
        if line.trim().is_empty() {
            continue;
        }
        let event: EndpointEvent =
            serde_json::from_str(&line).context("failed to parse spooled event")?;
        if event.sequence > accepted_sequence {
            remaining.push(line);
        }
    }

    let mut file = File::create(&path).context("failed to rewrite spool events file")?;
    for line in remaining {
        writeln!(file, "{line}").context("failed to write remaining spooled event")?;
    }

    Ok(())
}

fn spool_info(spool_dir: &Path) -> Result<SpoolInfo> {
    let path = spool_dir.join(EVENTS_FILE);
    if !path.exists() {
        return Ok(SpoolInfo::default());
    }

    let disk_bytes = fs::metadata(&path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let file = File::open(path).context("failed to open spool events file")?;
    let mut queued_events = 0;
    let mut oldest_sequence = None;
    let mut newest_sequence = None;

    for line in BufReader::new(file).lines() {
        let line = line.context("failed to read spooled event")?;
        if line.trim().is_empty() {
            continue;
        }
        let event: EndpointEvent =
            serde_json::from_str(&line).context("failed to parse spooled event")?;
        queued_events += 1;
        oldest_sequence = oldest_sequence.or(Some(event.sequence));
        newest_sequence = Some(event.sequence);
    }

    Ok(SpoolInfo {
        oldest_sequence,
        newest_sequence,
        queued_events,
        disk_bytes,
        dropped_low_priority_events: 0,
    })
}

fn send_batch(
    endpoint_id: &str,
    spool_dir: &Path,
    ingest_url: &str,
    token: Option<&str>,
    max_batch: usize,
) -> Result<usize> {
    let events = read_events(spool_dir, max_batch)?;
    if events.is_empty() {
        return Ok(0);
    }

    let batch = IngestBatch::new(endpoint_id, events, spool_info(spool_dir)?);
    let client = Client::new();
    let mut request = client
        .post(format!("{}/v1/ingest", ingest_url.trim_end_matches('/')))
        .json(&batch);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }

    let response = request.send().context("failed to send ingest batch")?;
    let status = response.status();
    let ingest_response: IngestResponse =
        response.json().context("failed to parse ingest response")?;

    if status.is_success() && ingest_response.accepted {
        if let Some(sequence) = ingest_response.accepted_sequence {
            remove_accepted(spool_dir, sequence)?;
        }
        return Ok(batch.events.len());
    }

    bail!(
        "ingest rejected batch: status={} message={} retry_after={:?} max_batch_size={:?}",
        status,
        ingest_response.message,
        ingest_response.retry_after_seconds,
        ingest_response.max_batch_size
    );
}
