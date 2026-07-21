use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: &str = "1.0.0";
pub const AGENT_NAME: &str = "crustacian";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Debug,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    #[serde(rename = "agent.health")]
    AgentHealth,
    #[serde(rename = "clamav.signature_update")]
    ClamavSignatureUpdate,
    #[serde(rename = "scan.started")]
    ScanStarted,
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    #[serde(rename = "detection.malware")]
    DetectionMalware,
    #[serde(rename = "file.quarantine_planned")]
    FileQuarantinePlanned,
    #[serde(rename = "response.plan_created")]
    ResponsePlanCreated,
    #[serde(rename = "transport.backpressure")]
    TransportBackpressure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub version: String,
    pub platform: String,
}

impl AgentInfo {
    pub fn current(version: impl Into<String>) -> Self {
        Self {
            name: AGENT_NAME.to_string(),
            version: version.into(),
            platform: std::env::consts::OS.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointEvent {
    pub schema_version: String,
    pub event_id: String,
    pub endpoint_id: String,
    pub sequence: u64,
    pub event_type: EventType,
    pub severity: Severity,
    pub observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentInfo>,
    pub payload: Value,
}

impl EndpointEvent {
    pub fn new(
        endpoint_id: impl Into<String>,
        sequence: u64,
        event_type: EventType,
        severity: Severity,
        payload: Value,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: Uuid::new_v4().to_string(),
            endpoint_id: endpoint_id.into(),
            sequence,
            event_type,
            severity,
            observed_at: Utc::now(),
            agent: Some(AgentInfo::current(env!("CARGO_PKG_VERSION"))),
            payload,
        }
    }

    pub fn health(endpoint_id: impl Into<String>, sequence: u64) -> Self {
        Self::new(
            endpoint_id,
            sequence,
            EventType::AgentHealth,
            Severity::Info,
            json!({
                "status": "ok",
                "clamav_detected": command_exists("clamscan"),
                "freshclam_detected": command_exists("freshclam")
            }),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpoolInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_sequence: Option<u64>,
    pub queued_events: usize,
    pub disk_bytes: u64,
    pub dropped_low_priority_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestBatch {
    pub schema_version: String,
    pub batch_id: String,
    pub endpoint_id: String,
    pub sent_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spool: Option<SpoolInfo>,
    pub events: Vec<EndpointEvent>,
}

impl IngestBatch {
    pub fn new(
        endpoint_id: impl Into<String>,
        events: Vec<EndpointEvent>,
        spool: SpoolInfo,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            batch_id: Uuid::new_v4().to_string(),
            endpoint_id: endpoint_id.into(),
            sent_at: Utc::now(),
            spool: Some(spool),
            events,
        }
    }

    pub fn accepted_sequence(&self) -> Option<u64> {
        self.events.iter().map(|event| event.sequence).max()
    }

    pub fn validate(&self, max_batch_size: usize) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }

        if self.events.is_empty() {
            return Err(ValidationError::EmptyBatch);
        }

        if self.events.len() > max_batch_size {
            return Err(ValidationError::BatchTooLarge {
                received: self.events.len(),
                max: max_batch_size,
            });
        }

        for event in &self.events {
            if event.schema_version != SCHEMA_VERSION {
                return Err(ValidationError::UnsupportedSchema(
                    event.schema_version.clone(),
                ));
            }

            if event.endpoint_id != self.endpoint_id {
                return Err(ValidationError::EndpointMismatch {
                    batch_endpoint: self.endpoint_id.clone(),
                    event_endpoint: event.endpoint_id.clone(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResponse {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_sequence: Option<u64>,
    #[serde(default)]
    pub rejected_events: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_batch_size: Option<usize>,
    pub message: String,
}

impl IngestResponse {
    pub fn accepted(accepted_sequence: Option<u64>) -> Self {
        Self {
            accepted: true,
            accepted_sequence,
            rejected_events: Vec::new(),
            retry_after_seconds: None,
            max_batch_size: None,
            message: "batch accepted".to_string(),
        }
    }

    pub fn rejected(message: impl Into<String>, rejected_events: Vec<String>) -> Self {
        Self {
            accepted: false,
            accepted_sequence: None,
            rejected_events,
            retry_after_seconds: None,
            max_batch_size: None,
            message: message.into(),
        }
    }

    pub fn backpressure(retry_after_seconds: u64, max_batch_size: usize) -> Self {
        Self {
            accepted: false,
            accepted_sequence: None,
            rejected_events: Vec::new(),
            retry_after_seconds: Some(retry_after_seconds),
            max_batch_size: Some(max_batch_size),
            message: "ingest backpressure active".to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("unsupported schema version: {0}")]
    UnsupportedSchema(String),
    #[error("batch must include at least one event")]
    EmptyBatch,
    #[error("batch contains {received} events, max is {max}")]
    BatchTooLarge { received: usize, max: usize },
    #[error("event endpoint {event_endpoint} does not match batch endpoint {batch_endpoint}")]
    EndpointMismatch {
        batch_endpoint: String,
        event_endpoint: String,
    },
}

fn command_exists(command: &str) -> bool {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join(command))
                .find(|candidate| candidate.exists())
        })
        .is_some()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_matching_batch() {
        let event = EndpointEvent::new(
            "endpoint-1",
            1,
            EventType::ScanCompleted,
            Severity::Info,
            json!({"files_scanned": 10}),
        );
        let batch = IngestBatch::new("endpoint-1", vec![event], SpoolInfo::default());

        assert!(batch.validate(10).is_ok());
        assert_eq!(batch.accepted_sequence(), Some(1));
    }

    #[test]
    fn rejects_endpoint_mismatch() {
        let event = EndpointEvent::health("endpoint-2", 1);
        let batch = IngestBatch::new("endpoint-1", vec![event], SpoolInfo::default());

        assert!(matches!(
            batch.validate(10),
            Err(ValidationError::EndpointMismatch { .. })
        ));
    }

    #[test]
    fn rejects_oversized_batch() {
        let event = EndpointEvent::health("endpoint-1", 1);
        let batch = IngestBatch::new("endpoint-1", vec![event], SpoolInfo::default());

        assert!(matches!(
            batch.validate(0),
            Err(ValidationError::BatchTooLarge {
                received: 1,
                max: 0
            })
        ));
    }
}
