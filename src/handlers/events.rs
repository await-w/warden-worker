use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::auth::Claims;
use crate::error::AppError;
use crate::router::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct EventCollection {
    pub r#type: i32,
    pub date: String,
    pub cipher_id: Option<String>,
    pub organization_id: Option<String>,
}

/// POST /events/collect
/// Matches upstream Vaultwarden behavior: authenticated endpoint that accepts
/// an array of client events and returns an empty JSON object on success.
#[worker::send]
pub async fn post_events_collect(
    _claims: Claims,
    State(_state): State<Arc<AppState>>,
    Json(_payload): Json<Vec<EventCollection>>,
) -> Result<Json<Value>, AppError> {
    // Events are accepted and discarded; no persistent event store is required
    // for the personal password manager use case.
    Ok(Json(json!({})))
}
