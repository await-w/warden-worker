use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{db, error::AppError, router::AppState};

#[worker::send]
pub async fn config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let user_exists: Option<i64> = db
        .prepare("SELECT 1 AS ok FROM users LIMIT 1")
        .first(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?;
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let domain = format!("{proto}://{host}");
    Ok(Json(json!({
        "version": "2026.6.0",
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "settings": {
            "disableUserRegistration": user_exists.is_some(),
            "suppressOnboardingInterstitials": false,
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": null,
          "cloudRegion": null,
        },
        "push": {
          "pushTechnology": 0,
          "vapidPublicKey": null
        },
        "featureStates": {
            "pm-19148-innovation-archive": true
        },
        "communication": null,
        "object": "config",
    })))
}

#[worker::send]
pub async fn apple_app_site_association(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "webcredentials": {
            "apps": [
                "LTZ2PFU5D6.com.8bit.bitwarden",
                "LTZ2PFU5D6.com.8bit.bitwarden.beta"
            ]
        }
    }))
}

#[worker::send]
pub async fn now(State(_state): State<Arc<AppState>>) -> Json<String> {
    Json(Utc::now().to_rfc3339())
}

#[worker::send]
pub async fn alive(State(state): State<Arc<AppState>>) -> Result<Json<String>, AppError> {
    let db = db::get_db(&state.env)?;
    db.prepare("SELECT 1 AS ok")
        .first::<i64>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or(AppError::Database)?;
    Ok(Json(Utc::now().to_rfc3339()))
}

#[worker::send]
pub async fn alive_head(State(state): State<Arc<AppState>>) -> Result<StatusCode, AppError> {
    let db = db::get_db(&state.env)?;
    db.prepare("SELECT 1 AS ok")
        .first::<i64>(Some("ok"))
        .await
        .map_err(|_| AppError::Database)?
        .ok_or(AppError::Database)?;
    Ok(StatusCode::OK)
}

#[worker::send]
pub async fn version(State(_state): State<Arc<AppState>>) -> Json<&'static str> {
    Json(env!("CARGO_PKG_VERSION"))
}

#[worker::send]
pub async fn webauthn(State(_state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    }))
}
