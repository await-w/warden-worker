use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::{Form, Json, extract::State, response::IntoResponse};
use chrono::{Duration, Utc};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;
use worker::wasm_bindgen::JsValue;

use crate::background::BackgroundExecutor;
use crate::notify::{self, NotifyContext, NotifyEvent};
use crate::router::AppState;
use crate::{
    auth::Claims, crypto, db, error::AppError, jwt, logging::targets, models::user::User, password,
    two_factor, webauthn,
};

const LOGIN_RATE_LIMITER_BINDING: &str = "LOGIN_LIMITER";

/// 后台更新设备信息
/// 将设备表的创建和更新操作放入后台执行，减少登录响应延迟
fn update_device_background(
    ctx: &BackgroundExecutor,
    env: worker::Env,
    user_id: String,
    device_identifier: String,
    device_name: Option<String>,
    device_type: Option<i32>,
) {
    ctx.wait_until(async move {
        log::debug!(
            target: targets::DB,
            "background device update started user_id={} device_id={}",
            user_id,
            device_identifier
        );

        let db = match db::get_db(&env) {
            Ok(db) => db,
            Err(e) => {
                log::warn!(
                    target: targets::DB,
                    "background device update failed: cannot get database user_id={} error={:?}",
                    user_id,
                    e
                );
                return;
            }
        };

        if let Err(e) = ensure_devices_table(&db).await {
            log::warn!(
                target: targets::DB,
                "background device update failed: cannot ensure devices table user_id={} error={:?}",
                user_id,
                e
            );
            return;
        }

        let now = Utc::now().to_rfc3339();

        match db
            .prepare(
                "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(user_id, device_identifier) DO UPDATE SET
                   updated_at = excluded.updated_at,
                   device_name = COALESCE(excluded.device_name, devices.device_name),
                   device_type = COALESCE(excluded.device_type, devices.device_type)",
            )
            .bind(&[
                Uuid::new_v4().to_string().into(),
                user_id.clone().into(),
                device_identifier.clone().into(),
                js_opt_string(device_name.clone()),
                js_opt_i64(device_type.map(|v| v as i64)),
                now.clone().into(),
                now.into(),
            ])
        {
            Ok(stmt) => {
                match stmt.run().await {
                    Ok(_) => {
                        log::info!(
                            target: targets::DB,
                            "background device update success user_id={} device_id={} device_name={:?}",
                            user_id,
                            device_identifier,
                            device_name
                        );
                    }
                    Err(e) => {
                        log::warn!(
                            target: targets::DB,
                            "background device update failed: database error user_id={} device_id={} error={:?}",
                            user_id,
                            device_identifier,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    target: targets::DB,
                    "background device update failed: bind error user_id={} device_id={} error={:?}",
                    user_id,
                    device_identifier,
                    e
                );
            }
        }
    });
}

fn deserialize_trimmed_i32_opt<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            s.parse::<i32>().map(Some).map_err(de::Error::custom)
        }
    }
}

fn deserialize_truthy_i32_opt<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    let Some(s) = opt else { return Ok(None) };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if matches!(s, "1" | "true" | "True" | "TRUE") {
        return Ok(Some(1));
    }
    if matches!(s, "0" | "false" | "False" | "FALSE") {
        return Ok(Some(0));
    }
    s.parse::<i32>().map(Some).map_err(de::Error::custom)
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
    token: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: Option<String>,
    #[serde(rename = "scope")]
    _scope: Option<String>,
    #[serde(rename = "client_id")]
    _client_id: Option<String>,
    #[serde(
        rename = "deviceIdentifier",
        alias = "device_identifier",
        alias = "deviceId"
    )]
    device_identifier: Option<String>,
    #[serde(rename = "deviceName", alias = "device_name")]
    device_name: Option<String>,
    #[serde(rename = "deviceType", alias = "device_type")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    device_type: Option<i32>,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider", alias = "two_factor_provider")]
    #[serde(default, deserialize_with = "deserialize_trimmed_i32_opt")]
    two_factor_provider: Option<i32>,
    #[serde(rename = "twoFactorRemember")]
    #[serde(default, deserialize_with = "deserialize_truthy_i32_opt")]
    two_factor_remember: Option<i32>,
    #[serde(rename = "authRequest")]
    auth_request: Option<String>,
    #[serde(rename = "code")] // Used for auth-request flow
    access_code: Option<String>,
}

fn js_opt_string(v: Option<String>) -> JsValue {
    match v {
        Some(v) => JsValue::from_str(&v),
        None => JsValue::NULL,
    }
}

fn js_opt_i64(v: Option<i64>) -> JsValue {
    match v {
        Some(v) => JsValue::from_f64(v as f64),
        None => JsValue::NULL,
    }
}

fn normalize_kdf_for_response(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    crypto::normalize_kdf_params(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
}

#[derive(Debug, Clone)]
struct WebAuthnPrfOptionPayload {
    encrypted_private_key: String,
    encrypted_user_key: String,
}

async fn generate_tokens_and_response(
    user: User,
    state: &Arc<AppState>,
    device_identifier: Option<String>,
    webauthn_prf_option: Option<&WebAuthnPrfOptionPayload>,
) -> Result<Value, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(2);
    let exp = (now + expires_in).timestamp() as usize;

    let access_claims = Claims {
        sub: user.id.clone(),
        exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
        security_stamp: Some(user.security_stamp.clone()),
        device: device_identifier.clone(),
    };

    let jwt_keys = state.jwt_keys.clone();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(jwt_keys.access_secret.as_ref()),
    )?;

    let refresh_expires_in = Duration::days(30);
    let refresh_exp = (now + refresh_expires_in).timestamp() as usize;
    let refresh_claims = Claims {
        sub: user.id.clone(),
        exp: refresh_exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
        security_stamp: Some(user.security_stamp.clone()),
        device: device_identifier,
    };
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_keys.refresh_secret.as_ref()),
    )?;

    let (kdf_memory, kdf_parallelism) = normalize_kdf_for_response(
        user.kdf_type,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism,
    );

    let mut user_decryption_options = json!({
        "HasMasterPassword": true,
        "MasterPasswordUnlock": {
            "Kdf": {
                "KdfType": user.kdf_type,
                "Iterations": user.kdf_iterations,
                "Memory": kdf_memory,
                "Parallelism": kdf_parallelism
            },
            "MasterKeyEncryptedUserKey": user.key,
            "MasterKeyWrappedUserKey": user.key,
            "Salt": user.email
        },
        "Object": "userDecryptionOptions"
    });

    if let Some(option) = webauthn_prf_option
        && let Some(obj) = user_decryption_options.as_object_mut()
    {
        obj.insert(
            "WebAuthnPrfOption".to_string(),
            json!({
                "EncryptedPrivateKey": option.encrypted_private_key,
                "EncryptedUserKey": option.encrypted_user_key
            }),
        );
    }

    Ok(json!({
        "ForcePasswordReset": false,
        "Kdf": user.kdf_type,
        "KdfIterations": user.kdf_iterations,
        "KdfMemory": kdf_memory,
        "KdfParallelism": kdf_parallelism,
        "Key": user.key,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "PrivateKey": user.private_key,
        "ResetMasterPassword": false,
        "UserDecryptionOptions": user_decryption_options,
        "AccountKeys": {
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair"
            },
            "Object": "privateKeys"
        },
        "access_token": access_token,
        "expires_in": expires_in.num_seconds(),
        "refresh_token": refresh_token,
        "scope": "api offline_access",
        "token_type": "Bearer"
    }))
}

async fn ensure_devices_table(db: &worker::D1Database) -> Result<(), AppError> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            device_identifier TEXT NOT NULL,
            device_name TEXT,
            device_type INTEGER,
            remember_token_hash TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, device_identifier),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    )
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let _ = db
        .prepare("ALTER TABLE devices ADD COLUMN remember_token_hash TEXT")
        .run()
        .await;

    Ok(())
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn verify_remember_token(
    token: &str,
    device_uuid: &str,
    user_uuid: &str,
    jwt_secret: &str,
) -> bool {
    match jwt::decode_2fa_remember(token, jwt_secret) {
        Ok(claims) => claims.sub == device_uuid && claims.user_uuid == user_uuid,
        Err(_) => false,
    }
}

async fn generate_remember_token_async(
    device_uuid: &str,
    user_uuid: &str,
    state: &Arc<AppState>,
) -> Result<String, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let claims = jwt::generate_2fa_remember_claims(device_uuid.to_string(), user_uuid.to_string());
    jwt::encode_2fa_remember(&claims, &jwt_keys.access_secret)
}

async fn verify_remember_token_async(
    token: &str,
    device_uuid: &str,
    user_uuid: &str,
    state: &Arc<AppState>,
) -> Result<bool, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    Ok(verify_remember_token(
        token,
        device_uuid,
        user_uuid,
        &jwt_keys.access_secret,
    ))
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn set_cookie(
    headers: &mut axum::http::HeaderMap,
    name: &str,
    value: &str,
    max_age_seconds: i64,
) -> Result<(), AppError> {
    let cookie = format!(
        "{name}={value}; Max-Age={max_age_seconds}; Path=/; HttpOnly; Secure; SameSite=Lax",
    );
    headers.append(
        header::SET_COOKIE,
        cookie.parse().map_err(|_| AppError::Internal)?,
    );
    Ok(())
}

fn client_ip_from_headers(headers: &HeaderMap) -> String {
    if let Some(ip) = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("CF-Connecting-IP"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return ip.to_string();
    }

    if let Some(ip) = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("X-Forwarded-For"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return ip.to_string();
    }

    "0.0.0.0".to_string()
}

async fn enforce_login_rate_limit(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    username: &str,
) -> Result<(), AppError> {
    let limiter = match state.env.rate_limiter(LOGIN_RATE_LIMITER_BINDING) {
        Ok(l) => l,
        Err(_) => return Ok(()),
    };
    let ip = client_ip_from_headers(headers);
    let key = format!("login:{}:{}", ip, username.trim().to_lowercase());
    let outcome = limiter.limit(key).await.map_err(|_| AppError::Internal)?;
    if !outcome.success {
        return Err(AppError::TooManyRequests(
            "Too many login attempts".to_string(),
        ));
    }
    Ok(())
}

async fn get_email_2fa_display_info(
    providers: &[i32],
    user_id: &str,
    state: &Arc<AppState>,
) -> Option<(String, String)> {
    if !providers.contains(&two_factor::TWO_FACTOR_PROVIDER_EMAIL) {
        return None;
    }

    let db = match db::get_db(&state.env) {
        Ok(db) => db,
        Err(_) => return None,
    };

    let (_, data) = match two_factor::get_email_2fa(&db, user_id).await {
        Ok(Some((enabled, data))) if enabled => (enabled, data),
        _ => return None,
    };

    let email_data = match two_factor::EmailTokenData::from_json(&data) {
        Ok(d) => d,
        Err(_) => return None,
    };

    let obscured = obscure_email(&email_data.email);
    Some((obscured, email_data.email))
}

fn obscure_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return "***".to_string();
    }
    let name = parts[0];
    let domain = parts[1];

    let obscured_name = if name.len() <= 2 {
        "*".repeat(name.len())
    } else {
        format!("{}***", &name[..2])
    };

    format!("{}@{}", obscured_name, domain)
}

fn invalid_grant_response(error_description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": error_description,
        })),
    )
        .into_response()
}

async fn two_factor_required_response(
    providers: &[i32],
    user_id: &str,
    email_2fa_data: Option<(String, String)>,
    headers: &HeaderMap,
    db: &worker::D1Database,
) -> Response {
    let mut response_providers: Vec<String> = Vec::new();
    let mut providers2 = serde_json::Map::new();
    for &p in providers {
        if p == two_factor::TWO_FACTOR_PROVIDER_EMAIL {
            response_providers.push(p.to_string());
            if let Some((ref email, _)) = email_2fa_data {
                providers2.insert(
                    p.to_string(),
                    json!({
                        "Email": email
                    }),
                );
            } else {
                providers2.insert(p.to_string(), Value::Null);
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN {
            if webauthn::is_webauthn_2fa_supported(headers) {
                let rp_id = webauthn::rp_id_from_headers(headers);
                let origin = webauthn::origin_from_headers(headers);
                if let Ok(Some(challenge)) = webauthn::issue_login_challenge(
                    db,
                    user_id,
                    &rp_id,
                    &origin,
                    webauthn::WEBAUTHN_USE_2FA,
                )
                .await
                {
                    response_providers.push(p.to_string());
                    providers2.insert(p.to_string(), challenge);
                }
            }
        } else {
            response_providers.push(p.to_string());
            providers2.insert(p.to_string(), Value::Null);
        }
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": response_providers,
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Two factor required."
        })),
    )
        .into_response()
}

async fn invalid_two_factor_response(
    providers: &[i32],
    user_id: &str,
    headers: &HeaderMap,
    state: &Arc<AppState>,
    db: &worker::D1Database,
) -> Response {
    let mut response_providers: Vec<String> = Vec::new();
    let email_2fa_data = get_email_2fa_display_info(providers, user_id, state).await;

    let mut providers2 = serde_json::Map::new();
    for &p in providers {
        if p == two_factor::TWO_FACTOR_PROVIDER_EMAIL {
            response_providers.push(p.to_string());
            if let Some((ref email, _)) = email_2fa_data {
                providers2.insert(
                    p.to_string(),
                    json!({
                        "Email": email
                    }),
                );
            } else {
                providers2.insert(p.to_string(), Value::Null);
            }
        } else if p == two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN {
            if webauthn::is_webauthn_2fa_supported(headers) {
                let rp_id = webauthn::rp_id_from_headers(headers);
                let origin = webauthn::origin_from_headers(headers);
                if let Ok(Some(challenge)) = webauthn::issue_login_challenge(
                    db,
                    user_id,
                    &rp_id,
                    &origin,
                    webauthn::WEBAUTHN_USE_2FA,
                )
                .await
                {
                    response_providers.push(p.to_string());
                    providers2.insert(p.to_string(), challenge);
                }
            }
        } else {
            response_providers.push(p.to_string());
            providers2.insert(p.to_string(), Value::Null);
        }
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "TwoFactorProviders": response_providers,
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "error": "invalid_grant",
            "error_description": "Invalid two factor token."
        })),
    )
        .into_response()
}

#[worker::send]
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(payload): Form<TokenRequest>,
) -> Result<Response, AppError> {
    let db = db::get_db(&state.env)?;
    match payload.grant_type.as_str() {
        "password" => {
            let username = payload
                .username
                .ok_or_else(|| AppError::BadRequest("Missing username".to_string()))?;
            enforce_login_rate_limit(&state, &headers, &username).await?;
            let password_hash = if payload.auth_request.is_some() {
                payload.password.unwrap_or_default()
            } else {
                payload
                    .password
                    .ok_or_else(|| AppError::BadRequest("Missing password".to_string()))?
            };

            let user_val: Value = match db
                .prepare("SELECT * FROM users WHERE email = ?1")
                .bind(&[username.to_lowercase().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?
            {
                Some(v) => v,
                None => {
                    notify::notify_background(
                        &state.ctx,
                        state.env.clone(),
                        NotifyEvent::LoginFailed,
                        NotifyContext {
                            user_email: Some(username.clone()),
                            device_identifier: payload.device_identifier.clone(),
                            device_name: payload.device_name.clone(),
                            device_type: payload.device_type,
                            meta: notify::extract_request_meta(&headers),
                            ..Default::default()
                        },
                    );
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
            };
            let user: User = serde_json::from_value(user_val).map_err(|_| AppError::Internal)?;

            // If this is an auth-request login (trusted device), skip master password check
            // and verify the auth-request access code instead.
            if let Some(auth_request_id) = payload.auth_request.as_deref() {
                use crate::handlers::devices as dev;
                dev::ensure_auth_requests_table(&db).await?;
                dev::purge_expired_auth_requests(&db).await?;

                let ar_row: Option<Value> = db
                    .prepare("SELECT * FROM auth_requests WHERE id = ?1 AND user_id = ?2 LIMIT 1")
                    .bind(&[auth_request_id.into(), user.id.clone().into()])?
                    .first(None)
                    .await
                    .map_err(|_| AppError::Database)?;
                let ar_row = ar_row
                    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

                // Must be approved
                let approved = ar_row
                    .get("approved")
                    .and_then(|v| {
                        if v.is_null() {
                            None
                        } else if let Some(b) = v.as_bool() {
                            Some(b)
                        } else {
                            v.as_i64().map(|i| i != 0)
                        }
                    })
                    .unwrap_or(false);
                if !approved {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }

                let already_authenticated = ar_row
                    .get("authentication_date")
                    .and_then(|v| v.as_str())
                    .is_some();
                if already_authenticated {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }

                let request_device_identifier = ar_row
                    .get("request_device_identifier")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let request_device_type = ar_row
                    .get("device_type")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32)
                    .unwrap_or(14);
                let request_ip = ar_row
                    .get("request_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                let payload_device_identifier = payload
                    .device_identifier
                    .as_deref()
                    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
                if payload_device_identifier != request_device_identifier {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }

                let payload_device_type = payload
                    .device_type
                    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
                if payload_device_type != request_device_type {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }

                let current_ip = client_ip_from_headers(&headers);
                if current_ip != request_ip {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }

                // Verify access code
                let stored_hash = ar_row
                    .get("access_code_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                let access_code = payload.access_code.as_deref().unwrap_or(&password_hash);
                let candidate_hash = sha256_hex(access_code);
                if !constant_time_eq(stored_hash.as_bytes(), candidate_hash.as_bytes()) {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }

                db.prepare(
                    "UPDATE auth_requests
                     SET authentication_date = ?1
                     WHERE id = ?2 AND user_id = ?3 AND authentication_date IS NULL",
                )
                .bind(&[
                    Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                        .into(),
                    auth_request_id.into(),
                    user.id.clone().into(),
                ])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;

                db.prepare("DELETE FROM auth_requests WHERE id = ?1 AND user_id = ?2")
                    .bind(&[auth_request_id.into(), user.id.clone().into()])?
                    .run()
                    .await
                    .map_err(|_| AppError::Database)?;

                // Auth-request login bypasses 2FA and remember-device flow
                let user_id = user.id.clone();
                let device_identifier = payload.device_identifier.clone();
                let device_name = payload.device_name.clone();
                let device_type = payload.device_type;

                let response =
                    generate_tokens_and_response(user, &state, device_identifier.clone(), None)
                        .await?;

                if let Some(device_id) = device_identifier {
                    update_device_background(
                        &state.ctx,
                        state.env.clone(),
                        user_id,
                        device_id,
                        device_name,
                        device_type,
                    );
                }

                return Ok(Json(response).into_response());
            }

            let password_valid =
                password::verify_user_password(&db, &user.id, &password_hash).await?;

            if !password_valid {
                notify::notify_background(
                    &state.ctx,
                    state.env.clone(),
                    NotifyEvent::LoginFailed,
                    NotifyContext {
                        user_id: Some(user.id.clone()),
                        user_email: Some(user.email.clone()),
                        device_identifier: payload.device_identifier.clone(),
                        device_name: payload.device_name.clone(),
                        device_type: payload.device_type,
                        meta: notify::extract_request_meta(&headers),
                        ..Default::default()
                    },
                );
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            let authenticator_enabled = two_factor::is_authenticator_enabled(&db, &user.id).await?;
            let email_2fa_enabled = two_factor::is_email_2fa_enabled(&db, &user.id).await?;
            let email_2fa_usable =
                email_2fa_enabled && notify::is_email_webhook_configured(&state.env);
            let webauthn_enabled = webauthn::is_webauthn_enabled(&db, &user.id).await?;
            let webauthn_usable = webauthn_enabled && webauthn::is_webauthn_2fa_supported(&headers);
            let two_factor_enabled = authenticator_enabled || email_2fa_enabled || webauthn_enabled;

            let mut providers: Vec<i32> = Vec::new();
            if authenticator_enabled {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR);
            }
            if email_2fa_usable {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_EMAIL);
            }
            if webauthn_usable {
                providers.push(two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN);
            }
            if two_factor_enabled && providers.is_empty() {
                return Ok(invalid_grant_response(
                    "No enabled and usable two factor providers are available for this account",
                ));
            }
            // 注意：Recovery Code (type=8) 不在这里添加，因为它不是常规的2FA方式
            // 它只在登录验证时作为一种特殊的恢复选项处理

            let mut remember_token_to_return: Option<String> = None;
            if two_factor_enabled {
                let wants_remember = payload.two_factor_remember.unwrap_or(0) == 1;
                let provider = payload.two_factor_provider;
                let token = payload.two_factor_token.clone();

                if provider.is_none() && token.is_none() {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };
                    let cookie_token = get_cookie(&headers, "twoFactorRemember")
                        .or_else(|| get_cookie(&headers, "TwoFactorRemember"));
                    let Some(cookie_token) = cookie_token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };

                    let valid = verify_remember_token_async(
                        cookie_token.trim(),
                        device_identifier,
                        &user.id,
                        &state,
                    )
                    .await?;
                    if !valid {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(5) {
                    let Some(device_identifier) = payload.device_identifier.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };

                    let valid = verify_remember_token_async(
                        token.trim(),
                        device_identifier,
                        &user.id,
                        &state,
                    )
                    .await?;
                    if !valid {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_AUTHENTICATOR)
                    && authenticator_enabled
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };

                    let secret_enc = two_factor::get_authenticator_secret_enc(&db, &user.id)
                        .await?
                        .ok_or_else(|| AppError::Internal)?;
                    let secret_encoded = two_factor::decrypt_secret_with_key(
                        &state.two_factor_key,
                        &user.id,
                        &secret_enc,
                    )?;
                    if !two_factor::verify_totp_code(&secret_encoded, token)? {
                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Authenticator Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers, &user.id, &headers, &state, &db,
                        )
                        .await);
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_EMAIL)
                    && email_2fa_usable
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };

                    let (_, data) = two_factor::get_email_2fa(&db, &user.id)
                        .await?
                        .ok_or_else(|| AppError::Internal)?;
                    let mut email_data = two_factor::EmailTokenData::from_json(&data)?;

                    let Some(issued_token) = email_data.last_token.clone() else {
                        log::warn!(
                            target: targets::AUTH,
                            "email 2fa login failed: no token available user_id={}",
                            user.id
                        );
                        return Ok(invalid_two_factor_response(
                            &providers, &user.id, &headers, &state, &db,
                        )
                        .await);
                    };

                    // 首先验证token是否匹配（常量时间比较）
                    if !constant_time_eq(token.as_bytes(), issued_token.as_bytes()) {
                        // 验证失败，增加尝试次数
                        email_data.add_attempt();
                        if email_data.attempts >= 3 {
                            email_data.reset_token();
                        }

                        let now = Utc::now().to_rfc3339();
                        let _ = two_factor::upsert_email_2fa(
                            &db,
                            &user.id,
                            two_factor::TWO_FACTOR_PROVIDER_EMAIL,
                            true,
                            &email_data.to_json(),
                            &now,
                        )
                        .await;

                        log::warn!(
                            target: targets::AUTH,
                            "email 2fa login failed: invalid token user_id={} attempts={}",
                            user.id,
                            email_data.attempts
                        );

                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Email Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers, &user.id, &headers, &state, &db,
                        )
                        .await);
                    }

                    // token验证成功，先重置token
                    email_data.reset_token();
                    let now = Utc::now().to_rfc3339();
                    two_factor::upsert_email_2fa(
                        &db,
                        &user.id,
                        two_factor::TWO_FACTOR_PROVIDER_EMAIL,
                        true,
                        &email_data.to_json(),
                        &now,
                    )
                    .await?;

                    // 最后检查token是否过期（参考vaultwarden实现）
                    if two_factor::is_token_expired(email_data.token_sent, 600) {
                        log::warn!(
                            target: targets::AUTH,
                            "email 2fa login failed: token expired user_id={}",
                            user.id
                        );
                        return Ok(invalid_two_factor_response(
                            &providers, &user.id, &headers, &state, &db,
                        )
                        .await);
                    }

                    log::info!(
                        target: targets::AUTH,
                        "email 2fa login success user_id={}",
                        user.id
                    );

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_RECOVERY_CODE) {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };

                    // 验证恢复码
                    let recovery_valid =
                        two_factor::verify_recovery_code(&db, &user.id, token).await?;
                    if !recovery_valid {
                        log::warn!(
                            target: targets::AUTH,
                            "recovery code login failed: invalid code user_id={}",
                            user.id
                        );

                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA Recovery Code Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers, &user.id, &headers, &state, &db,
                        )
                        .await);
                    }

                    // 恢复码验证成功，删除所有2FA并清除恢复码
                    log::info!(
                        target: targets::AUTH,
                        "recovery code login success: removing all 2fa user_id={}",
                        user.id
                    );

                    two_factor::delete_all_two_factors(&db, &user.id).await?;
                    two_factor::clear_recovery_code(&db, &user.id).await?;

                    // 发送恢复通知
                    notify::notify_background(
                        &state.ctx,
                        state.env.clone(),
                        NotifyEvent::TwoFactorRecover,
                        NotifyContext {
                            user_id: Some(user.id.clone()),
                            user_email: Some(user.email.clone()),
                            device_identifier: payload.device_identifier.clone(),
                            device_name: payload.device_name.clone(),
                            device_type: payload.device_type,
                            meta: notify::extract_request_meta(&headers),
                            ..Default::default()
                        },
                    );
                } else if provider == Some(two_factor::TWO_FACTOR_PROVIDER_WEBAUTHN)
                    && webauthn_usable
                {
                    let Some(token) = token.as_deref() else {
                        let email_data =
                            get_email_2fa_display_info(&providers, &user.id, &state).await;
                        return Ok(two_factor_required_response(
                            &providers, &user.id, email_data, &headers, &db,
                        )
                        .await);
                    };

                    if webauthn::verify_login_assertion(
                        &db,
                        &user.id,
                        token,
                        webauthn::WEBAUTHN_USE_2FA,
                    )
                    .await
                    .is_err()
                    {
                        notify::notify_background(
                            &state.ctx,
                            state.env.clone(),
                            NotifyEvent::LoginFailed,
                            NotifyContext {
                                user_id: Some(user.id.clone()),
                                user_email: Some(user.email.clone()),
                                detail: Some("2FA WebAuthn Verification Failed".to_string()),
                                device_identifier: payload.device_identifier.clone(),
                                device_name: payload.device_name.clone(),
                                device_type: payload.device_type,
                                meta: notify::extract_request_meta(&headers),
                                ..Default::default()
                            },
                        );
                        return Ok(invalid_two_factor_response(
                            &providers, &user.id, &headers, &state, &db,
                        )
                        .await);
                    }

                    if wants_remember && payload.device_identifier.is_some() {
                        remember_token_to_return = Some(
                            generate_remember_token_async(
                                payload.device_identifier.as_deref().unwrap(),
                                &user.id,
                                &state,
                            )
                            .await?,
                        );
                    }
                } else {
                    let email_data = get_email_2fa_display_info(&providers, &user.id, &state).await;
                    return Ok(two_factor_required_response(
                        &providers, &user.id, email_data, &headers, &db,
                    )
                    .await);
                }
            }

            let user_id = user.id.clone();
            let user_email_for_notify = Some(user.email.clone());
            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;
            log::info!(
                target: targets::AUTH,
                "token login device id={:?} type={:?} name={:?} 2fa_provider={:?} remember={:?}",
                device_identifier,
                device_type,
                device_name,
                payload.two_factor_provider,
                payload.two_factor_remember
            );

            let mut response =
                generate_tokens_and_response(user, &state, device_identifier.clone(), None).await?;
            let remember_token_to_set = remember_token_to_return.clone();

            // 后台异步更新设备信息，减少登录响应延迟
            if let Some(device_identifier) = device_identifier.clone() {
                log::debug!(
                    target: targets::AUTH,
                    "scheduling background device update user_id={} device_id={}",
                    user_id,
                    device_identifier
                );
                update_device_background(
                    &state.ctx,
                    state.env.clone(),
                    user_id.clone(),
                    device_identifier,
                    device_name.clone(),
                    device_type,
                );
            }

            if let Some(token) = remember_token_to_return
                && let Some(obj) = response.as_object_mut()
            {
                obj.insert("TwoFactorToken".to_string(), Value::String(token));
            }

            let access_token_to_set = response
                .get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let refresh_token_to_set = response
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut resp = Json(response).into_response();
            if let Some(token) = remember_token_to_set {
                set_cookie(
                    resp.headers_mut(),
                    "twoFactorRemember",
                    &token,
                    Duration::days(30).num_seconds(),
                )?;
                set_cookie(
                    resp.headers_mut(),
                    "TwoFactorRemember",
                    &token,
                    Duration::days(30).num_seconds(),
                )?;
            }
            if let Some(v) = access_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = refresh_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }

            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                NotifyEvent::Login,
                NotifyContext {
                    user_id: Some(user_id),
                    user_email: user_email_for_notify,
                    device_identifier,
                    device_name,
                    device_type,
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );
            Ok(resp)
        }
        "refresh_token" => {
            let Some(refresh_token) = payload
                .refresh_token
                .or_else(|| get_cookie(&headers, "bw_refresh_token"))
            else {
                return Ok(invalid_grant_response("Missing refresh_token"));
            };

            let jwt_keys = state.jwt_keys.clone();
            let token_data = match decode::<Claims>(
                &refresh_token,
                &DecodingKey::from_secret(jwt_keys.refresh_secret.as_ref()),
                &Validation::default(),
            ) {
                Ok(data) => data,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Invalid refresh token"
                        })),
                    )
                        .into_response());
                }
            };

            let user_id = token_data.claims.sub;
            let user: Value = match db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
            {
                Ok(Some(v)) => v,
                _ => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Invalid user"
                        })),
                    )
                        .into_response());
                }
            };
            let user: User = match serde_json::from_value(user) {
                Ok(u) => u,
                Err(_) => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Invalid user"
                        })),
                    )
                        .into_response());
                }
            };

            let stamp = match token_data.claims.security_stamp {
                Some(s) => s,
                None => {
                    return Ok((
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_grant",
                            "error_description": "Missing security stamp"
                        })),
                    )
                        .into_response());
                }
            };

            if stamp != user.security_stamp {
                return Ok((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_grant",
                        "error_description": "Invalid security stamp"
                    })),
                )
                    .into_response());
            }

            let response = generate_tokens_and_response(
                user.clone(),
                &state,
                payload.device_identifier.clone(),
                None,
            )
            .await?;
            let mut resp = Json(response.clone()).into_response();
            if let Some(v) = response.get("access_token").and_then(|v| v.as_str()) {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = response.get("refresh_token").and_then(|v| v.as_str()) {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }

            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                NotifyEvent::TokenRefresh,
                NotifyContext {
                    user_id: Some(user.id.clone()),
                    user_email: Some(user.email.clone()),
                    device_identifier: payload.device_identifier.clone(),
                    device_name: payload.device_name.clone(),
                    device_type: payload.device_type,
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );

            Ok(resp)
        }
        "webauthn" => {
            let challenge_token = payload
                .token
                .ok_or_else(|| AppError::BadRequest("Missing token".to_string()))?;
            let device_response = payload
                .device_response
                .ok_or_else(|| AppError::BadRequest("Missing deviceResponse".to_string()))?;
            log::info!(
                target: targets::AUTH,
                "identity token webauthn start device_identifier={:?} device_name={:?} device_type={:?}",
                payload.device_identifier,
                payload.device_name,
                payload.device_type
            );
            let jwt_keys = state.jwt_keys.clone();
            let login_result = webauthn::verify_passwordless_login_assertion(
                &db,
                &challenge_token,
                &device_response,
                &jwt_keys.access_secret,
            )
            .await
            .map_err(|e| match e {
                AppError::BadRequest(msg) | AppError::Unauthorized(msg) => {
                    AppError::Unauthorized(msg)
                }
                other => other,
            })?;
            let user_id = login_result.user_id.clone();
            log::info!(
                target: targets::AUTH,
                "identity token webauthn verified user_id={} has_enc_user={} has_enc_priv={}",
                user_id,
                login_result
                    .encrypted_user_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_some(),
                login_result
                    .encrypted_private_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .is_some()
            );

            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.clone().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid WebAuthn credentials".to_string()))?
                .ok_or_else(|| {
                    AppError::Unauthorized("Invalid WebAuthn credentials".to_string())
                })?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            let device_identifier = payload.device_identifier.clone();
            let device_name = payload.device_name.clone();
            let device_type = payload.device_type;

            let webauthn_prf_option = match (
                login_result.encrypted_private_key.as_deref(),
                login_result.encrypted_user_key.as_deref(),
            ) {
                (Some(encrypted_private_key), Some(encrypted_user_key))
                    if !encrypted_private_key.trim().is_empty()
                        && !encrypted_user_key.trim().is_empty() =>
                {
                    Some(WebAuthnPrfOptionPayload {
                        encrypted_private_key: encrypted_private_key.to_string(),
                        encrypted_user_key: encrypted_user_key.to_string(),
                    })
                }
                _ => None,
            };

            log::info!(
                target: targets::AUTH,
                "identity token webauthn response user_id={} include_prf_option={}",
                user_id,
                webauthn_prf_option.is_some()
            );

            let user_email = user.email.clone();
            let response = generate_tokens_and_response(
                user,
                &state,
                device_identifier.clone(),
                webauthn_prf_option.as_ref(),
            )
            .await?;

            if let Some(device_identifier) = device_identifier.as_deref() {
                ensure_devices_table(&db).await?;

                let now = chrono::Utc::now().to_rfc3339();
                if let Ok(stmt) = db
                    .prepare(
                        "INSERT INTO devices (id, user_id, device_identifier, device_name, device_type, remember_token_hash, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                         ON CONFLICT(user_id, device_identifier) DO UPDATE SET
                           updated_at = excluded.updated_at,
                           device_name = excluded.device_name,
                           device_type = excluded.device_type,
                           remember_token_hash = COALESCE(excluded.remember_token_hash, devices.remember_token_hash)",
                    )
                    .bind(&[
                        Uuid::new_v4().to_string().into(),
                        user_id.clone().into(),
                        device_identifier.into(),
                        device_name.clone().into(),
                        device_type.map(f64::from).into(),
                        Option::<String>::None.into(),
                        now.clone().into(),
                        now.clone().into(),
                    ])
                {
                    let _ = stmt.run().await;
                }
            }

            let access_token_to_set = response
                .get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let refresh_token_to_set = response
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut resp = Json(response).into_response();
            if let Some(v) = access_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_access_token",
                    v,
                    Duration::hours(2).num_seconds(),
                )?;
            }
            if let Some(v) = refresh_token_to_set.as_deref() {
                set_cookie(
                    resp.headers_mut(),
                    "bw_refresh_token",
                    v,
                    Duration::days(30).num_seconds(),
                )?;
            }

            // Send WebAuthn login notification
            notify::notify_background(
                &state.ctx,
                state.env.clone(),
                notify::NotifyEvent::WebAuthnLogin,
                notify::NotifyContext {
                    user_id: Some(user_id.clone()),
                    user_email: Some(user_email),
                    device_identifier: payload.device_identifier.clone(),
                    device_name: payload.device_name.clone(),
                    device_type: payload.device_type,
                    meta: notify::extract_request_meta(&headers),
                    ..Default::default()
                },
            );

            Ok(resp)
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}
