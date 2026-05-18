use axum::http::{HeaderMap, StatusCode};
use axum::{Json, extract::State};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use worker::{Delay, query};

use crate::{
    auth::Claims,
    crypto::{self, KDF_TYPE_ARGON2ID, KDF_TYPE_PBKDF2},
    db,
    error::AppError,
    models::user::{KeyData, PreloginResponse, RegisterRequest, RegisterVerifyClaims, User},
    notify::{self, NotifyContext, NotifyEvent},
    router::AppState,
    two_factor,
};

const PROTECTED_ACTION_OTP_SIZE: u8 = 6;
const PROTECTED_ACTION_OTP_REQUEST_COOLDOWN_SECONDS: i64 = 30;

fn clean_password_hint(password_hint: Option<String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => {
            let ht = h.trim();
            if ht.is_empty() {
                None
            } else {
                Some(ht.to_string())
            }
        }
    }
}

fn validate_kdf(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> Result<(Option<i32>, Option<i32>), AppError> {
    crypto::validate_kdf_params(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
        .map_err(AppError::BadRequest)?;

    // 返回标准化的参数
    Ok(crypto::normalize_kdf_params(
        kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
    ))
}

fn normalize_kdf_for_response(
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    crypto::normalize_kdf_params(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KdfData {
    #[serde(rename = "kdfType", alias = "kdf")]
    pub kdf: i32,
    #[serde(rename = "iterations", alias = "kdfIterations")]
    pub kdf_iterations: i32,
    #[serde(rename = "memory", alias = "kdfMemory")]
    pub kdf_memory: Option<i32>,
    #[serde(rename = "parallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationData {
    #[serde(alias = "Salt", alias = "salt")]
    pub salt: String,
    #[serde(alias = "Kdf")]
    pub kdf: KdfData,
    #[serde(
        alias = "masterPasswordAuthenticationHash",
        alias = "MasterPasswordAuthenticationHash"
    )]
    pub master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockData {
    #[serde(alias = "Salt", alias = "salt")]
    pub salt: String,
    #[serde(alias = "Kdf")]
    pub kdf: KdfData,
    #[serde(alias = "masterKeyWrappedUserKey", alias = "MasterKeyWrappedUserKey")]
    pub master_key_wrapped_user_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfRequest {
    #[serde(alias = "newMasterPasswordHash", alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
    #[serde(
        alias = "authenticationData",
        alias = "authentication_data",
        alias = "AuthenticationData"
    )]
    pub authentication_data: AuthenticationData,
    #[serde(alias = "unlockData", alias = "unlock_data", alias = "UnlockData")]
    pub unlock_data: UnlockData,
    #[serde(alias = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfFlatRequest {
    #[serde(alias = "kdfType")]
    pub kdf: i32,
    #[serde(alias = "kdfIterations", alias = "iterations")]
    pub kdf_iterations: i32,
    #[serde(alias = "kdfMemory", alias = "memory")]
    pub kdf_memory: Option<i32>,
    #[serde(alias = "kdfParallelism", alias = "parallelism")]
    pub kdf_parallelism: Option<i32>,
    #[serde(alias = "masterPasswordHash", alias = "MasterPasswordHash")]
    pub master_password_hash: String,
    #[serde(alias = "newMasterPasswordHash", alias = "NewMasterPasswordHash")]
    pub new_master_password_hash: String,
    #[serde(alias = "Key")]
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ChangeKdfPayload {
    Vw(ChangeKdfRequest),
    Flat(ChangeKdfFlatRequest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeMasterPasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub master_password_hint: Option<String>,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub user_asymmetric_keys: Option<KeyData>,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_email: String,
    pub user_symmetric_key: String,
    #[serde(default)]
    pub kdf: Option<i32>,
    #[serde(default)]
    pub kdf_iterations: Option<i32>,
    #[serde(default)]
    pub kdf_memory: Option<i32>,
    #[serde(default)]
    pub kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarData {
    pub avatar_color: Option<String>,
}

#[worker::send]
pub async fn profile(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name.unwrap_or_default(),
        "email": user.email,
        "emailVerified": user.email_verified,
        "avatarColor": user.avatar_color,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn post_profile(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProfileData>,
) -> Result<Json<Value>, AppError> {
    let name = payload.name.unwrap_or_default();

    if name.len() > 50 {
        return Err(AppError::BadRequest(
            "The field Name must be a string with a maximum length of 50.".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[name.into(), now.into(), claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let response = profile(claims, State(state)).await?;
    Ok(response)
}

#[worker::send]
pub async fn put_avatar(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AvatarData>,
) -> Result<Json<Value>, AppError> {
    if let Some(color) = payload.avatar_color.as_deref()
        && color.len() != 7
    {
        return Err(AppError::BadRequest(
            "The field AvatarColor must be a HTML/Hex color code with a length of 7 characters"
                .to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();

    db.prepare("UPDATE users SET avatar_color = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            to_js_val(payload.avatar_color),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let response = profile(claims, State(state)).await?;
    Ok(response)
}

#[worker::send]
pub async fn post_security_stamp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();

    // Delete all devices for this user (matching vaultwarden behavior)
    db.prepare("DELETE FROM devices WHERE user_id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    db.prepare("UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            security_stamp.clone().into(),
            now.into(),
            claims.sub.clone().into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let two_factor_enabled = two_factor::is_authenticator_enabled(&db, &claims.sub).await?;
    let user: User = query!(&db, "SELECT * FROM users WHERE id = ?1", claims.sub)
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?
        .ok_or(AppError::NotFound("User not found".to_string()))?;

    Ok(Json(json!({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "emailVerified": user.email_verified,
        "avatarColor": user.avatar_color,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": user.master_password_hint,
        "culture": "en-US",
        "twoFactorEnabled": two_factor_enabled,
        "key": user.key,
        "privateKey": user.private_key,
        "securityStamp": user.security_stamp,
        "organizations": [],
        "object": "profile"
    })))
}

#[worker::send]
pub async fn revision_date(
    _claims: Claims,
    State(_state): State<Arc<AppState>>,
) -> Result<Json<i64>, AppError> {
    Ok(Json(chrono::Utc::now().timestamp_millis()))
}

#[worker::send]
pub async fn prelogin(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;
    let db = db::get_db(&state.env)?;

    let stmt = db.prepare(
        "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE email = ?1",
    );
    let query = stmt.bind(&[email.into()])?;
    let row: Option<Value> = query.first(None).await.map_err(|_| AppError::Database)?;
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) = match row {
        Some(v) => {
            let kdf_type = v
                .get("kdf_type")
                .and_then(|x| x.as_i64())
                .unwrap_or(KDF_TYPE_ARGON2ID as i64) as i32;
            let kdf_iterations = v
                .get("kdf_iterations")
                .and_then(|x| x.as_i64())
                .unwrap_or(3) as i32;
            let kdf_memory = v
                .get("kdf_memory")
                .and_then(|x| x.as_i64())
                .map(|v| v as i32)
                .or(Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB));
            let kdf_parallelism = v
                .get("kdf_parallelism")
                .and_then(|x| x.as_i64())
                .map(|v| v as i32)
                .or(Some(crypto::ARGON2ID_PARALLELISM_DEFAULT));

            let kdf_name = match kdf_type {
                crypto::KDF_TYPE_PBKDF2 => "PBKDF2",
                crypto::KDF_TYPE_ARGON2ID => "Argon2id",
                _ => "Unknown",
            };
            log::info!(
                "[KDF] prelogin response for email={}: kdf_type={} ({}), iterations={}, memory={:?}, parallelism={:?}",
                email,
                kdf_type,
                kdf_name,
                kdf_iterations,
                kdf_memory,
                kdf_parallelism
            );
            (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)
        }
        None => {
            log::info!(
                "[KDF] prelogin response for email={}: user not found, returning defaults (Argon2id)",
                email
            );
            (
                KDF_TYPE_ARGON2ID,
                3,
                Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB),
                Some(crypto::ARGON2ID_PARALLELISM_DEFAULT),
            )
        }
    };

    let (kdf_memory, kdf_parallelism) =
        normalize_kdf_for_response(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism);

    Ok(Json(PreloginResponse {
        kdf: kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
    }))
}

#[worker::send]
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    // Debug log
    log::info!(
        "Register payload: name={:?}, email={}",
        payload.name,
        payload.email
    );

    let db = db::get_db(&state.env)?;

    // Check if email is in ALLOWED_EMAILS list
    let allowed_emails = state
        .env
        .secret("ALLOWED_EMAILS")
        .map_err(|_| AppError::Internal)?;
    let allowed_emails = allowed_emails
        .as_ref()
        .as_string()
        .ok_or_else(|| AppError::Internal)?;
    if allowed_emails
        .split(",")
        .all(|email| email.trim().to_lowercase() != payload.email.to_lowercase())
    {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }
    let now = Utc::now().to_rfc3339();
    let email = payload.email.to_lowercase();

    let jwt_keys = state.jwt_keys.clone();
    let name_from_token = if let Some(token) = payload.email_verification_token.as_ref() {
        use jsonwebtoken::{DecodingKey, Validation, decode};
        let decoding_key = DecodingKey::from_secret(jwt_keys.access_secret.as_ref());
        match decode::<RegisterVerifyClaims>(token, &decoding_key, &Validation::default()) {
            Ok(token_data) if token_data.claims.sub == email => {
                token_data.claims.name.filter(|n| !n.trim().is_empty())
            }
            _ => None,
        }
    } else {
        None
    };

    let name = name_from_token
        .or_else(|| payload.name.filter(|n| !n.trim().is_empty()))
        .unwrap_or_else(|| email.clone());

    if payload.kdf != KDF_TYPE_ARGON2ID {
        return Err(AppError::BadRequest(
            "Registration requires Argon2id (kdfType=1)".to_string(),
        ));
    }

    let (kdf_memory, kdf_parallelism) = validate_kdf(
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )?;

    let password_salt = crypto::generate_salt();
    let master_password_hash = crypto::hash_password(
        &payload.master_password_hash,
        &password_salt,
        payload.kdf,
        payload.kdf_iterations,
        payload.kdf_memory,
        payload.kdf_parallelism,
    )
    .await
    .map_err(|_| AppError::Internal)?;
    let master_password_hint = clean_password_hint(payload.master_password_hint);

    let user = User {
        id: Uuid::new_v4().to_string(),
        name: Some(name),
        email,
        email_verified: true,
        avatar_color: None,
        master_password_hash,
        master_password_hint,
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        security_stamp: Uuid::new_v4().to_string(),
        password_salt: Some(password_salt),
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, email_verified, avatar_color, master_password_hash, master_password_hint, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, password_salt, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
         user.id,
         user.name,
         user.email,
         user.email_verified,
         user.avatar_color,
         user.master_password_hash,
         user.master_password_hint,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_type,
         user.kdf_iterations,
         user.kdf_memory,
         user.kdf_parallelism,
         user.security_stamp,
         user.password_salt,
         user.created_at,
         user.updated_at
    ).map_err(|_|{
        AppError::Database
    })?
    .run()
    .await
    .map_err(|_|{
        AppError::Database
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_master_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeMasterPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // 验证旧密码
    let password_valid = if let Some(salt) = &user.password_salt {
        crypto::verify_password(
            &payload.master_password_hash,
            salt,
            &user.master_password_hash,
            user.kdf_type,
            user.kdf_iterations,
            user.kdf_memory,
            user.kdf_parallelism,
        )
        .await
    } else {
        // 旧格式：直接比较哈希值
        constant_time_eq(
            user.master_password_hash.as_bytes(),
            payload.master_password_hash.as_bytes(),
        )
    };

    if !password_valid {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let master_password_hint = clean_password_hint(payload.master_password_hint.clone());
    let private_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.encrypted_private_key.clone())
        .unwrap_or_else(|| user.private_key.clone());
    let public_key = payload
        .user_asymmetric_keys
        .as_ref()
        .map(|k| k.public_key.clone())
        .unwrap_or_else(|| user.public_key.clone());
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory_in = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism_in = payload.kdf_parallelism.or(user.kdf_parallelism);
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let password_salt = crypto::generate_salt();
    let new_master_password_hash = crypto::hash_password(
        &payload.new_master_password_hash,
        &password_salt,
        kdf_type,
        kdf_iterations,
        kdf_memory_in,
        kdf_parallelism_in,
    )
    .await
    .map_err(|_| AppError::Internal)?;

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, master_password_hint = ?2, key = ?3, private_key = ?4, public_key = ?5, kdf_type = ?6, kdf_iterations = ?7, kdf_memory = ?8, kdf_parallelism = ?9, security_stamp = ?10, updated_at = ?11, password_salt = ?12 WHERE id = ?13",
    )
    .bind(&[
        new_master_password_hash.into(),
        to_js_val(master_password_hint),
        payload.user_symmetric_key.into(),
        private_key.into(),
        public_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        to_js_val(Some(password_salt)),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::PasswordChange,
        NotifyContext {
            user_id: Some(user.id),
            user_email: Some(user.email),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn change_email(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeEmailRequest>,
) -> Result<Json<Value>, AppError> {
    if payload.master_password_hash.is_empty() || payload.new_master_password_hash.is_empty() {
        return Err(AppError::BadRequest(
            "Missing masterPasswordHash".to_string(),
        ));
    }
    if payload.new_email.trim().is_empty() {
        return Err(AppError::BadRequest("Missing newEmail".to_string()));
    }
    if payload.user_symmetric_key.is_empty() {
        return Err(AppError::BadRequest("Missing userSymmetricKey".to_string()));
    }

    let new_email = payload.new_email.to_lowercase();

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    if let Some(salt) = &user.password_salt {
        let password_valid = crypto::verify_password(
            &payload.master_password_hash,
            salt,
            &user.master_password_hash,
            user.kdf_type,
            user.kdf_iterations,
            user.kdf_memory,
            user.kdf_parallelism,
        )
        .await;
        if !password_valid {
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }
    } else if !constant_time_eq(
        user.master_password_hash.as_bytes(),
        payload.master_password_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();
    let kdf_type = payload.kdf.unwrap_or(user.kdf_type);
    let kdf_iterations = payload.kdf_iterations.unwrap_or(user.kdf_iterations);
    let kdf_memory_in = payload.kdf_memory.or(user.kdf_memory);
    let kdf_parallelism_in = payload.kdf_parallelism.or(user.kdf_parallelism);
    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let password_salt = crypto::generate_salt();
    let new_master_password_hash = crypto::hash_password(
        &payload.new_master_password_hash,
        &password_salt,
        kdf_type,
        kdf_iterations,
        kdf_memory_in,
        kdf_parallelism_in,
    )
    .await
    .map_err(|_| AppError::Internal)?;

    db.prepare(
        "UPDATE users SET email = ?1, email_verified = ?2, master_password_hash = ?3, key = ?4, kdf_type = ?5, kdf_iterations = ?6, kdf_memory = ?7, kdf_parallelism = ?8, security_stamp = ?9, updated_at = ?10, password_salt = ?11 WHERE id = ?12",
    )
    .bind(&[
        new_email.clone().into(),
        true.into(),
        new_master_password_hash.into(),
        payload.user_symmetric_key.into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        to_js_val(Some(password_salt)),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("Email already in use".to_string())
        } else {
            AppError::Database
        }
    })?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::EmailChange,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(new_email),
            detail: Some("Action: Change Email".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_kdf(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChangeKdfPayload>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    let provided_old_hash = match &payload {
        ChangeKdfPayload::Vw(p) => &p.master_password_hash,
        ChangeKdfPayload::Flat(p) => &p.master_password_hash,
    };

    // 验证旧密码
    let password_valid = if let Some(salt) = &user.password_salt {
        crypto::verify_password(
            provided_old_hash,
            salt,
            &user.master_password_hash,
            user.kdf_type,
            user.kdf_iterations,
            user.kdf_memory,
            user.kdf_parallelism,
        )
        .await
    } else {
        constant_time_eq(
            user.master_password_hash.as_bytes(),
            provided_old_hash.as_bytes(),
        )
    };

    if !password_valid {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    let (
        new_master_password_hash,
        key,
        kdf_type,
        kdf_iterations,
        kdf_memory_in,
        kdf_parallelism_in,
    ) = match &payload {
        ChangeKdfPayload::Vw(p) => {
            let _ = (
                &p.authentication_data.master_password_authentication_hash,
                &p.unlock_data.master_key_wrapped_user_key,
            );

            if p.authentication_data.kdf != p.unlock_data.kdf {
                return Err(AppError::BadRequest(
                    "KDF settings must be equal for authentication and unlock".to_string(),
                ));
            }

            if !user.email.eq_ignore_ascii_case(&p.authentication_data.salt)
                || !user.email.eq_ignore_ascii_case(&p.unlock_data.salt)
            {
                return Err(AppError::BadRequest(
                    "Invalid master password salt".to_string(),
                ));
            }

            (
                &p.new_master_password_hash,
                &p.key,
                p.unlock_data.kdf.kdf,
                p.unlock_data.kdf.kdf_iterations,
                p.unlock_data.kdf.kdf_memory,
                p.unlock_data.kdf.kdf_parallelism,
            )
        }
        ChangeKdfPayload::Flat(p) => (
            &p.new_master_password_hash,
            &p.key,
            p.kdf,
            p.kdf_iterations,
            p.kdf_memory,
            p.kdf_parallelism,
        ),
    };

    let (kdf_memory, kdf_parallelism) =
        validate_kdf(kdf_type, kdf_iterations, kdf_memory_in, kdf_parallelism_in)?;

    let now = Utc::now().to_rfc3339();
    let security_stamp = Uuid::new_v4().to_string();

    let password_salt = crypto::generate_salt();
    let hashed_new_password = crypto::hash_password(
        new_master_password_hash,
        &password_salt,
        kdf_type,
        kdf_iterations,
        kdf_memory_in,
        kdf_parallelism_in,
    )
    .await
    .map_err(|_| AppError::Internal)?;

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, key = ?2, kdf_type = ?3, kdf_iterations = ?4, kdf_memory = ?5, kdf_parallelism = ?6, security_stamp = ?7, updated_at = ?8, password_salt = ?9 WHERE id = ?10",
    )
    .bind(&[
        hashed_new_password.into(),
        key.to_string().into(),
        kdf_type.into(),
        kdf_iterations.into(),
        to_js_val(kdf_memory),
        to_js_val(kdf_parallelism),
        security_stamp.into(),
        now.into(),
        to_js_val(Some(password_salt)),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::KdfChange,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(user.email),
            detail: Some("Action: Change KDF settings".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    Ok(Json(json!({})))
}

fn to_js_val<T: Into<JsValue>>(val: Option<T>) -> JsValue {
    val.map(Into::into).unwrap_or(JsValue::NULL)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHintRequest {
    pub email: String,
}

#[worker::send]
pub async fn password_hint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<PasswordHintRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if !notify::is_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "This server is not configured to provide password hints.".to_string(),
        ));
    }

    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::BadRequest("Missing email".to_string()));
    }

    let db = db::get_db(&state.env)?;
    let row: Option<Value> = db
        .prepare("SELECT master_password_hint FROM users WHERE email = ?1")
        .bind(&[email.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    const NO_HINT: &str = "当前未配置密码提示词";
    let (registered, detail) = match row {
        None => {
            let sleep_ms = rand::thread_rng().gen_range(900..=1100);
            Delay::from(std::time::Duration::from_millis(sleep_ms as u64)).await;
            (false, NO_HINT.to_string())
        }
        Some(row) => {
            let hint = row
                .get("master_password_hint")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let hint = clean_password_hint(hint);
            (true, hint.unwrap_or_else(|| NO_HINT.to_string()))
        }
    };

    notify::send_password_hint_background(
        &state.ctx,
        state.env.clone(),
        NotifyContext {
            user_email: Some(email),
            detail: Some(detail.clone()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );

    let status = if registered {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    Ok((status, Json(json!({ "hint": detail }))))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendVerificationEmailRequest {
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "receiveMarketingEmails")]
    pub _receive_marketing_emails: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOtpRequest {
    #[serde(rename = "OTP", alias = "otp")]
    pub otp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationRequest {
    #[serde(alias = "MasterPasswordHash")]
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[worker::send]
pub async fn request_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email verification is not configured on server".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    if let Some(existing) = two_factor::get_protected_action_otp(&db, &claims.sub).await? {
        let elapsed = Utc::now().timestamp().saturating_sub(existing.token_sent);
        if elapsed < PROTECTED_ACTION_OTP_REQUEST_COOLDOWN_SECONDS {
            return Err(AppError::BadRequest(format!(
                "Please wait {} seconds before requesting another code.",
                PROTECTED_ACTION_OTP_REQUEST_COOLDOWN_SECONDS - elapsed
            )));
        }
    }

    let user_row: Option<Value> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let email = user_row
        .and_then(|r| {
            r.get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let token = two_factor::generate_email_token(PROTECTED_ACTION_OTP_SIZE);
    let otp_data = two_factor::ProtectedActionOtpData::new(token.clone());
    let now = Utc::now().to_rfc3339();
    two_factor::upsert_protected_action_otp(&db, &claims.sub, &otp_data, &now).await?;

    notify::send_email_token_background(
        &state.ctx,
        state.env.clone(),
        email,
        token,
        notify::EmailType::TwoFactorLogin,
    );

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_otp(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<Json<Value>, AppError> {
    if !notify::is_email_webhook_configured(&state.env) {
        return Err(AppError::BadRequest(
            "Email verification is not configured on server".to_string(),
        ));
    }

    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    two_factor::validate_protected_action_otp(&db, &claims.sub, &payload.otp, true).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn verify_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let master_password_hash = payload
        .master_password_hash
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing masterPasswordHash".to_string()))?;

    verify_user_password(&db, &claims.sub, master_password_hash).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn send_verification_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendVerificationEmailRequest>,
) -> Result<Json<Value>, AppError> {
    use crate::models::user::RegisterVerifyClaims;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{EncodingKey, Header, encode};

    log::info!(
        "Send verification email: name={:?}, email={}",
        payload.name,
        payload.email
    );

    let jwt_keys = state.jwt_keys.clone();

    // Generate a token containing the name
    let now = Utc::now();
    let exp = (now + Duration::hours(24)).timestamp() as usize;

    let claims = RegisterVerifyClaims {
        sub: payload.email.to_lowercase(),
        name: payload.name.filter(|n| !n.trim().is_empty()),
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_keys.access_secret.as_ref()),
    )
    .map_err(|_| AppError::Internal)?;

    // Return token as JSON to skip email verification
    // This makes the client go directly to password entry instead of "check your email" screen
    Ok(Json(json!(token)))
}

/// KDF 升级函数（参照 vaultwarden 实现）
/// 当用户的 KDF 参数低于推荐值时，自动升级
pub async fn kdf_upgrade(
    db: &worker::D1Database,
    user: &mut User,
    password_hash: &str,
) -> Result<(), AppError> {
    let kdf_name = match user.kdf_type {
        crypto::KDF_TYPE_PBKDF2 => "PBKDF2",
        crypto::KDF_TYPE_ARGON2ID => "Argon2id",
        _ => "Unknown",
    };
    log::info!(
        "[KDF] kdf_upgrade check: user_id={}, kdf_type={} ({}), iterations={}, memory={:?}, parallelism={:?}",
        user.id,
        user.kdf_type,
        kdf_name,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism
    );

    let needs_upgrade = match user.kdf_type {
        KDF_TYPE_PBKDF2 => user.kdf_iterations < crypto::PBKDF2_ITERATIONS_DEFAULT,
        KDF_TYPE_ARGON2ID => {
            user.kdf_iterations < crypto::ARGON2ID_ITERATIONS_DEFAULT
                || user.kdf_memory.unwrap_or(0) < crypto::ARGON2ID_MEMORY_DEFAULT_MB
                || user.kdf_parallelism.unwrap_or(0) < crypto::ARGON2ID_PARALLELISM_DEFAULT
        }
        _ => false,
    };

    if !needs_upgrade {
        log::info!("[KDF] kdf_upgrade: no upgrade needed for user {}", user.id);
        return Ok(());
    }

    log::info!(
        "[KDF] kdf_upgrade: upgrading KDF for user {} from {} to recommended values",
        user.id,
        kdf_name
    );

    // 确定升级后的参数
    let (new_iterations, new_memory, new_parallelism) = match user.kdf_type {
        KDF_TYPE_PBKDF2 => (crypto::PBKDF2_ITERATIONS_DEFAULT, None, None),
        KDF_TYPE_ARGON2ID => (
            crypto::ARGON2ID_ITERATIONS_DEFAULT.max(user.kdf_iterations),
            Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB.max(user.kdf_memory.unwrap_or(0))),
            Some(crypto::ARGON2ID_PARALLELISM_DEFAULT.max(user.kdf_parallelism.unwrap_or(0))),
        ),
        _ => return Ok(()),
    };

    // 重新哈希密码
    let password_salt = match &user.password_salt {
        Some(salt) => salt.clone(),
        None => return Ok(()), // 没有 salt 无法升级
    };

    let new_hash = crypto::hash_password(
        password_hash,
        &password_salt,
        user.kdf_type,
        new_iterations,
        new_memory,
        new_parallelism,
    )
    .await
    .map_err(|_| AppError::Internal)?;

    // 更新数据库
    let now = Utc::now().to_rfc3339();
    db.prepare(
        "UPDATE users SET master_password_hash = ?1, kdf_iterations = ?2, kdf_memory = ?3, kdf_parallelism = ?4, updated_at = ?5 WHERE id = ?6",
    )
    .bind(&[
        new_hash.clone().into(),
        new_iterations.into(),
        to_js_val(new_memory),
        to_js_val(new_parallelism),
        now.into(),
        user.id.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // 更新内存中的用户对象
    user.master_password_hash = new_hash;
    user.kdf_iterations = new_iterations;
    user.kdf_memory = new_memory;
    user.kdf_parallelism = new_parallelism;

    log::info!(
        "[KDF] kdf_upgrade SUCCESS: user_id={}, kdf_type={} ({}), new_iterations={}, new_memory={:?}, new_parallelism={:?}",
        user.id,
        user.kdf_type,
        kdf_name,
        user.kdf_iterations,
        user.kdf_memory,
        user.kdf_parallelism
    );

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecoverData {
    pub email: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecoverTokenData {
    pub user_id: String,
    pub token: String,
}

#[worker::send]
pub async fn post_delete_recover(
    State(state): State<Arc<AppState>>,
    Json(data): Json<DeleteRecoverData>,
) -> Result<Json<Value>, AppError> {
    if notify::is_email_webhook_configured(&state.env) {
        let email = data.email.trim().to_lowercase();
        if !email.is_empty() {
            let db = db::get_db(&state.env)?;
            let user: Option<Value> = db
                .prepare("SELECT id FROM users WHERE email = ?1")
                .bind(&[email.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Database)?;

            if let Some(user) = user
                && let Some(user_id) = user.get("id").and_then(|v| v.as_str())
            {
                log::info!("Delete recover requested for user {user_id}");
            }
        }

        Ok(Json(json!({})))
    } else {
        Err(AppError::BadRequest(
            "Please contact the administrator to delete your account".to_string(),
        ))
    }
}

#[worker::send]
pub async fn post_delete_recover_token(
    State(state): State<Arc<AppState>>,
    Json(data): Json<DeleteRecoverTokenData>,
) -> Result<Json<Value>, AppError> {
    let jwt_keys = state.jwt_keys.clone();
    let claims = crate::auth::decode_delete(&data.token, &jwt_keys.access_secret)?;

    if claims.sub != data.user_id {
        return Err(AppError::Unauthorized("Invalid claim".to_string()));
    }

    let db = db::get_db(&state.env)?;
    let user: Option<Value> = db
        .prepare("SELECT id FROM users WHERE id = ?1")
        .bind(&[data.user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if user.is_none() {
        return Err(AppError::NotFound("User doesn't exist".to_string()));
    }

    cascade_delete_user_data(&db, &data.user_id).await?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_delete_account(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    validate_password_or_otp(&db, &claims.sub, &payload).await?;
    cascade_delete_user_data(&db, &claims.sub).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    post_delete_account(claims, State(state), Json(payload)).await
}

async fn validate_password_or_otp(
    db: &worker::D1Database,
    user_id: &str,
    payload: &SecretVerificationRequest,
) -> Result<(), AppError> {
    match (
        payload.master_password_hash.as_deref(),
        payload.otp.as_deref(),
    ) {
        (Some(master_password_hash), None) => {
            verify_user_password(db, user_id, master_password_hash).await
        }
        (None, Some(otp)) => {
            two_factor::validate_protected_action_otp(db, user_id, otp, true).await
        }
        _ => Err(AppError::BadRequest("No validation provided".to_string())),
    }
}

async fn verify_user_password(
    db: &worker::D1Database,
    user_id: &str,
    password_hash: &str,
) -> Result<(), AppError> {
    let user_row: Option<Value> = db
        .prepare("SELECT master_password_hash, password_salt, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = user_row else {
        return Err(AppError::NotFound("User not found".to_string()));
    };

    let stored_hash = row
        .get("master_password_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let password_salt = row.get("password_salt").and_then(|v| v.as_str());
    let kdf_type: i32 = row
        .get("kdf_type")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(0);
    let kdf_iterations: i32 = row
        .get("kdf_iterations")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .unwrap_or(600_000);
    let kdf_memory: Option<i32> = row
        .get("kdf_memory")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let kdf_parallelism: Option<i32> = row
        .get("kdf_parallelism")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    let valid = if let Some(salt) = password_salt {
        crypto::verify_password(
            password_hash,
            salt,
            stored_hash,
            kdf_type,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
        )
        .await
    } else {
        constant_time_eq(stored_hash.as_bytes(), password_hash.as_bytes())
    };

    if !valid {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    Ok(())
}

async fn cascade_delete_user_data(db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
    db.prepare("DELETE FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .run()
        .await
        .map_err(|e| {
            log::error!("Failed to cascade delete user {user_id}: {e:?}");
            AppError::Database
        })?;

    log::info!("User {user_id} and all associated data deleted");
    Ok(())
}

#[worker::send]
pub async fn get_tasks(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    Ok(Json(json!({
        "data": [],
        "object": "list"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_password_hint_none() {
        assert_eq!(clean_password_hint(None), None);
    }

    #[test]
    fn clean_password_hint_blank_to_none() {
        assert_eq!(clean_password_hint(Some("   ".to_string())), None);
    }

    #[test]
    fn clean_password_hint_trims() {
        assert_eq!(
            clean_password_hint(Some("  hint  ".to_string())),
            Some("hint".to_string())
        );
    }

    #[test]
    fn validate_kdf_pbkdf2_ok() {
        let (m, p) = validate_kdf(crypto::KDF_TYPE_PBKDF2, 600_000, Some(64), Some(4)).unwrap();
        assert_eq!(m, None);
        assert_eq!(p, None);
    }

    #[test]
    fn validate_kdf_pbkdf2_iterations_too_low() {
        assert!(validate_kdf(crypto::KDF_TYPE_PBKDF2, 99_999, None, None).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_requires_params() {
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, None, Some(4)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), None).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_range_checks() {
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(14), Some(4)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(1025), Some(4)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), Some(0)).is_err());
        assert!(validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), Some(17)).is_err());
    }

    #[test]
    fn validate_kdf_argon2id_ok() {
        let (m, p) = validate_kdf(crypto::KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)).unwrap();
        assert_eq!(m, Some(64));
        assert_eq!(p, Some(4));
    }

    #[test]
    fn normalize_kdf_for_response_defaults_argon2id() {
        let (m, p) = normalize_kdf_for_response(crypto::KDF_TYPE_ARGON2ID, 3, None, None);
        assert_eq!(m, Some(crypto::ARGON2ID_MEMORY_DEFAULT_MB));
        assert_eq!(p, Some(crypto::ARGON2ID_PARALLELISM_DEFAULT));
    }
}
