use axum::http::HeaderMap;
use axum::{Json, extract::State};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
use worker::{D1Database, query};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::logging::targets;
use crate::models::{
    archive,
    cipher::{
        Cipher, CipherDBModel, CipherData, CipherRequestData, CipherRequestFlat,
        CreateCipherRequest,
    },
};
use crate::notify::{self, NotifyContext, NotifyEvent};
use crate::router::AppState;
use axum::extract::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CipherIdsRequest {
    ids: Vec<String>,
}

fn now_string() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn normalize_archived_date(archived_date: Option<String>) -> Option<String> {
    archived_date.and_then(|d| {
        let d = d.trim().to_string();
        if d.is_empty() { None } else { Some(d) }
    })
}

async fn get_cipher_dbmodel_from_db(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::models::cipher::CipherDBModel, AppError> {
    archive::ensure_table(db).await?;

    query!(
        db,
        "SELECT ciphers.*, archives.archived_at AS archived_at
         FROM ciphers
         LEFT JOIN archives ON archives.cipher_id = ciphers.id AND archives.user_id = ?3
         WHERE ciphers.id = ?1 AND ciphers.user_id = ?2",
        cipher_id,
        user_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))
}

async fn get_cipher_dbmodel(
    state: &Arc<AppState>,
    cipher_id: &str,
    user_id: &str,
) -> Result<crate::models::cipher::CipherDBModel, AppError> {
    let db = db::get_db(&state.env)?;
    get_cipher_dbmodel_from_db(&db, cipher_id, user_id).await
}

async fn create_cipher_inner(
    claims: Claims,
    state: &Arc<AppState>,
    cipher_data_req: CipherRequestData,
    collection_ids: Vec<String>,
) -> Result<Cipher, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;
    let now = now_string();
    let archived_at = normalize_archived_date(cipher_data_req.archived_date.clone());

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        archived_at: archived_at.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipherDetails".to_string(),
        organization_use_totp: true,
        edit: true,
        view_password: true,
        collection_ids: if collection_ids.is_empty() {
            None
        } else {
            Some(collection_ids)
        },
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    if let Some(archived_at) = &archived_at {
        archive::save(&db, &claims.sub, &cipher.id, archived_at).await?;
    }

    Ok(cipher)
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let meta = notify::extract_request_meta(&headers);

    let cipher =
        create_cipher_inner(claims, &state, payload.cipher, payload.collection_ids).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherCreate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn post_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherRequestFlat>,
) -> Result<Json<Cipher>, AppError> {
    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let meta = notify::extract_request_meta(&headers);

    let cipher =
        create_cipher_inner(claims, &state, payload.cipher, payload.collection_ids).await?;

    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherCreate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;
    let now = now_string();

    let existing_cipher = get_cipher_dbmodel_from_db(&db, &id, &claims.sub).await?;

    let cipher_data_req = payload;
    let requested_archived_at = normalize_archived_date(cipher_data_req.archived_date.clone());
    let archived_at = requested_archived_at
        .clone()
        .or_else(|| existing_cipher.archived_at.clone());

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: existing_cipher.deleted_at,
        archived_at: archived_at.clone(),
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipherDetails".to_string(),
        organization_use_totp: true,
        edit: true,
        view_password: true,
        collection_ids: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    if let Some(archived_at) = &requested_archived_at {
        archive::save(&db, &claims.sub, &id, archived_at).await?;
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(cipher.id.clone()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
        now,
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = Some(now.clone());
    cipher.updated_at = now;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.deleted_at = None;
    cipher.updated_at = now;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Restore Cipher".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

async fn archive_cipher_record(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    archived_at: String,
) -> Result<Cipher, AppError> {
    let existing = get_cipher_dbmodel_from_db(db, cipher_id, user_id).await?;

    archive::save(db, user_id, cipher_id, &archived_at).await?;
    query!(
        db,
        "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        archived_at,
        cipher_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.archived_at = Some(archived_at.clone());
    cipher.updated_at = archived_at;
    Ok(cipher)
}

async fn unarchive_cipher_record(
    db: &D1Database,
    cipher_id: &str,
    user_id: &str,
    updated_at: String,
) -> Result<Cipher, AppError> {
    let existing = get_cipher_dbmodel_from_db(db, cipher_id, user_id).await?;

    archive::delete(db, user_id, cipher_id).await?;
    query!(
        db,
        "UPDATE ciphers SET updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        updated_at,
        cipher_id,
        user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.archived_at = None;
    cipher.updated_at = updated_at;
    Ok(cipher)
}

#[worker::send]
pub async fn archive_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let cipher = archive_cipher_record(&db, &id, &claims.sub, now_string()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Archive Cipher".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn unarchive_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let cipher = unarchive_cipher_record(&db, &id, &claims.sub, now_string()).await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            detail: Some("Action: Unarchive Cipher".to_string()),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(cipher))
}

#[worker::send]
pub async fn archive_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let count = payload.ids.len();
    let mut ciphers = Vec::with_capacity(count);
    for id in payload.ids {
        let cipher = archive_cipher_record(&db, &id, &user_id, now_string()).await?;
        ciphers.push(json!(cipher));
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            detail: Some(format!("Action: Batch Archive ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn unarchive_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let user_id = claims.sub.clone();
    let user_email = Some(claims.email.clone());
    let count = payload.ids.len();
    let mut ciphers = Vec::with_capacity(count);
    for id in payload.ids {
        let cipher = unarchive_cipher_record(&db, &id, &user_id, now_string()).await?;
        ciphers.push(json!(cipher));
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(user_id),
            user_email,
            detail: Some(format!("Action: Batch Unarchive ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::delete(&db, &claims.sub, &id).await?;

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            cipher_id: Some(id),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_cipher_post(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    hard_delete_cipher(claims, State(state), headers, Path(id)).await
}

#[worker::send]
pub async fn soft_delete_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let count = payload.ids.len();
    for id in payload.ids {
        query!(
            &db,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4",
            now,
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Soft Delete ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn restore_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let count = payload.ids.len();
    for id in payload.ids {
        query!(
            &db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Restore ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let count = payload.ids.len();
    for id in payload.ids {
        archive::delete(&db, &claims.sub, &id).await?;
        query!(
            &db,
            "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
    }

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherDelete,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Hard Delete ({} items)", count)),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn hard_delete_ciphers_delete(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CipherIdsRequest>,
) -> Result<Json<()>, AppError> {
    hard_delete_ciphers(claims, State(state), headers, Json(payload)).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveCipherData {
    #[serde(
        default,
        deserialize_with = "crate::models::cipher::deserialize_optional_nonempty_string"
    )]
    pub folder_id: Option<String>,
    pub ids: Vec<String>,
}

#[worker::send]
pub async fn move_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<MoveCipherData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    if let Some(folder_id) = &payload.folder_id {
        let folder_exists: Option<Value> = db
            .prepare("SELECT id FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        if folder_exists.is_none() {
            return Err(AppError::NotFound("Folder not found".to_string()));
        }
    }

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let placeholders = payload
        .ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "UPDATE ciphers SET folder_id = ?1, updated_at = ?2 WHERE user_id = ?3 AND id IN ({})",
        placeholders
    );

    let mut params = vec![
        payload
            .folder_id
            .clone()
            .map(|s| s.into())
            .unwrap_or_else(|| worker::wasm_bindgen::JsValue::NULL),
        now.into(),
        claims.sub.clone().into(),
    ];
    for id in &payload.ids {
        params.push(id.clone().into());
    }

    db.prepare(&sql)
        .bind(&params)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let meta = notify::extract_request_meta(&headers);
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::CipherUpdate,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some(format!("Action: Batch Move ({} items)", payload.ids.len())),
            meta,
            ..Default::default()
        },
    );

    Ok(Json(()))
}

#[worker::send]
pub async fn move_ciphers_put(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<MoveCipherData>,
) -> Result<Json<()>, AppError> {
    move_ciphers(claims, State(state), headers, Json(payload)).await
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    #[serde(
        default,
        deserialize_with = "crate::models::cipher::deserialize_optional_nonempty_string"
    )]
    pub folder_id: Option<String>,
    pub favorite: bool,
}

#[worker::send]
pub async fn get_ciphers(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;

    let cipher_rows: Vec<Value> = db
        .prepare(
            "SELECT ciphers.*, archives.archived_at AS archived_at
             FROM ciphers
             LEFT JOIN archives ON archives.cipher_id = ciphers.id AND archives.user_id = ?2
             WHERE ciphers.user_id = ?1",
        )
        .bind(&[claims.sub.clone().into(), claims.sub.clone().into()])?
        .all()
        .await?
        .results()?;

    let ciphers: Vec<Cipher> = cipher_rows
        .into_iter()
        .filter_map(|row| match serde_json::from_value::<CipherDBModel>(row) {
            Ok(db_model) => Some(db_model.into()),
            Err(err) => {
                log::warn!(target: targets::DB, "Cannot parse cipher: {err:?}");
                None
            }
        })
        .collect();

    Ok(Json(json!({
        "data": ciphers,
        "object": "list",
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn get_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;

    let cipher: CipherDBModel = db
        .prepare(
            "SELECT ciphers.*, archives.archived_at AS archived_at
             FROM ciphers
             LEFT JOIN archives ON archives.cipher_id = ciphers.id AND archives.user_id = ?3
             WHERE ciphers.id = ?1 AND ciphers.user_id = ?2",
        )
        .bind(&[
            id.clone().into(),
            claims.sub.clone().into(),
            claims.sub.clone().into(),
        ])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("Cipher not found".to_string()))?;

    Ok(Json(cipher.into()))
}

#[worker::send]
pub async fn get_cipher_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    get_cipher(claims, State(state), Path(id)).await
}

#[worker::send]
pub async fn post_cipher(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    update_cipher(claims, State(state), headers, Path(id), Json(payload)).await
}

#[worker::send]
pub async fn post_cipher_partial(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    put_cipher_partial(claims, State(state), Path(id), Json(data)).await
}

#[worker::send]
pub async fn put_cipher_partial(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<PartialCipherData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    archive::ensure_table(&db).await?;

    let now = now_string();

    let existing = get_cipher_dbmodel(&state, &id, &claims.sub).await?;

    if let Some(ref folder_id) = data.folder_id {
        let folder: Option<crate::models::folder::Folder> = db
            .prepare("SELECT * FROM folders WHERE id = ?1 AND user_id = ?2")
            .bind(&[folder_id.clone().into(), claims.sub.clone().into()])?
            .first(None)
            .await?;
        if folder.is_none() {
            return Err(AppError::BadRequest(
                "Folder does not exist or belongs to another user".to_string(),
            ));
        }
    }

    query!(
        &db,
        "UPDATE ciphers SET folder_id = ?1, favorite = ?2, updated_at = ?3 WHERE id = ?4 AND user_id = ?5",
        data.folder_id,
        data.favorite as i32,
        now,
        id,
        claims.sub,
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let mut cipher: Cipher = existing.into();
    cipher.folder_id = data.folder_id;
    cipher.favorite = data.favorite;
    cipher.updated_at = now;

    Ok(Json(cipher))
}
