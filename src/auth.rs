use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::AppError;
use crate::router::AppState;
use serde_json::Value;
use worker::D1Database;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub nbf: usize,

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub amr: Vec<String>,
    pub security_stamp: Option<String>,
    pub device: Option<String>,
}

impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send>> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| {
                if auth_value.starts_with("Bearer ") {
                    Some(auth_value[7..].to_owned())
                } else {
                    None
                }
            })
            .or_else(|| {
                let raw = parts.headers.get(header::COOKIE)?.to_str().ok()?;
                for part in raw.split(';') {
                    let part = part.trim();
                    if let Some((k, v)) = part.split_once('=') {
                        if k.trim() == "bw_access_token" {
                            return Some(v.trim().to_string());
                        }
                    }
                }
                None
            });

        let result = match token {
            Some(token) => {
                let decoding_key = DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref());
                decode::<Claims>(&token, &decoding_key, &Validation::default())
                    .map(|td| td.claims)
                    .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))
            }
            None => Err(AppError::Unauthorized(
                "Missing or invalid token".to_string(),
            )),
        };

        Box::pin(std::future::ready(result))
    }
}

impl Claims {
    pub async fn verify_security_stamp(&self, db: &D1Database) -> Result<(), AppError> {
        let token_stamp = self
            .security_stamp
            .as_deref()
            .ok_or_else(|| AppError::Unauthorized("Missing security stamp".to_string()))?;

        let user_val: Option<Value> = db
            .prepare("SELECT security_stamp FROM users WHERE id = ?1")
            .bind(&[self.sub.clone().into()])
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        let Some(user_val) = user_val else {
            return Err(AppError::Unauthorized("User not found".to_string()));
        };

        let db_stamp = user_val
            .get("security_stamp")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if db_stamp != token_stamp {
            return Err(AppError::Unauthorized("Invalid security stamp".to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BasicJwtClaims {
    pub nbf: usize,
    pub exp: usize,
    pub iss: String,
    pub sub: String,
}

pub fn decode_delete(token: &str, jwt_secret: &str) -> Result<BasicJwtClaims, AppError> {
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
    decode::<BasicJwtClaims>(token, &decoding_key, &Validation::default())
        .map(|d| d.claims)
        .map_err(|_| AppError::Unauthorized("Invalid delete token".to_string()))
}
