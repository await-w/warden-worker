use base64::{Engine as _, engine::general_purpose};
use constant_time_eq::constant_time_eq;
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;

// KDF 类型常量
pub const KDF_TYPE_PBKDF2: i32 = 0;
pub const KDF_TYPE_ARGON2ID: i32 = 1;

// 默认参数（与 vaultwarden 一致）
pub const PBKDF2_ITERATIONS_DEFAULT: i32 = 600_000;
pub const PBKDF2_ITERATIONS_MIN: i32 = 100_000;
pub const ARGON2ID_MEMORY_DEFAULT_MB: i32 = 64;
pub const ARGON2ID_PARALLELISM_DEFAULT: i32 = 4;
pub const ARGON2ID_ITERATIONS_DEFAULT: i32 = 3;

async fn get_subtle_crypto() -> Result<web_sys::SubtleCrypto, String> {
    let global = js_sys::global();
    let crypto_val = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|e| format!("Failed to get crypto: {:?}", e))?;
    let crypto = crypto_val
        .dyn_into::<web_sys::Crypto>()
        .map_err(|_| "Failed to cast to Crypto".to_string())?;

    Ok(crypto.subtle())
}

/// 使用 PBKDF2-HMAC-SHA256 哈希密码
///
/// # 参数
/// * `password` - 密码字符串
/// * `salt` - Base64 编码的盐值
/// * `iterations` - 迭代次数
///
/// # 返回
/// Base64 编码的哈希值
pub async fn hash_password_pbkdf2(
    password: &str,
    salt: &str,
    iterations: i32,
) -> Result<String, String> {
    let salt_bytes = general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Invalid salt: {}", e))?;

    let subtle = get_subtle_crypto().await?;

    // Encode password to bytes
    let enc =
        web_sys::TextEncoder::new().map_err(|_| "Failed to create TextEncoder".to_string())?;
    let password_vec = enc.encode_with_input(password);
    let password_bytes = Uint8Array::from(&password_vec[..]);

    // Import password as key
    let key_usages = Array::of1(&JsValue::from_str("deriveBits"));

    let key_promise = subtle
        .import_key_with_str("raw", &password_bytes, "PBKDF2", false, &key_usages)
        .map_err(|e| format!("ImportKey failed: {:?}", e))?;

    let key_val = JsFuture::from(key_promise)
        .await
        .map_err(|e| format!("ImportKey promise failed: {:?}", e))?;
    let key = key_val
        .dyn_into::<CryptoKey>()
        .map_err(|_| "ImportKey result is not a CryptoKey".to_string())?;

    // Derive bits
    let params = Object::new();
    Reflect::set(&params, &"name".into(), &"PBKDF2".into())
        .map_err(|e| format!("Failed to set params name: {:?}", e))?;
    Reflect::set(&params, &"salt".into(), &Uint8Array::from(&salt_bytes[..]))
        .map_err(|e| format!("Failed to set params salt: {:?}", e))?;
    Reflect::set(
        &params,
        &"iterations".into(),
        &JsValue::from(iterations as u32),
    )
    .map_err(|e| format!("Failed to set params iterations: {:?}", e))?;
    Reflect::set(&params, &"hash".into(), &"SHA-256".into())
        .map_err(|e| format!("Failed to set params hash: {:?}", e))?;

    let derive_promise = subtle
        .derive_bits_with_object(
            &params, &key, 256, // 256 bits
        )
        .map_err(|e| format!("DeriveBits failed: {:?}", e))?;

    let derived_bits_val = JsFuture::from(derive_promise)
        .await
        .map_err(|e| format!("DeriveBits promise failed: {:?}", e))?;

    let derived_array = Uint8Array::new(&derived_bits_val);
    let mut derived_vec = vec![0u8; derived_array.length() as usize];
    derived_array.copy_to(&mut derived_vec);

    Ok(general_purpose::STANDARD.encode(&derived_vec))
}

/// 使用 Argon2id 哈希密码
///
/// # 参数
/// * `password` - 密码字符串
/// * `salt` - Base64 编码的盐值
/// * `iterations` - 迭代次数 (time cost)
/// * `memory` - 内存使用量 (MB)
/// * `parallelism` - 并行度
///
/// # 返回
/// Base64 编码的哈希值 (PHC 格式)
pub fn hash_password_argon2id(
    password: &str,
    salt: &str,
    iterations: i32,
    memory: i32,
    parallelism: i32,
) -> Result<String, String> {
    use argon2::{
        Argon2, Params,
        password_hash::{PasswordHasher, SaltString},
    };

    // 解码 salt
    let salt_bytes = general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Invalid salt: {}", e))?;

    // 转换为 SaltString (需要 Base64 编码)
    let salt_string = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| format!("Failed to encode salt: {:?}", e))?;

    // 构建 Argon2 参数
    let params = Params::new(
        (memory as u32) * 1024, // 转换为 KB
        iterations as u32,
        parallelism as u32,
        Some(32), // output length
    )
    .map_err(|e| format!("Invalid Argon2 params: {:?}", e))?;

    // 创建 Argon2id 实例
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // 哈希密码
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| format!("Argon2 hash failed: {:?}", e))?;

    // 返回 PHC 格式字符串 ($argon2id$v=19$m=65540,t=3,p=4$...)
    Ok(password_hash.to_string())
}

/// 根据 KDF 类型哈希密码
///
/// # 参数
/// * `password` - 密码字符串
/// * `salt` - Base64 编码的盐值
/// * `kdf_type` - KDF 类型 (0=PBKDF2, 1=Argon2id)
/// * `iterations` - 迭代次数
/// * `memory` - 内存使用量 (Argon2id 专用，MB)
/// * `parallelism` - 并行度 (Argon2id 专用)
///
/// # 返回
/// Base64 编码的哈希值 (PBKDF2) 或 PHC 格式字符串 (Argon2id)
pub async fn hash_password(
    password: &str,
    salt: &str,
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> Result<String, String> {
    let kdf_name = match kdf_type {
        KDF_TYPE_PBKDF2 => "PBKDF2",
        KDF_TYPE_ARGON2ID => "Argon2id",
        _ => "Unknown",
    };
    log::info!(
        "[KDF] hash_password: type={} ({}), iterations={}, memory={:?}, parallelism={:?}",
        kdf_type,
        kdf_name,
        iterations,
        memory,
        parallelism
    );

    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            log::debug!("[KDF] Hashing with PBKDF2, {} iterations", iterations);
            hash_password_pbkdf2(password, salt, iterations).await
        }
        KDF_TYPE_ARGON2ID => {
            let memory =
                memory.ok_or_else(|| "Missing memory parameter for Argon2id".to_string())?;
            let parallelism = parallelism
                .ok_or_else(|| "Missing parallelism parameter for Argon2id".to_string())?;
            log::debug!(
                "[KDF] Hashing with Argon2id, iterations={}, memory={}MB, parallelism={}",
                iterations,
                memory,
                parallelism
            );
            hash_password_argon2id(password, salt, iterations, memory, parallelism)
        }
        _ => {
            log::error!("[KDF] Invalid KDF type: {}", kdf_type);
            Err(format!("Invalid KDF type: {}", kdf_type))
        }
    }
}

/// 验证 PBKDF2 密码
pub async fn verify_password_pbkdf2(
    password: &str,
    salt: &str,
    hash: &str,
    iterations: i32,
) -> bool {
    match hash_password_pbkdf2(password, salt, iterations).await {
        Ok(new_hash) => constant_time_eq(new_hash.as_bytes(), hash.as_bytes()),
        Err(_) => false,
    }
}

/// 验证 Argon2id 密码 (PHC 格式)
pub fn verify_password_argon2id(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, password_hash::PasswordVerifier};

    // 解析 PHC 格式哈希
    let parsed_hash = match argon2::password_hash::PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("Failed to parse Argon2 hash: {:?}", e);
            return false;
        }
    };

    // 验证密码
    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// 根据 KDF 类型验证密码
///
/// # 参数
/// * `password` - 密码字符串
/// * `salt` - Base64 编码的盐值 (PBKDF2 需要)
/// * `hash` - 存储的哈希值
/// * `kdf_type` - KDF 类型 (0=PBKDF2, 1=Argon2id)
/// * `iterations` - 迭代次数
/// * `memory` - 内存使用量 (Argon2id 专用)
/// * `parallelism` - 并行度 (Argon2id 专用)
///
/// # 返回
/// 密码是否匹配
pub async fn verify_password(
    password: &str,
    salt: &str,
    hash: &str,
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> bool {
    let kdf_name = match kdf_type {
        KDF_TYPE_PBKDF2 => "PBKDF2",
        KDF_TYPE_ARGON2ID => "Argon2id",
        _ => "Unknown",
    };
    log::info!(
        "[KDF] verify_password: type={} ({}), iterations={}, memory={:?}, parallelism={:?}",
        kdf_type,
        kdf_name,
        iterations,
        memory,
        parallelism
    );

    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            log::debug!(
                "[KDF] Using PBKDF2 verification with {} iterations",
                iterations
            );
            verify_password_pbkdf2(password, salt, hash, iterations).await
        }
        KDF_TYPE_ARGON2ID => {
            log::debug!("[KDF] Using Argon2id verification (PHC format)");
            let _ = (salt, memory, parallelism);
            verify_password_argon2id(password, hash)
        }
        _ => {
            log::warn!("[KDF] Unknown KDF type: {}", kdf_type);
            false
        }
    }
}

/// 生成随机盐值 (32 字节)
pub fn generate_salt() -> String {
    let mut salt = [0u8; 32];
    let global = js_sys::global();

    if let Ok(crypto_val) = js_sys::Reflect::get(&global, &JsValue::from_str("crypto")) {
        if let Ok(crypto) = crypto_val.dyn_into::<web_sys::Crypto>() {
            let array = Uint8Array::new_with_length(32);
            if crypto
                .get_random_values_with_array_buffer_view(&array)
                .is_ok()
            {
                let mut vec = vec![0u8; 32];
                array.copy_to(&mut vec);
                return general_purpose::STANDARD.encode(&vec);
            }
        }
    }

    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    general_purpose::STANDARD.encode(salt)
}

/// 验证 KDF 参数
pub fn validate_kdf_params(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> Result<(), String> {
    match kdf_type {
        KDF_TYPE_PBKDF2 => {
            if iterations < PBKDF2_ITERATIONS_MIN {
                return Err(format!(
                    "PBKDF2 iterations must be at least {}",
                    PBKDF2_ITERATIONS_MIN
                ));
            }
            Ok(())
        }
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return Err("Argon2id iterations must be at least 1".to_string());
            }
            let memory =
                memory.ok_or_else(|| "Missing memory parameter for Argon2id".to_string())?;
            let parallelism = parallelism
                .ok_or_else(|| "Missing parallelism parameter for Argon2id".to_string())?;

            if !(15..=1024).contains(&memory) {
                return Err("Argon2id memory must be between 15 MB and 1024 MB".to_string());
            }
            if !(1..=16).contains(&parallelism) {
                return Err("Argon2id parallelism must be between 1 and 16".to_string());
            }
            Ok(())
        }
        _ => Err(format!("Invalid KDF type: {}", kdf_type)),
    }
}

/// 标准化 KDF 参数（用于响应）
pub fn normalize_kdf_params(
    kdf_type: i32,
    iterations: i32,
    memory: Option<i32>,
    parallelism: Option<i32>,
) -> (Option<i32>, Option<i32>) {
    match kdf_type {
        KDF_TYPE_PBKDF2 => (None, None),
        KDF_TYPE_ARGON2ID => {
            if iterations < 1 {
                return (
                    Some(ARGON2ID_MEMORY_DEFAULT_MB),
                    Some(ARGON2ID_PARALLELISM_DEFAULT),
                );
            }
            let mem = memory.unwrap_or(ARGON2ID_MEMORY_DEFAULT_MB);
            let par = parallelism.unwrap_or(ARGON2ID_PARALLELISM_DEFAULT);
            let mem = if (15..=1024).contains(&mem) {
                mem
            } else {
                ARGON2ID_MEMORY_DEFAULT_MB
            };
            let par = if (1..=16).contains(&par) {
                par
            } else {
                ARGON2ID_PARALLELISM_DEFAULT
            };
            (Some(mem), Some(par))
        }
        _ => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_kdf_params_pbkdf2_valid() {
        assert!(validate_kdf_params(KDF_TYPE_PBKDF2, 600_000, None, None).is_ok());
    }

    #[test]
    fn test_validate_kdf_params_pbkdf2_invalid() {
        assert!(validate_kdf_params(KDF_TYPE_PBKDF2, 50_000, None, None).is_err());
    }

    #[test]
    fn test_validate_kdf_params_argon2id_valid() {
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, Some(64), Some(4)).is_ok());
    }

    #[test]
    fn test_validate_kdf_params_argon2id_invalid_memory() {
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, Some(10), Some(4)).is_err());
    }

    #[test]
    fn test_validate_kdf_params_argon2id_missing_params() {
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, None, Some(4)).is_err());
        assert!(validate_kdf_params(KDF_TYPE_ARGON2ID, 3, Some(64), None).is_err());
    }

    #[test]
    fn test_normalize_kdf_params_pbkdf2() {
        let (mem, par) = normalize_kdf_params(KDF_TYPE_PBKDF2, 600_000, None, None);
        assert_eq!(mem, None);
        assert_eq!(par, None);
    }

    #[test]
    fn test_normalize_kdf_params_argon2id_defaults() {
        let (mem, par) = normalize_kdf_params(KDF_TYPE_ARGON2ID, 0, None, None);
        assert_eq!(mem, Some(ARGON2ID_MEMORY_DEFAULT_MB));
        assert_eq!(par, Some(ARGON2ID_PARALLELISM_DEFAULT));
    }
}
