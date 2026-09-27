use super::{cipher::Cipher, folder::FolderResponse};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDecryption {
    pub master_password_unlock: Value,
    pub user_key_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub name: String,
    pub email: String,
    pub id: String,
    pub avatar_color: Option<String>,
    pub master_password_hint: Option<String>,
    pub security_stamp: String,
    pub object: String,
    pub premium_from_organization: bool,
    pub force_password_reset: bool,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub premium: bool,
    pub uses_key_connector: bool,
    pub creation_date: String,
    pub private_key: String,
    pub key: String,
    pub culture: String,
    pub organizations: Vec<Value>,
    pub organizations_new: Vec<Value>,
    pub providers: Vec<Value>,
    pub provider_organizations: Vec<Value>,
    pub account_keys: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    pub folders: Vec<FolderResponse>,
    pub collections: Vec<Value>,
    pub policies: Vec<Value>,
    pub policies_new: Vec<Value>,
    pub ciphers: Vec<Cipher>,
    pub sends: Vec<Value>,
    pub domains: Value,
    pub user_decryption: UserDecryption,
    pub object: String,
}

#[cfg(test)]
mod tests {
    use super::UserDecryption;
    use serde_json::{Value, json};

    #[test]
    fn sync_user_key_id_is_null_until_initialized() {
        for key_id in [None, Some("key-1".to_string())] {
            let expected = json!(key_id);
            let response = serde_json::to_value(UserDecryption {
                master_password_unlock: json!({"masterKeyWrappedUserKey": "encrypted-key"}),
                user_key_id: key_id,
            })
            .unwrap();
            assert_eq!(response.get("userKeyId"), Some(&expected));
            assert_eq!(
                response["masterPasswordUnlock"]["masterKeyWrappedUserKey"],
                "encrypted-key"
            );
            assert_eq!(response.get("user_key_id"), None::<&Value>);
        }
    }
}
