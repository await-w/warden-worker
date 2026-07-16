use serde::{Deserialize, Deserializer};
use serde_json::Value;

fn deserialize_optional_nonempty_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .and_then(|s| if s.is_empty() { None } else { Some(s) }))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportCipher {
    #[serde(rename = "type")]
    pub r#type: i32,
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    pub folder_id: Option<String>,
    pub organization_id: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    pub login: Option<Value>,
    pub card: Option<Value>,
    pub identity: Option<Value>,
    pub secure_note: Option<Value>,
    pub fields: Option<Value>,
    pub password_history: Option<Value>,
    pub reprompt: Option<i32>,
    #[serde(rename = "lastKnownRevisionDate")]
    pub _last_known_revision_date: Option<String>,
    #[serde(default)]
    pub archived_date: Option<String>,
    pub encrypted_for: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportFolder {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderRelationship {
    pub key: usize,
    pub value: usize,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers: Vec<ImportCipher>,
    pub folders: Vec<ImportFolder>,
    #[serde(default)]
    pub folder_relationships: Vec<FolderRelationship>,
}

#[cfg(test)]
mod tests {
    use super::ImportCipher;
    use serde_json::json;

    #[test]
    fn import_cipher_allows_missing_folder_id() {
        let body = json!({
            "type": 1,
            "organizationId": null,
            "key": "2.cipher-key",
            "name": "n",
            "notes": null,
            "favorite": false,
            "login": null,
            "card": null,
            "identity": null,
            "secureNote": null,
            "fields": null,
            "passwordHistory": null,
            "reprompt": null,
            "lastKnownRevisionDate": null,
            "archivedDate": null,
            "encryptedFor": ""
        });

        let cipher: ImportCipher = serde_json::from_value(body).expect("deserialize");
        assert_eq!(cipher.folder_id, None);
        assert_eq!(cipher.key.as_deref(), Some("2.cipher-key"));
    }
}
