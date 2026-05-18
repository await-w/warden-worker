use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::{Map, Value, json};

// This struct represents the data stored in the `data` column of the `ciphers` table.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
}

// Custom deserialization function for booleans
fn deserialize_bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    // A visitor is used to handle different data types
    struct BoolOrIntVisitor;

    impl<'de> de::Visitor<'de> for BoolOrIntVisitor {
        type Value = bool;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or an integer 0 or 1")
        }

        // Handles boolean values
        fn visit_bool<E>(self, value: bool) -> Result<bool, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        // Handles integer values (0 or 1)
        fn visit_u64<E>(self, value: u64) -> Result<bool, E>
        where
            E: de::Error,
        {
            match value {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(de::Error::invalid_value(
                    de::Unexpected::Unsigned(value),
                    &"0 or 1",
                )),
            }
        }
    }

    deserializer.deserialize_any(BoolOrIntVisitor)
}

// Custom deserialization function for optional non-empty strings
// Converts empty strings to None to handle newer Bitwarden clients
pub fn deserialize_optional_nonempty_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .and_then(|s| if s.is_empty() { None } else { Some(s) }))
}

// The struct that is stored in the database and used in handlers.
// For serialization to JSON for the client, we implement a custom `Serialize`.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub data: Value,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub favorite: bool,
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,

    // Bitwarden specific field for API responses
    #[serde(default = "default_object")]
    pub object: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub organization_use_totp: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub edit: bool,
    #[serde(default = "default_true")]
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub view_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherDBModel {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub r#type: i32,
    pub data: String,
    pub favorite: i32,
    pub folder_id: Option<String>,
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub archived_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CipherDBModel> for Cipher {
    fn from(val: CipherDBModel) -> Self {
        Cipher {
            id: val.id,
            user_id: Some(val.user_id),
            organization_id: val.organization_id,
            r#type: val.r#type,
            data: serde_json::from_str(&val.data).unwrap_or_default(),
            favorite: !matches!(val.favorite, 0),
            folder_id: val.folder_id,
            deleted_at: val.deleted_at,
            archived_at: val.archived_at,
            created_at: val.created_at,
            updated_at: val.updated_at,
            object: default_object(),
            organization_use_totp: true,
            edit: true,
            view_password: true,
            collection_ids: None,
        }
    }
}

impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut response_map = Map::new();
        let data_obj = self.data.as_object();
        let empty_data = Map::new();
        let data_obj = data_obj.unwrap_or(&empty_data);

        let name = data_obj.get("name").cloned().unwrap_or(Value::Null);
        let notes = data_obj.get("notes").cloned().unwrap_or(Value::Null);
        let fields = array_or_empty(data_obj.get("fields"));
        let password_history = array_or_empty(data_obj.get("passwordHistory"));
        let reprompt = data_obj
            .get("reprompt")
            .and_then(Value::as_i64)
            .filter(|v| *v == 0 || *v == 1)
            .unwrap_or(0);

        let mut login = Value::Null;
        let mut secure_note = Value::Null;
        let mut card = Value::Null;
        let mut identity = Value::Null;
        let mut ssh_key = Value::Null;

        let type_data = match self.r#type {
            1 => {
                let mut value = data_obj.get("login").cloned().unwrap_or(Value::Null);
                normalize_login(&mut value);
                login = value.clone();
                value
            }
            2 => {
                let mut value = data_obj.get("secureNote").cloned().unwrap_or(Value::Null);
                normalize_secure_note(&mut value);
                secure_note = value.clone();
                value
            }
            3 => {
                let value = data_obj.get("card").cloned().unwrap_or(Value::Null);
                card = value.clone();
                value
            }
            4 => {
                let value = data_obj.get("identity").cloned().unwrap_or(Value::Null);
                identity = value.clone();
                value
            }
            5 => {
                let value = data_obj.get("sshKey").cloned().unwrap_or(Value::Null);
                ssh_key = value.clone();
                value
            }
            _ => Value::Null,
        };

        let mut response_data = match type_data {
            Value::Object(map) => Value::Object(map),
            _ => Value::Object(Map::new()),
        };

        if let Value::Object(ref mut map) = response_data {
            map.insert("fields".to_string(), fields.clone());
            map.insert("name".to_string(), name.clone());
            map.insert("notes".to_string(), notes.clone());
            map.insert("passwordHistory".to_string(), password_history.clone());
        }

        response_map.insert("object".to_string(), json!(self.object));
        response_map.insert("id".to_string(), json!(self.id));
        response_map.insert("type".to_string(), json!(self.r#type));
        response_map.insert("creationDate".to_string(), json!(self.created_at));
        response_map.insert("revisionDate".to_string(), json!(self.updated_at));
        response_map.insert("deletedDate".to_string(), json!(self.deleted_at));
        response_map.insert("reprompt".to_string(), json!(reprompt));
        response_map.insert("organizationId".to_string(), json!(self.organization_id));
        response_map.insert("key".to_string(), Value::Null);
        response_map.insert("attachments".to_string(), Value::Null);
        response_map.insert(
            "organizationUseTotp".to_string(),
            json!(self.organization_use_totp),
        );
        response_map.insert(
            "collectionIds".to_string(),
            json!(self.collection_ids.clone().unwrap_or_default()),
        );
        response_map.insert("name".to_string(), name);
        response_map.insert("notes".to_string(), notes);
        response_map.insert("fields".to_string(), fields);
        response_map.insert("data".to_string(), response_data);
        response_map.insert("passwordHistory".to_string(), password_history);
        response_map.insert("login".to_string(), login);
        response_map.insert("secureNote".to_string(), secure_note);
        response_map.insert("card".to_string(), card);
        response_map.insert("identity".to_string(), identity);
        response_map.insert("sshKey".to_string(), ssh_key);
        response_map.insert("folderId".to_string(), json!(self.folder_id));
        response_map.insert("favorite".to_string(), json!(self.favorite));
        response_map.insert("archivedDate".to_string(), json!(self.archived_at));
        response_map.insert("edit".to_string(), json!(self.edit));
        response_map.insert("viewPassword".to_string(), json!(self.view_password));
        response_map.insert(
            "permissions".to_string(),
            json!({ "delete": self.edit, "restore": self.edit }),
        );

        Value::Object(response_map).serialize(serializer)
    }
}

fn default_object() -> String {
    "cipherDetails".to_string()
}

fn default_true() -> bool {
    true
}

fn array_or_empty(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Array(_)) => value.cloned().unwrap_or(Value::Array(Vec::new())),
        _ => Value::Array(Vec::new()),
    }
}

fn normalize_login(login: &mut Value) {
    let Value::Object(map) = login else {
        return;
    };

    let first_uri = map
        .get("uris")
        .and_then(Value::as_array)
        .and_then(|uris| uris.first())
        .and_then(|uri| uri.get("uri"))
        .cloned();

    map.insert("uri".to_string(), first_uri.unwrap_or(Value::Null));
}

fn normalize_secure_note(secure_note: &mut Value) {
    let has_numeric_type = secure_note
        .as_object()
        .and_then(|map| map.get("type"))
        .is_some_and(Value::is_number);

    if !has_numeric_type {
        *secure_note = json!({ "type": 0 });
    }
}

#[cfg(test)]
mod tests {
    use super::{Cipher, CreateCipherRequest};
    use serde_json::{Value, json};

    #[test]
    fn cipher_serialization_includes_permissions_delete() {
        let cipher = Cipher {
            id: "test-id".to_string(),
            user_id: Some("user-1".to_string()),
            organization_id: None,
            r#type: 1,
            data: json!({
                "name": "Example",
                "notes": null,
                "login": { "username": "u", "password": "p" }
            }),
            favorite: false,
            folder_id: None,
            deleted_at: None,
            archived_at: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
            object: "cipherDetails".to_string(),
            organization_use_totp: true,
            edit: true,
            view_password: true,
            collection_ids: None,
        };

        let value = serde_json::to_value(cipher).expect("serialize cipher");

        let permissions = value
            .get("permissions")
            .and_then(Value::as_object)
            .expect("permissions object");

        assert_eq!(
            permissions.get("delete"),
            Some(&Value::Bool(true)),
            "permissions.delete must exist and be true when edit=true"
        );
        assert_eq!(
            permissions.get("restore"),
            Some(&Value::Bool(true)),
            "permissions.restore must exist and be true when edit=true"
        );
        assert_eq!(value.get("archivedDate"), Some(&Value::Null));
        assert_eq!(value.get("object"), Some(&json!("cipherDetails")));
        assert_eq!(value.get("collectionIds"), Some(&json!([])));
        assert_eq!(value.get("fields"), Some(&json!([])));
        assert_eq!(value.pointer("/data/name"), Some(&json!("Example")));
        assert_eq!(value.pointer("/data/fields"), Some(&json!([])));
        assert_eq!(value.pointer("/login/uri"), Some(&Value::Null));
        assert!(
            value.get("userId").is_none(),
            "vaultwarden cipherDetails responses do not expose userId"
        );
    }

    #[test]
    fn create_cipher_request_deserializes_camelcase() {
        let body = json!({
            "cipher": { "type": 1, "name": "n" },
            "collectionIds": ["c1", "c2"]
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(req.cipher.r#type, 1);
        assert_eq!(req.cipher.name, "n");
        assert_eq!(req.collection_ids, vec!["c1".to_string(), "c2".to_string()]);
    }

    #[test]
    fn create_cipher_request_deserializes_pascalcase_compat() {
        let body = json!({
            "Cipher": { "type": 1, "name": "n" },
            "CollectionIds": ["c1"]
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(req.cipher.r#type, 1);
        assert_eq!(req.cipher.name, "n");
        assert_eq!(req.collection_ids, vec!["c1".to_string()]);
    }

    #[test]
    fn create_cipher_request_treats_empty_folder_id_as_none() {
        let body = json!({
            "cipher": { "type": 1, "name": "n", "folderId": "" },
            "collectionIds": []
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(req.cipher.folder_id, None);
    }

    #[test]
    fn create_cipher_request_deserializes_archived_date() {
        let body = json!({
            "cipher": {
                "type": 1,
                "name": "n",
                "archivedDate": "2026-05-06T00:00:00.000Z"
            },
            "collectionIds": []
        });

        let req: CreateCipherRequest = serde_json::from_value(body).expect("deserialize");
        assert_eq!(
            req.cipher.archived_date,
            Some("2026-05-06T00:00:00.000Z".to_string())
        );
    }
}

// Represents the "Cipher" object within the incoming request payload.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestData {
    #[serde(rename = "type")]
    pub r#type: i32,
    #[serde(default, deserialize_with = "deserialize_optional_nonempty_string")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_known_revision_date: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived_date: Option<String>,
}

// Represents the full request payload for creating a cipher.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCipherRequest {
    #[serde(alias = "Cipher")]
    pub cipher: CipherRequestData,
    #[serde(default)]
    #[serde(alias = "CollectionIds")]
    pub collection_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequestFlat {
    #[serde(flatten)]
    pub cipher: CipherRequestData,
    #[serde(default)]
    pub collection_ids: Vec<String>,
}
