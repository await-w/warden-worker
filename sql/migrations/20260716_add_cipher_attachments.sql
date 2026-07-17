-- Cipher attachment metadata. Binary data is stored in R2.
CREATE TABLE IF NOT EXISTS cipher_attachments (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    key TEXT,
    r2_object_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cipher_attachments_cipher_id
    ON cipher_attachments(cipher_id);
CREATE INDEX IF NOT EXISTS idx_cipher_attachments_user_id
    ON cipher_attachments(user_id);
