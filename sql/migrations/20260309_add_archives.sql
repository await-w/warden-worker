CREATE TABLE IF NOT EXISTS archives (
    user_id TEXT NOT NULL,
    cipher_id TEXT NOT NULL,
    archived_at TEXT NOT NULL,
    PRIMARY KEY (user_id, cipher_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_archives_user_id ON archives(user_id);
CREATE INDEX IF NOT EXISTS idx_archives_cipher_id ON archives(cipher_id);
