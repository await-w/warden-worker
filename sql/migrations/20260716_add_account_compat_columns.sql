-- Account compatibility fields used by the upstream API contracts.
ALTER TABLE users ADD COLUMN api_key TEXT;
ALTER TABLE users ADD COLUMN email_new TEXT;
ALTER TABLE users ADD COLUMN email_new_token TEXT;
ALTER TABLE users ADD COLUMN email_new_token_sent_at TEXT;
