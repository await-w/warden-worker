-- NULL marks legacy rows. They are rehashed with Vaultwarden-compatible
-- PBKDF2-HMAC-SHA256 after the next successful password verification.
ALTER TABLE users ADD COLUMN password_iterations INTEGER;
