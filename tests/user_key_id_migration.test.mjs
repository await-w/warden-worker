import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";

const baseline = readFileSync(new URL("../sql/schema.sql", import.meta.url), "utf8");
const migration = readFileSync(
  new URL("../sql/migrations/0001_add_user_key_id.sql", import.meta.url),
  "utf8",
);
const accounts = readFileSync(new URL("../src/handlers/accounts.rs", import.meta.url), "utf8");
const initializeSql = accounts.match(/const SET_USER_KEY_ID_SQL: &str =\s*"([^"]+)";/)?.[1];
assert.ok(initializeSql, "the account handler must define the key initialization SQL");

test("user key ID migration preserves existing vault data and allows only one initialization", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(baseline);
    db.prepare(`INSERT INTO users
      (id, email, master_password_hash, key, private_key, public_key, security_stamp, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      "user-1", "user@example.com", "password-verifier", "encrypted-key", "encrypted-private-key",
      "public-key", "stamp", "original-created", "original-updated",
    );
    db.prepare(`INSERT INTO ciphers (id, user_id, type, data, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)`).run("cipher-1", "user-1", 1, '{"name":"encrypted-name"}', "created", "updated");
    db.exec(migration);
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get("user-1");
    assert.equal(user.key_id, null);
    assert.equal(user.key, "encrypted-key");
    assert.equal(user.master_password_hash, "password-verifier");
    assert.equal(user.updated_at, "original-updated");
    assert.equal(db.prepare("SELECT data FROM ciphers WHERE id = ?").get("cipher-1").data, '{"name":"encrypted-name"}');

    const initialize = db.prepare(initializeSql);
    assert.equal(initialize.run("foreign-key", "wrong-revision", "user-2").changes, 0);
    assert.equal(initialize.run("key-1", "initialized-revision", "user-1").changes, 1);
    assert.equal(initialize.run("key-1", "repeat-revision", "user-1").changes, 0);
    assert.equal(initialize.run("key-2", "replacement-revision", "user-1").changes, 0);
    const initialized = db.prepare("SELECT key_id, key, updated_at FROM users WHERE id = ?").get("user-1");
    assert.equal(initialized.key_id, "key-1");
    assert.equal(initialized.key, "encrypted-key");
    assert.equal(initialized.updated_at, "initialized-revision");
  } finally {
    db.close();
  }
});

test("fresh database receives the key ID column through the migration chain", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(baseline);
    db.exec(migration);
    const column = db.prepare("PRAGMA table_info(users)").all().find((column) => column.name === "key_id");
    assert.equal(column?.type, "TEXT");
    assert.equal(column.notnull, 0);
  } finally {
    db.close();
  }
});
