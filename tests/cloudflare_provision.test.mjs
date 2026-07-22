import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  ensureD1Database,
  ensureR2Bucket,
  ensureWorkersSubdomain,
  CloudflareApiError,
  provisionFromEnvironment,
  resolveAccountId,
  updateD1DatabaseId,
  workerExists,
} from "../scripts/cloudflare-provision.mjs";

const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const DATABASE_ID = "11111111-2222-4333-8444-555555555555";

test("account ID is discovered when the token has exactly one account", async () => {
  const api = {
    async request(path) {
      assert.equal(path, "/accounts?page=1&per_page=50");
      return { result: [{ id: ACCOUNT_ID }], result_info: { total_pages: 1 } };
    },
  };
  assert.equal(await resolveAccountId(api), ACCOUNT_ID);
});

test("multiple visible accounts require an explicit account ID", async () => {
  const api = {
    async request() {
      return {
        result: [{ id: ACCOUNT_ID }, { id: "f".repeat(32) }],
        result_info: { total_pages: 1 },
      };
    },
  };
  await assert.rejects(resolveAccountId(api), /can access 2 accounts/);
});

test("configured account ID is validated against Cloudflare", async () => {
  const calls = [];
  const api = {
    async request(path) {
      calls.push(path);
      return { result: { id: ACCOUNT_ID } };
    },
  };
  assert.equal(await resolveAccountId(api, ACCOUNT_ID), ACCOUNT_ID);
  assert.deepEqual(calls, [`/accounts/${ACCOUNT_ID}`]);
});

test("D1 lookup uses an exact database name and returns its database_id", async () => {
  const api = {
    async request(path) {
      assert.equal(
        path,
        `/accounts/${ACCOUNT_ID}/d1/database?page=1&per_page=50`,
      );
      return {
        result: [
          { name: "vaultsql-backup", uuid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
          { name: "vaultsql", uuid: DATABASE_ID },
        ],
        result_info: { total_pages: 1 },
      };
    },
  };
  assert.deepEqual(await ensureD1Database(api, ACCOUNT_ID, "vaultsql"), {
    databaseId: DATABASE_ID,
    isNew: false,
  });
});

test("missing D1 database is created and its returned database_id is used", async () => {
  const calls = [];
  const api = {
    async request(path, options = {}) {
      calls.push([path, options]);
      if (options.method === "POST") {
        return { result: { name: "vaultsql", uuid: DATABASE_ID } };
      }
      if (path.endsWith(`/${DATABASE_ID}`)) {
        return { result: { name: "vaultsql", uuid: DATABASE_ID } };
      }
      return { result: [], result_info: { total_pages: 1 } };
    },
  };
  assert.deepEqual(await ensureD1Database(api, ACCOUNT_ID, "vaultsql"), {
    databaseId: DATABASE_ID,
    isNew: true,
  });
  assert.deepEqual(calls[1], [
    `/accounts/${ACCOUNT_ID}/d1/database`,
    { method: "POST", body: { name: "vaultsql" } },
  ]);
  assert.deepEqual(calls[2], [
    `/accounts/${ACCOUNT_ID}/d1/database/${DATABASE_ID}`,
    {},
  ]);
});

test("R2 bucket creation is verified with an exact bucket lookup", async () => {
  let optionalCalls = 0;
  const api = {
    async optional(path) {
      assert.equal(path, `/accounts/${ACCOUNT_ID}/r2/buckets/warden-send-files`);
      optionalCalls += 1;
      return optionalCalls === 1 ? null : { result: { name: "warden-send-files" } };
    },
    async request(path, options) {
      assert.equal(path, `/accounts/${ACCOUNT_ID}/r2/buckets`);
      assert.deepEqual(options, {
        method: "POST",
        body: { name: "warden-send-files" },
      });
      return { result: { name: "warden-send-files" } };
    },
  };
  assert.deepEqual(await ensureR2Bucket(api, ACCOUNT_ID, "warden-send-files"), {
    isNew: true,
  });
  assert.equal(optionalCalls, 2);
});

test("a missing Workers subdomain is created deterministically", async () => {
  const api = {
    async request(path, options = {}) {
      assert.equal(path, `/accounts/${ACCOUNT_ID}/workers/subdomain`);
      if (!options.method) {
        throw new CloudflareApiError("Subdomain is not registered", 400, [10007]);
      }
      assert.deepEqual(options, {
        method: "PUT",
        body: { subdomain: "warden-0123456789abcdef0123456789abcdef" },
      });
      return { result: { subdomain: options.body.subdomain } };
    },
  };
  assert.deepEqual(await ensureWorkersSubdomain(api, ACCOUNT_ID), {
    subdomain: "warden-0123456789abcdef0123456789abcdef",
    isNew: true,
  });
});

test("worker existence check treats only an exact settings 404 as missing", async () => {
  const paths = [];
  const api = {
    async optional(path) {
      paths.push(path);
      return null;
    },
  };
  assert.equal(await workerExists(api, ACCOUNT_ID, "warden-worker"), false);
  assert.deepEqual(paths, [
    `/accounts/${ACCOUNT_ID}/workers/scripts/warden-worker/settings`,
  ]);
});

test("only the requested D1 binding database_id is updated", () => {
  const config = `{
  "d1_databases": [
    {
      "binding": "vaultsql",
      "database_name": "vaultsql",
      "database_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    },
    {
      "binding": "audit",
      "database_id": "99999999-8888-4777-8666-555555555555"
    }
  ]
}`;
  const updated = updateD1DatabaseId(config, "vaultsql", DATABASE_ID);
  assert.match(updated, new RegExp(`"database_id": "${DATABASE_ID}"`));
  assert.match(
    updated,
    /"binding": "audit",\s+"database_id": "99999999-8888-4777-8666-555555555555"/,
  );
});

test("D1 config update rejects a missing binding or invalid database_id", () => {
  assert.throws(
    () => updateD1DatabaseId("{}", "vaultsql", DATABASE_ID),
    /found 0/,
  );
  assert.throws(
    () => updateD1DatabaseId("{}", "vaultsql", "not-a-uuid"),
    /must be a UUID/,
  );
});

function jsonResponse(result, status = 200) {
  return new Response(
    JSON.stringify({
      success: status >= 200 && status < 300,
      result,
      errors:
        status >= 200 && status < 300
          ? []
          : [{ code: 1000, message: "Not found" }],
    }),
    { status, headers: { "Content-Type": "application/json" } },
  );
}

async function runProvisionScenario(existing) {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "warden-provision-test-"));
  const configPath = join(temporaryDirectory, "wrangler.jsonc");
  const outputPath = join(temporaryDirectory, "github-output.txt");
  const environmentPath = join(temporaryDirectory, "github-env.txt");
  writeFileSync(
    configPath,
    `{
      "name": "warden-worker",
      "d1_databases": [{
        "binding": "vaultsql",
        "database_name": "vaultsql",
        "database_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
      }]
    }`,
    "utf8",
  );

  let r2Created = false;
  const requests = [];
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const key = `${options.method} ${parsed.pathname}${parsed.search}`;
    requests.push(key);
    assert.equal(options.headers.Authorization, "Bearer test-token");

    if (parsed.pathname === "/client/v4/accounts") {
      return jsonResponse([{ id: ACCOUNT_ID }]);
    }
    if (parsed.pathname.endsWith("/workers/scripts/warden-worker/settings")) {
      return existing ? jsonResponse({ bindings: [] }) : jsonResponse(null, 404);
    }
    if (parsed.pathname.endsWith("/workers/subdomain")) {
      if (options.method === "PUT") {
        return jsonResponse({ subdomain: JSON.parse(options.body).subdomain });
      }
      return existing
        ? jsonResponse({ subdomain: "existing-subdomain" })
        : new Response(
            JSON.stringify({
              success: false,
              result: null,
              errors: [{ code: 10007, message: "Subdomain is not registered" }],
            }),
            { status: 400, headers: { "Content-Type": "application/json" } },
          );
    }
    if (parsed.pathname.endsWith("/d1/database")) {
      if (options.method === "POST") {
        return jsonResponse({ name: "vaultsql", uuid: DATABASE_ID });
      }
      return jsonResponse(
        existing ? [{ name: "vaultsql", uuid: DATABASE_ID }] : [],
      );
    }
    if (parsed.pathname.endsWith(`/d1/database/${DATABASE_ID}`)) {
      return jsonResponse({ name: "vaultsql", uuid: DATABASE_ID });
    }
    if (parsed.pathname.endsWith("/r2/buckets/warden-send-files")) {
      return existing || r2Created
        ? jsonResponse({ name: "warden-send-files" })
        : jsonResponse(null, 404);
    }
    if (parsed.pathname.endsWith("/r2/buckets") && options.method === "POST") {
      r2Created = true;
      return jsonResponse({ name: "warden-send-files" });
    }
    throw new Error(`Unexpected request: ${key}`);
  };

  try {
    const outputs = await provisionFromEnvironment(
      {
        CLOUDFLARE_API_TOKEN: "test-token",
        D1_DATABASE_NAME: "vaultsql",
        D1_BINDING: "vaultsql",
        R2_BUCKET_NAME: "warden-send-files",
        WORKER_NAME: "warden-worker",
        WRANGLER_CONFIG: configPath,
        GITHUB_OUTPUT: outputPath,
        GITHUB_ENV: environmentPath,
      },
      fetchImpl,
    );
    return {
      outputs,
      requests,
      config: readFileSync(configPath, "utf8"),
      githubOutput: readFileSync(outputPath, "utf8"),
      githubEnvironment: readFileSync(environmentPath, "utf8"),
    };
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

test("fresh provisioning creates all resources and fills database_id", async () => {
  const result = await runProvisionScenario(false);
  assert.equal(result.outputs.deployment_mode, "fresh");
  assert.equal(result.outputs.d1_is_new, true);
  assert.equal(result.outputs.r2_is_new, true);
  assert.match(result.config, new RegExp(`"database_id": "${DATABASE_ID}"`));
  assert.match(result.githubOutput, /^d1_database_id=11111111-2222-4333-8444-555555555555$/m);
  assert.match(result.githubOutput, /^deployment_mode=fresh$/m);
  assert.equal(
    result.githubEnvironment,
    `CLOUDFLARE_ACCOUNT_ID=${ACCOUNT_ID}\n`,
  );
  assert.ok(result.requests.some((request) => request.startsWith("POST ") && request.endsWith("/d1/database")));
  assert.ok(result.requests.some((request) => request.startsWith("POST ") && request.endsWith("/r2/buckets")));
});

test("upgrade provisioning reuses resources and keeps schema initialization disabled", async () => {
  const result = await runProvisionScenario(true);
  assert.equal(result.outputs.deployment_mode, "upgrade");
  assert.equal(result.outputs.d1_is_new, false);
  assert.equal(result.outputs.r2_is_new, false);
  assert.equal(result.outputs.worker_url, "https://warden-worker.existing-subdomain.workers.dev");
  assert.ok(!result.requests.some((request) => request.startsWith("POST ")));
  assert.ok(!result.requests.some((request) => request.startsWith("PUT ")));
  assert.match(result.githubOutput, /^d1_is_new=false$/m);
});
