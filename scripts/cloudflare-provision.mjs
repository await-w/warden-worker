import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const API_BASE_URL = "https://api.cloudflare.com/client/v4";
const ACCOUNT_ID_PATTERN = /^[0-9a-f]{32}$/i;
const D1_DATABASE_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class CloudflareApiError extends Error {
  constructor(message, status = 0, codes = []) {
    super(message);
    this.name = "CloudflareApiError";
    this.status = status;
    this.codes = codes;
  }
}

function apiErrorMessage(payload, status) {
  const messages = Array.isArray(payload?.errors)
    ? payload.errors
        .map((error) => {
          const code = error?.code ? ` (${error.code})` : "";
          return `${error?.message || "Unknown Cloudflare API error"}${code}`;
        })
        .join("; ")
    : "";
  return messages || `Cloudflare API request failed with HTTP ${status}`;
}

export class CloudflareApi {
  constructor(token, fetchImpl = globalThis.fetch) {
    if (!token) {
      throw new Error("CLOUDFLARE_API_TOKEN is required");
    }
    if (typeof fetchImpl !== "function") {
      throw new Error("A Fetch API implementation is required");
    }
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  async request(path, { method = "GET", body } = {}) {
    const headers = {
      Accept: "application/json",
      Authorization: `Bearer ${this.token}`,
    };
    const options = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }

    const response = await this.fetchImpl(`${API_BASE_URL}${path}`, options);
    const text = await response.text();
    let payload;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new CloudflareApiError(
        `Cloudflare API returned invalid JSON (HTTP ${response.status})`,
        response.status,
      );
    }

    if (!response.ok || payload?.success === false) {
      const codes = Array.isArray(payload?.errors)
        ? payload.errors
            .map((error) => Number(error?.code))
            .filter(Number.isFinite)
        : [];
      throw new CloudflareApiError(
        apiErrorMessage(payload, response.status),
        response.status,
        codes,
      );
    }
    return payload;
  }

  async optional(path) {
    try {
      return await this.request(path);
    } catch (error) {
      if (error instanceof CloudflareApiError && error.status === 404) {
        return null;
      }
      throw error;
    }
  }
}

async function collectPages(api, path) {
  const results = [];
  const perPage = 50;
  for (let page = 1; page <= 100; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const payload = await api.request(
      `${path}${separator}page=${page}&per_page=${perPage}`,
    );
    if (!Array.isArray(payload?.result)) {
      throw new Error(`Cloudflare API did not return a list for ${path}`);
    }
    results.push(...payload.result);

    const totalPages = Number(payload?.result_info?.total_pages || 0);
    if ((totalPages > 0 && page >= totalPages) || payload.result.length < perPage) {
      return results;
    }
  }
  throw new Error(`Cloudflare API pagination exceeded 100 pages for ${path}`);
}

export async function resolveAccountId(api, configuredAccountId = "") {
  const supplied = configuredAccountId.trim();
  if (supplied) {
    if (!ACCOUNT_ID_PATTERN.test(supplied)) {
      throw new Error("CLOUDFLARE_ACCOUNT_ID must be a 32-character hexadecimal ID");
    }
    await api.request(`/accounts/${supplied}`);
    return supplied;
  }

  const accounts = await collectPages(api, "/accounts");
  if (accounts.length === 0) {
    throw new Error(
      "The API token cannot access any Cloudflare account. Check Account Settings > Read and the token resource scope.",
    );
  }
  if (accounts.length !== 1) {
    throw new Error(
      `The API token can access ${accounts.length} accounts. Restrict the token to the target account or set the optional CLOUDFLARE_ACCOUNT_ID secret.`,
    );
  }

  const accountId = String(accounts[0]?.id || "");
  if (!ACCOUNT_ID_PATTERN.test(accountId)) {
    throw new Error("Cloudflare returned an invalid account ID");
  }
  return accountId;
}

export async function ensureD1Database(api, accountId, databaseName) {
  const databases = await collectPages(
    api,
    `/accounts/${accountId}/d1/database`,
  );
  const matches = databases.filter((database) => database?.name === databaseName);
  if (matches.length > 1) {
    throw new Error(`Multiple D1 databases are named '${databaseName}'`);
  }
  if (matches.length === 1) {
    const databaseId = String(matches[0]?.uuid || "");
    if (!D1_DATABASE_ID_PATTERN.test(databaseId)) {
      throw new Error(`D1 database '${databaseName}' has an invalid database ID`);
    }
    return { databaseId, isNew: false };
  }

  const created = await api.request(`/accounts/${accountId}/d1/database`, {
    method: "POST",
    body: { name: databaseName },
  });
  const databaseId = String(created?.result?.uuid || "");
  if (!D1_DATABASE_ID_PATTERN.test(databaseId)) {
    throw new Error(
      `Cloudflare created D1 database '${databaseName}' without returning a valid database ID`,
    );
  }
  const verified = await api.request(
    `/accounts/${accountId}/d1/database/${databaseId}`,
  );
  if (
    verified?.result?.uuid !== databaseId ||
    verified?.result?.name !== databaseName
  ) {
    throw new Error(
      `D1 database '${databaseName}' could not be verified after creation`,
    );
  }
  return { databaseId, isNew: true };
}

export async function ensureR2Bucket(api, accountId, bucketName) {
  const bucketPath = `/accounts/${accountId}/r2/buckets/${encodeURIComponent(bucketName)}`;
  const existing = await api.optional(bucketPath);
  if (existing) {
    return { isNew: false };
  }

  await api.request(`/accounts/${accountId}/r2/buckets`, {
    method: "POST",
    body: { name: bucketName },
  });
  const verified = await api.optional(bucketPath);
  if (!verified) {
    throw new Error(`R2 bucket '${bucketName}' was not found after creation`);
  }
  return { isNew: true };
}

export async function ensureWorkersSubdomain(api, accountId) {
  const path = `/accounts/${accountId}/workers/subdomain`;
  let existing;
  try {
    existing = await api.request(path);
  } catch (error) {
    const notRegistered =
      error instanceof CloudflareApiError &&
      (error.status === 404 || error.codes.includes(10007));
    if (!notRegistered) {
      throw error;
    }
    existing = null;
  }
  const existingSubdomain = String(existing?.result?.subdomain || "").trim();
  if (existingSubdomain) {
    return { subdomain: existingSubdomain, isNew: false };
  }

  const candidate = `warden-${accountId.toLowerCase()}`;
  const created = await api.request(path, {
    method: "PUT",
    body: { subdomain: candidate },
  });
  const subdomain = String(created?.result?.subdomain || "").trim();
  if (!subdomain) {
    throw new Error("Cloudflare created a Workers subdomain without returning its name");
  }
  return { subdomain, isNew: true };
}

export async function workerExists(api, accountId, workerName) {
  const settings = await api.optional(
    `/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}/settings`,
  );
  return settings !== null;
}

export function updateD1DatabaseId(configText, bindingName, databaseId) {
  if (!D1_DATABASE_ID_PATTERN.test(databaseId)) {
    throw new Error("database_id must be a UUID");
  }

  const escapedBinding = bindingName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const bindingPattern = new RegExp(
    `"binding"\\s*:\\s*"${escapedBinding}"(?:\\s*,)?`,
  );
  const objectPattern = /\{[^{}]*\}/gs;
  const matches = [...configText.matchAll(objectPattern)].filter((match) =>
    bindingPattern.test(match[0]),
  );

  if (matches.length !== 1) {
    throw new Error(
      `Expected exactly one flat D1 binding object named '${bindingName}', found ${matches.length}`,
    );
  }

  const match = matches[0];
  const objectText = match[0];
  const databaseIdPattern = /("database_id"\s*:\s*")[^"]*(")/g;
  const idMatches = [...objectText.matchAll(databaseIdPattern)];
  if (idMatches.length !== 1) {
    throw new Error(
      `D1 binding '${bindingName}' must contain exactly one database_id field`,
    );
  }

  const updatedObject = objectText.replace(
    databaseIdPattern,
    `$1${databaseId}$2`,
  );
  return `${configText.slice(0, match.index)}${updatedObject}${configText.slice(
    match.index + objectText.length,
  )}`;
}

function appendWorkflowValue(filePath, name, value) {
  if (filePath) {
    appendFileSync(filePath, `${name}=${String(value)}\n`, "utf8");
  }
}

export async function provisionFromEnvironment(
  env = process.env,
  fetchImpl = globalThis.fetch,
) {
  const token = env.CLOUDFLARE_API_TOKEN || "";
  const databaseName = env.D1_DATABASE_NAME || "vaultsql";
  const bucketName = env.R2_BUCKET_NAME || "warden-send-files";
  const workerName = env.WORKER_NAME || "warden-worker";
  const bindingName = env.D1_BINDING || "vaultsql";
  const configPath = env.WRANGLER_CONFIG || "wrangler.jsonc";

  const api = new CloudflareApi(token, fetchImpl);
  const accountId = await resolveAccountId(api, env.CLOUDFLARE_ACCOUNT_ID || "");
  const existed = await workerExists(api, accountId, workerName);
  const workersSubdomain = await ensureWorkersSubdomain(api, accountId);
  const d1 = await ensureD1Database(api, accountId, databaseName);
  const r2 = await ensureR2Bucket(api, accountId, bucketName);

  const originalConfig = readFileSync(configPath, "utf8");
  const updatedConfig = updateD1DatabaseId(
    originalConfig,
    bindingName,
    d1.databaseId,
  );
  writeFileSync(configPath, updatedConfig, "utf8");

  const workerUrl = `https://${workerName}.${workersSubdomain.subdomain}.workers.dev`;
  const outputs = {
    account_id: accountId,
    d1_database_id: d1.databaseId,
    d1_is_new: d1.isNew,
    r2_is_new: r2.isNew,
    workers_subdomain_is_new: workersSubdomain.isNew,
    worker_exists: existed,
    deployment_mode: existed ? "upgrade" : "fresh",
    worker_url: workerUrl,
  };

  for (const [name, value] of Object.entries(outputs)) {
    appendWorkflowValue(env.GITHUB_OUTPUT, name, value);
  }
  appendWorkflowValue(env.GITHUB_ENV, "CLOUDFLARE_ACCOUNT_ID", accountId);

  console.log(`Cloudflare account: ${accountId}`);
  console.log(
    `D1 '${databaseName}': ${d1.isNew ? "created" : "reused"} (${d1.databaseId})`,
  );
  console.log(`R2 '${bucketName}': ${r2.isNew ? "created" : "reused"}`);
  console.log(
    `Workers subdomain: ${workersSubdomain.isNew ? "created" : "reused"}`,
  );
  console.log(`Deployment mode: ${outputs.deployment_mode}`);
  return outputs;
}

const invokedAsScript =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  provisionFromEnvironment().catch((error) => {
    console.error(`::error::Cloudflare provisioning failed: ${error.message}`);
    process.exitCode = 1;
  });
}
