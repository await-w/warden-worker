import fs from "node:fs";
import path from "node:path";

const LOG_PREFIX = "[patch-webvault-kdf]";
const SNIPPET_RADIUS = 80;
const MAX_SNIPPET_LEN = 240;
const MAX_LOGGED_MATCHES_PER_RULE = 10;

function normalizePath(filePath) {
  return path.relative(process.cwd(), filePath).split(path.sep).join("/");
}

function preview(text, maxLen = MAX_SNIPPET_LEN) {
  const oneLine = String(text).replace(/\s+/g, " ").trim();
  if (oneLine.length <= maxLen) {
    return oneLine;
  }
  return `${oneLine.slice(0, maxLen)}...`;
}

function log(message) {
  console.log(`${LOG_PREFIX} ${message}`);
}

function logError(message) {
  console.error(`${LOG_PREFIX} ${message}`);
}

function createGlobalRegex(regex) {
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  return new RegExp(regex.source, flags);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function collectRuleMatches(content, regex) {
  const globalRegex = createGlobalRegex(regex);
  const hits = [];
  let match;
  while ((match = globalRegex.exec(content)) !== null) {
    const start = Math.max(0, match.index - SNIPPET_RADIUS);
    const end = Math.min(content.length, match.index + match[0].length + SNIPPET_RADIUS);
    hits.push({
      index: match.index,
      before: content.slice(start, match.index),
      matched: match[0],
      after: content.slice(match.index + match[0].length, end),
    });
  }
  return hits;
}

const webVaultAppDir = path.resolve(
  process.env.WEB_VAULT_APP_DIR ?? path.join("static", "web-vault", "app"),
);
if (!fs.existsSync(webVaultAppDir)) {
  logError(`Directory not found: ${webVaultAppDir}`);
  process.exit(1);
}

function collectFiles(dir, predicate) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath, predicate));
      continue;
    }
    if (predicate(entry.name, fullPath)) {
      results.push(fullPath);
    }
  }
  return results;
}

const targets = collectFiles(webVaultAppDir, (name) => name.endsWith(".js"));

log(`Scanning directory: ${normalizePath(webVaultAppDir)}`);
log(`Discovered ${targets.length} JavaScript bundle candidate(s).`);
for (const file of targets) {
  log(`Candidate file: ${normalizePath(file)}`);
}

if (targets.length === 0) {
  logError("No JavaScript bundles found under static/web-vault/app");
  process.exit(1);
}

function buildPatches(content) {
  const patches = [];
  const pbkdf2Class =
    /class ([\w$]+)\{constructor\(e\)\{this\.kdfType=([\w$]+)\.PBKDF2_SHA256,this\.iterations=null!=e\?e:\1\.ITERATIONS\.defaultValue/.exec(
      content,
    );
  const argon2Class =
    /class ([\w$]+)\{constructor\(e,t,i\)\{this\.kdfType=([\w$]+)\.Argon2id,this\.iterations=null!=e\?e:\1\.ITERATIONS\.defaultValue/.exec(
      content,
    );

  if (pbkdf2Class && argon2Class && pbkdf2Class[2] === argon2Class[2]) {
    const pbkdf2Name = escapeRegex(pbkdf2Class[1]);
    const argon2Name = argon2Class[1];
    patches.push({
      name: "default-kdf-config",
      search: new RegExp(
        `const ([\\w$]+)=new ${pbkdf2Name}\\(${pbkdf2Name}\\.ITERATIONS\\.defaultValue\\);`,
        "g",
      ),
      replace: (_match, configName) =>
        `const ${configName}=new ${argon2Name}(${argon2Name}.ITERATIONS.defaultValue,${argon2Name}.MEMORY.defaultValue,${argon2Name}.PARALLELISM.defaultValue);`,
      replacementDescription: `replace the detected PBKDF2 default with ${argon2Name} Argon2id defaults`,
    });
  } else {
    log("Could not detect matching PBKDF2/Argon2id class symbols in this file.");
  }

  patches.push(
    {
      name: "kdf-form-default",
      search:
        /kdf:new ([\w$]+)\.MJ\(([\w$]+)\.ao\.PBKDF2_SHA256,\[\1\.k0\.required\]\)/g,
      replace: (_match, formSymbol, kdfSymbol) =>
        `kdf:new ${formSymbol}.MJ(${kdfSymbol}.ao.Argon2id,[${formSymbol}.k0.required])`,
      replacementDescription: "replace the registration form PBKDF2 default with Argon2id",
    },
    {
      name: "argon2-register-defaults",
      search:
        /this\.kdf=([\w$]+)\.ao\.Argon2id,this\.kdfIterations=([\w$]+)\.iterations,this\.kdfMemory=\2\.memory,this\.kdfParallelism=\2\.parallelism/g,
      replace: (_match, kdfSymbol, kdfConfig) =>
        `this.kdf=${kdfSymbol}.ao.Argon2id,this.kdfIterations=${kdfConfig}.iterations,this.kdfMemory=null!=${kdfConfig}.memory?${kdfConfig}.memory:64,this.kdfParallelism=null!=${kdfConfig}.parallelism?${kdfConfig}.parallelism:4`,
      replacementDescription: "add Argon2id memory and parallelism fallbacks",
    },
    {
      name: "register-request-kdf-params",
      search:
        /new ([\w$]+)\(([^,()]+),([\w$]+)\.newServerMasterKeyHash,\3\.newPasswordHint,([^,()]+),([^,()]+),\3\.kdfConfig\.kdfType,\3\.kdfConfig\.iterations\)/g,
      replace: (_match, requestClass, email, state, userKey, asymmetricKeys) =>
        `new ${requestClass}(${email},${state}.newServerMasterKeyHash,${state}.newPasswordHint,${userKey},${asymmetricKeys},${state}.kdfConfig.kdfType,${state}.kdfConfig.iterations,null!=${state}.kdfConfig.memory?${state}.kdfConfig.memory:64,null!=${state}.kdfConfig.parallelism?${state}.kdfConfig.parallelism:4)`,
      replacementDescription: "include Argon2id memory and parallelism in the register request",
    },
  );

  return patches;
}

const functionalSignals = [
  {
    name: "default-kdf-config-argon2id",
    search:
      /const [\w$]+=new ([\w$]+)\(\1\.ITERATIONS\.defaultValue,\1\.MEMORY\.defaultValue,\1\.PARALLELISM\.defaultValue\);/,
  },
  {
    name: "form-default-argon2id",
    search:
      /kdf:new ([\w$]+)\.MJ\(([\w$]+)\.ao\.Argon2id,\[\1\.k0\.required\]\)/,
  },
  {
    name: "register-default-memory-parallelism",
    search:
      /kdf=([\w$]+)\.ao\.Argon2id,this\.kdfIterations=([\w$]+)\.iterations,this\.kdfMemory=null!=\2\.memory\?\2\.memory:64,this\.kdfParallelism=null!=\2\.parallelism\?\2\.parallelism:4/,
  },
  {
    name: "request-carries-kdf-memory-parallelism",
    search:
      /kdfConfig\.iterations,null!=([\w$]+)\.kdfConfig\.memory\?\1\.kdfConfig\.memory:64,null!=\1\.kdfConfig\.parallelism\?\1\.kdfConfig\.parallelism:4/,
  },
];

function collectSignalHits(fileContents) {
  const hitMap = new Map(functionalSignals.map((signal) => [signal.name, false]));
  const hitFiles = new Map(functionalSignals.map((signal) => [signal.name, []]));
  for (const [file, content] of fileContents) {
    const rel = normalizePath(file);
    log(`Signal scan file: ${rel}`);
    for (const signal of functionalSignals) {
      if (signal.search.test(content)) {
        hitMap.set(signal.name, true);
        hitFiles.get(signal.name).push(rel);
        log(
          `Signal hit: ${signal.name} in ${rel} | keyword regex: ${signal.search.source}`,
        );
      }
    }
  }
  return { hitMap, hitFiles };
}

function allSignalsSatisfied(hitMap) {
  for (const signal of functionalSignals) {
    if (!hitMap.get(signal.name)) {
      return false;
    }
  }
  return true;
}

let totalReplacements = 0;
const originalContents = new Map(
  targets.map((file) => [file, fs.readFileSync(file, "utf8")]),
);
const patchedContents = new Map(originalContents);
const changedFiles = new Set();
for (const file of targets) {
  let content = originalContents.get(file);
  let fileReplacements = 0;
  const rel = normalizePath(file);
  log(`Start patch scan: ${rel}`);

  for (const patch of buildPatches(content)) {
    const matches = collectRuleMatches(content, patch.search);
    if (matches.length > 0) {
      log(
        `Rule matched: ${patch.name} in ${rel} | count=${matches.length} | regex=${patch.search.source}`,
      );
      const logCount = Math.min(matches.length, MAX_LOGGED_MATCHES_PER_RULE);
      for (let i = 0; i < logCount; i++) {
        const hit = matches[i];
        log(
          `  [${patch.name} #${i + 1}] index=${hit.index} | before="${preview(hit.before)}" | matched="${preview(hit.matched)}" | after="${preview(hit.after)}"`,
        );
        log(
          `  [${patch.name} #${i + 1}] replacement="${preview(patch.replacementDescription ?? patch.replace)}"`,
        );
      }
      if (matches.length > MAX_LOGGED_MATCHES_PER_RULE) {
        log(
          `  [${patch.name}] additional ${matches.length - MAX_LOGGED_MATCHES_PER_RULE} match(es) omitted from detailed log.`,
        );
      }
    } else {
      log(`Rule miss: ${patch.name} in ${rel} | regex=${patch.search.source}`);
    }

    const before = content;
    content = content.replace(createGlobalRegex(patch.search), patch.replace);
    if (content !== before) {
      fileReplacements += matches.length;
      log(`Rule applied: ${patch.name} in ${rel}`);
    }
  }

  if (fileReplacements > 0) {
    patchedContents.set(file, content);
    changedFiles.add(file);
    totalReplacements += fileReplacements;
    log(`Prepared ${rel} (${fileReplacements} replacement(s))`);
  } else {
    log(`No changes for file: ${rel}`);
  }
}

if (totalReplacements === 0) {
  const { hitMap, hitFiles } = collectSignalHits(originalContents);
  for (const signal of functionalSignals) {
    const files = hitFiles.get(signal.name);
    if (files.length > 0) {
      log(`Signal summary: ${signal.name} found in ${files.join(", ")}`);
    } else {
      log(`Signal summary: ${signal.name} NOT found`);
    }
  }

  if (allSignalsSatisfied(hitMap)) {
    log("KDF behavior already present. No changes needed.");
    process.exit(0);
  }

  const missingSignals = functionalSignals
    .filter((signal) => !hitMap.get(signal.name))
    .map((signal) => signal.name)
    .join(", ");

  logError(`No patch rules matched and required KDF behavior is missing: ${missingSignals}`);
  process.exit(1);
}

const { hitMap: signalHitsAfterPatchMap, hitFiles: signalHitsAfterPatchFiles } =
  collectSignalHits(patchedContents);
for (const signal of functionalSignals) {
  const files = signalHitsAfterPatchFiles.get(signal.name);
  if (files.length > 0) {
    log(`Post-patch signal: ${signal.name} found in ${files.join(", ")}`);
  } else {
    log(`Post-patch signal: ${signal.name} NOT found`);
  }
}

if (!allSignalsSatisfied(signalHitsAfterPatchMap)) {
  const missingSignals = functionalSignals
    .filter((signal) => !signalHitsAfterPatchMap.get(signal.name))
    .map((signal) => signal.name)
    .join(", ");
  logError(`Patch applied but required KDF behavior is still missing: ${missingSignals}`);
  process.exit(1);
}

for (const file of changedFiles) {
  fs.writeFileSync(file, patchedContents.get(file), "utf8");
  log(`Patched ${normalizePath(file)}`);
}

log(`Done. Total replacements: ${totalReplacements}`);
