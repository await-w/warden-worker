# Project Memory

> 本文件保存当前仓库经过代码与本地验证确认的长期上下文。
> 开始项目任务前应先读取并核验本文件，任务结束后应同步更新。

## 基本信息

- 项目名称：Warden Worker
- 项目路径：`D:\gitrepo\warden-worker`
- 上游仓库：`git@github.com:snakexgc/warden-worker.git`
- 当前分支：`main`
- 项目类型：面向个人、单用户部署的 Bitwarden 兼容 Cloudflare Workers 服务端
- Cargo 包版本：`1.3.0`
- Web Vault 版本：`2026.6.2`
- 主要技术栈：Rust 2024、WebAssembly、worker-rs、Axum、JavaScript、Cloudflare Workers、D1、R2、Durable Objects
- 数据与鉴权：SQLite/D1、JWT、PBKDF2-HMAC-SHA256、Argon2id 兼容、TOTP、WebAuthn
- 构建工具：Cargo、`worker-build`、Node.js、Wrangler
- CI 固定版本：Wrangler `4.111.0`、`worker-build` `0.8.5`
- Worker 兼容日期：`2026-02-28`
- 构建命令：`node ./scripts/patch-webvault-turnstile.mjs && worker-build --release`
- 测试命令：
  - `cargo test`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo fmt --all -- --check`
  - `node --test tests/heavy_do_routing.test.mjs`
- 手动部署命令：`wrangler deploy`
- 最后更新时间：2026-07-17

## 项目概述

Warden Worker 将个人密码库服务部署到 Cloudflare 边缘环境，提供 Bitwarden 客户端和 Web Vault 所需的账户、认证、同步、密码项、文件夹、附件、Send、2FA、WebAuthn 与通知接口。D1 保存业务数据和密钥材料，R2 保存附件及 Send 文件，Durable Objects 分别承担实时通知和高 CPU 路由。

本项目不是 Vaultwarden 的逐行移植。兼容性工作应以客户端可观察行为为准，核对请求/响应结构、路由、状态码、版本与功能开关、同步 revision、通知副作用和数据迁移，而不能仅比较同名文件。

## 项目结构与文件职责

### 根目录与部署

- `README.md`
  - 部署、升级、Secrets、接口与通知配置说明。
- `Cargo.toml` / `Cargo.lock`
  - Rust 包元数据、依赖版本、Wasm 发布配置和 lint 规则。
- `wrangler.jsonc`
  - Worker 入口、Cron、变量、D1/R2/限流/DO 绑定、迁移、日志、构建与静态资源配置。
- `.github/workflows/push-cloudflare.yaml`
  - 对 `main`、`uat`、`release*` 的 CI/CD；执行预检、基础设施创建或复用、旧库基线处理、D1 原生迁移、DO 绑定协调和 Worker 部署。
- `scripts/patch-webvault-turnstile.mjs`
  - 构建前在 Web Vault 入口注入匿名 Send 的 Turnstile 导航保护；通过版本标记避免重复注入。
- `tests/heavy_do_routing.test.mjs`
  - 验证高 CPU/密码相关路径被分流到固定的 `personal-vault` HeavyDo。
- `static/web-vault/`
  - Wrangler Assets 发布的 Web Vault 构建产物；当前版本为 `2026.6.2`。
- `build/`、`target/`
  - 本地生成的 JS/Wasm 与 Rust 构建产物，不作为业务源码维护。

### `src`

- `src/entry.js`
  - Cloudflare JS 入口；规范化路径，将高 CPU 路由交给 `HEAVY_DO`，其余请求交给 Rust/Wasm Worker，并导出两个 DO 类。
- `src/heavy_do_routing.mjs`
  - HeavyDo 路由白名单和固定实例名规则。
- `src/lib.rs`
  - Rust Worker 的 `fetch`、`scheduled` 入口；初始化日志、D1/JWT/2FA 密钥、通知代理、CF 地理请求头、CORS 与 Axum Router。
- `src/router.rs`
  - Bitwarden/Vaultwarden 兼容 HTTP 路由总表和共享 `AppState`。
- `src/heavy_do.rs`
  - `HeavyDo` 实现；复用同一套 Router，在 DO CPU 预算内执行密码验证等重计算请求。
- `src/notifications.rs`
  - `NotificationsHub` Durable Object、SignalR/WebSocket 协议处理，以及密码项、文件夹、Send、用户和认证请求的实时更新发布。
- `src/background.rs`
  - 统一封装入口 Worker 的 `wait_until` 与 DO 内的异步后台任务。
- `src/handlers/`
  - HTTP 业务处理层，涵盖账户、身份令牌、同步、密码项、附件、文件夹、Send、导入、设备、设置、事件、兼容端点、2FA、WebAuthn、图标、CSS 与用量统计。
- `src/models/`
  - 用户、密码项、文件夹、Send、同步、导入和归档的数据结构、兼容反序列化及 API 序列化。
- `src/auth.rs`、`src/jwt.rs`、`src/jwt_manager.rs`
  - Bearer/JWT 鉴权、令牌签发与 D1 中的 JWT 密钥管理。
- `src/password.rs`、`src/crypto.rs`
  - 服务端密码哈希、验证、旧哈希升级与客户端 KDF 参数校验。
- `src/two_factor.rs`、`src/two_factor_key_manager.rs`
  - TOTP/2FA 核心逻辑和 D1 加密密钥管理。
- `src/webauthn.rs`
  - WebAuthn/Passkey 凭据、挑战、登录验证与 PRF 支持。
- `src/notify/`
  - 企业微信、Telegram 通道、事件类型、模板、配置、上下文与分发器。
- `src/db.rs`
  - D1 获取、统一毫秒时间戳和用户 vault revision 更新/读取。

### `sql`

- `sql/schema.sql`
  - 新数据库的完整基线结构；包含 `DROP TABLE`，对已有数据库执行会清空数据。
- `sql/d1-migrations/`
  - Wrangler 原生 D1 迁移目录；`0001_baseline.sql` 是兼容新旧数据库的 no-op 跟踪基线。
- `sql/migrations/`
  - 原生迁移启用前的历史/兼容迁移，以及 CI 对旧数据库做结构探测时使用的 SQL。

## 架构与关键流程

### HTTP 请求

1. Wrangler Assets 根据 `run_worker_first` 决定 API/动态路径先进入 Worker。
2. `src/entry.js` 规范化 URL；匹配 `src/heavy_do_routing.mjs` 的路径进入固定 `personal-vault` HeavyDo，其余进入 Rust Worker。
3. Rust 入口对 `/notifications/*` 直接代理到 `NotificationsHub`；普通请求初始化 D1、JWT 密钥和 2FA 密钥后进入 Axum Router。
4. `src/router.rs` 将请求分派到 `src/handlers/`；处理器调用模型、鉴权/密码/WebAuthn/2FA 模块并读写 D1 或 R2。
5. 成功的 vault 变更需同步更新用户 revision，并按业务需要发布实时通知。

### 高 CPU 密码路径

- 服务端密码 verifier 使用 PBKDF2-HMAC-SHA256，当前规则为 600,000 次迭代和独立随机 salt。
- 创建或验证 verifier 的路径必须经 `HEAVY_DO`，避免入口 Worker 的 CPU 限制。
- 本项目是单用户密码库，所有重计算请求共用固定的 `personal-vault` 实例；并发重计算可能短暂串行。
- 旧密码记录在成功验证后按当前格式渐进升级，不应将客户端 KDF 设置与服务端 verifier 规则混为一谈。

### 数据与文件

- D1 绑定名固定为 `vaultsql`，保存用户、密码项、文件夹、Send、设备、2FA/WebAuthn、JWT/2FA 密钥和附件元数据。
- R2 绑定名为 `SEND_FILES_BUCKET`，保存附件及 Send 文件二进制数据。
- `LOGIN_LIMITER` 与 `SEND_ACCESS_LIMITER` 分别保护登录和匿名 Send 访问。
- 每日 `0 3 * * *` Cron 调用 Send 清理逻辑，删除过期元数据和相关 R2 文件。

### 实时通知

- `NOTIFICATIONS_HUB` 承担 WebSocket/SignalR 连接与内部事件广播。
- vault 写操作的正确性不仅包括 D1 结果，还包括用户 revision 和相应的实时更新事件。

### 部署与迁移

- GitHub Actions 会检查 Cloudflare 凭证权限，创建或复用 `vaultsql` 与 `warden-send-files`，再应用迁移并部署。
- 新数据库先导入 `sql/schema.sql`，再由 Wrangler 应用 `sql/d1-migrations/`。
- 已发布的迁移文件不得修改或重排；新增结构变化应创建新的顺序迁移文件。
- 对已有生产数据库不得直接执行 `sql/schema.sql`；执行任何数据库操作前先确认 `--local`/`--remote` 和目标数据库。

## 特殊事项与项目约束

- 项目定位是个人单用户密码库；`users_single_user_before_insert` 触发器是数据库层最终约束，注册处理也应在昂贵哈希前快速拒绝第二个用户。
- 不得在仓库、日志或 `memory.md` 中记录 API Token、Webhook、Bot Token、Turnstile Secret 或用户密码。
- `DOMAIN` 影响 WebAuthn RP ID、Origin 和外部 URL，部署时必须与真实 HTTPS 域名一致。
- `wrangler.jsonc` 中的 D1、R2、DO、Assets 与路由意图不能为了消除配置漂移警告而随意删除。
- Workers 本地模拟器通过不等于生产路由通过；生产故障应优先检查部署版本和远程日志。
- 上游兼容合并必须先确认本地路由、数据模型和 Workers/DO 调用链是否适用，不能机械 cherry-pick Vaultwarden 原生实现。
- Turnstile 匿名 Send 门禁、Workers 架构和本地令牌设计可能构成有意的上游差异；除非完成行为级审计和真实客户端验证，不应声称“完全等同 Vaultwarden”。
- 历史上用户在后端同步任务中明确要求过 `static/**` 由其自行维护；只有任务再次包含该范围约束时才视为硬边界，不能擅自推广为所有任务的永久规则。
- 本机 PowerShell 显示中文异常时先用 `Get-Content -Encoding utf8` 复核，不要直接判定文件损坏。
- 本机访问 Cloudflare API 时可能需要显式设置 `HTTP_PROXY`、`HTTPS_PROXY` 与 `ALL_PROXY`；是否需要应按当次网络状态验证。

## 当前项目状态

- 分支/提交：`main`，当前 HEAD 为 `a5aa013`（“增强兼容性”），与 `origin/main` 一致。
- 当前工作树包含本次依赖升级对 `.github/workflows/push-cloudflare.yaml`、`Cargo.toml`、`Cargo.lock` 和 `memory.md` 的修改。
- 当前实现覆盖账户认证、密码库同步、Ciphers、Folders、附件、Send、导入、设备、2FA、WebAuthn、实时通知和动态 Vaultwarden CSS。
- 最近主要变化：
  - 将 worker-rs/worker-build 升级到 `0.8.5`、Wrangler 升级到 `4.111.0`，并刷新低风险直接依赖和完整锁文件。
  - 本机全局 Wrangler CLI 已从 `4.104.0` 升级到 `4.111.0`，与 GitHub Actions 固定版本一致。
  - 增加附件 API 与附件元数据迁移。
  - 加强新版 Bitwarden 客户端的 Cipher key、请求字段、序列化、revision 与通知兼容。
  - 引入 Wrangler 原生 D1 迁移基线，同时保留旧数据库兼容步骤。
- 当前没有在本次依赖升级中复现到本地测试、lint、Wasm 构建或 Wrangler dry-run 失败。
- 尚未验证：
  - 未部署到 Cloudflare，未检查远程 Worker 版本、绑定、D1/R2 实际状态或远程日志。
  - 未执行真实 Bitwarden Android/Desktop/Web 客户端端到端验证。
  - 未在本次依赖升级中重新做完整的上游 Vaultwarden 行为对等审计。

## 需求与修改记录

### 2026-07-17：使用 Memory 技能初始化仓库

#### 用户需求

使用 Memory 技能初始化当前 `warden-worker` 仓库。

#### 需求分析

- 仓库根目录此前不存在 `memory.md`。
- 初始化必须以当前代码、配置和测试为准，并保留已经验证且仍适用的项目历史约束。
- 只建立长期项目上下文，不修改业务逻辑、部署配置或数据库。

#### 修改内容

- 分析 README、Cargo/Wrangler 配置、JS/Rust 入口、Router、核心模块、D1 schema/迁移、GitHub Actions、测试和最近提交。
- 创建根目录 `memory.md`，记录项目结构、请求流、数据流、部署迁移规则、兼容性边界、当前状态和验证结果。

#### 涉及文件

- `memory.md`

#### 修改结果

仓库已建立可供后续任务读取和持续维护的项目级长期记忆。

#### 验证情况

- `cargo test`：通过，48 passed，0 failed。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `node --test tests/heavy_do_routing.test.mjs`：通过，3 passed，0 failed。
- `worker-build --release`：通过，生成 Wasm/JS 构建产物。
- `git diff --check`：通过。
- 未进行生产环境部署或真实客户端验证。

#### 特殊事项

- 本机验证工具版本为 Rust/Cargo `1.96.0`、Node.js `v24.18.0`、`worker-build 0.8.5`、Wrangler `4.104.0`；CI 使用上方固定版本，不能把本机版本误记为 CI 版本。

#### 遗留事项

- 无阻塞遗留项；后续每次项目任务完成后继续更新本文件。

### 2026-07-17：在不改变项目功能的前提下升级依赖

#### 用户需求

升级项目依赖包，同时保证现有项目功能不受影响。

#### 需求分析

- 优先更新 Cargo 当前兼容范围内的直接和传递依赖，并将 worker-rs、worker-build 与 Wrangler 对齐到当前稳定版本。
- 对 API 已保持兼容且能被现有测试覆盖的依赖采用新版本。
- `aes-gcm`、`sha2`、`hmac`、`pbkdf2`、`p256` 和 `rand` 的下一主版本涉及加密协议或随机数 API，未在本次一般依赖升级中跨主版本，避免产生无法由现有单元测试完全覆盖的行为变化。
- 不更新 `compatibility_date`，不新增兼容性 flag，不修改业务源码、数据库 schema、路由或静态资源。

#### 修改内容

- 将 `worker` 与 `worker-macros` 从 `0.8.1` 升级到 `0.8.5`。
- 将 `tower-http` 升级到 `0.7.0`、`base64` 升级到 `0.22.1`、`constant_time_eq` 升级到 `0.5.0`、`thiserror` 升级到 `2.0.18`。
- 提升 Axum、Serde、Chrono、UUID、TOTP、getrandom、日志及其他低风险直接依赖的最低版本。
- 运行 `cargo update`，刷新 `Cargo.lock` 中 worker-rs/Wasm 和其他兼容的传递依赖。
- 将 GitHub Actions 的 Wrangler 固定版本从 `4.73.0` 提升到 `4.111.0`，将 `worker-build` 从 `0.8.1` 提升到 `0.8.5`。

#### 涉及文件

- `Cargo.toml`
- `Cargo.lock`
- `.github/workflows/push-cloudflare.yaml`
- `memory.md`

#### 修改结果

项目现在使用 worker-rs/worker-build `0.8.5` 和 Wrangler `4.111.0`；Cargo 当前版本约束下已无可继续更新的包。升级未要求修改 Rust/JavaScript 业务源码。

#### 验证情况

- `cargo test`：通过，48 passed，0 failed。
- `cargo fmt --all -- --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `node --test tests/heavy_do_routing.test.mjs`：通过，3 passed，0 failed。
- `worker-build --release`（`0.8.5`）：通过。
- `npx --yes wrangler@4.111.0 deploy --dry-run`：通过；正确识别 D1、R2、两个 Durable Objects、两个 Rate Limiters、变量和 335 个静态资源，未部署远程资源。
- Turnstile 构建补丁检测到当前 v2 标记并保持 `static/web-vault/index.html` 不变。
- `cargo update --dry-run`：0 个可在当前约束下继续更新的包。
- `git diff --check`：通过，仅有 Windows 行尾转换提示。
- 未进行生产环境部署或真实客户端验证。

#### 特殊事项

- worker-rs 与 worker-build 应保持同一发布代际；Wasm 相关的 `wasm-bindgen`、`js-sys`、`web-sys` 和 `wasm-bindgen-futures` 也应作为一组核验。
- 后续若升级上述密码学/随机数依赖的下一主版本，应单独执行协议向量、旧数据读取、TOTP、WebAuthn 和真实客户端回归，不应混入普通补丁更新。

#### 遗留事项

- 无阻塞遗留项；密码学/随机数依赖的下一主版本可在具备更完整端到端测试时单独评估。

### 2026-07-17：同步升级本机 Wrangler 到 4.111.0

#### 用户需求

确认 Wrangler 最新版本为 `4.111.0`，并将其一并升级。

#### 需求分析

- GitHub Actions 的 `WRANGLER_VERSION` 已在上一任务中升级到 `4.111.0`。
- 本机全局 Wrangler 仍为 `4.104.0`，需要与项目 CI 版本对齐。
- 项目没有 `package.json`，无需为全局 CLI 升级额外引入 Node.js 项目依赖文件。

#### 修改内容

- 执行 `npm install -g wrangler@4.111.0`，升级本机全局 Wrangler。
- 核验 `.github/workflows/push-cloudflare.yaml` 继续固定使用 `4.111.0`。

#### 涉及文件

- `memory.md`
- `.github/workflows/push-cloudflare.yaml`（仅核验，版本修改已由上一任务完成）

#### 修改结果

本机全局 Wrangler 与 GitHub Actions 现在都使用 `4.111.0`，没有新增 `package.json`，也没有改变 Worker 配置或业务代码。

#### 验证情况

- `npm view wrangler version`：返回 `4.111.0`。
- `wrangler --version`：返回 `4.111.0`。
- 全局 `wrangler deploy --dry-run`：通过；release 构建成功，正确识别 D1、R2、两个 Durable Objects、两个 Rate Limiters、环境变量和 335 个静态资源。
- Turnstile 构建补丁检测到现有 v2 标记，没有修改 `static/web-vault/index.html`。
- 未部署远程资源。

#### 特殊事项

- npm 安装提示 `esbuild`、`workerd`、`sharp` 的安装脚本尚未列入 `allowScripts`；当前 Wrangler 版本检查和 dry-run 均已通过，因此本次未额外执行脚本授权。

#### 遗留事项

- 无。

## 待处理事项

- [ ] 涉及生产行为时，按任务需要补充远程部署版本、D1/R2/DO 绑定和真实客户端验证。
- [ ] 涉及上游同步时，重新按当前 Vaultwarden 提交窗口执行行为级兼容性审计。
- [ ] 可选：为密码学和随机数依赖的下一主版本补齐端到端兼容测试后再单独升级。

## 最近一次任务摘要

- 任务：将本机全局 Wrangler 与项目 CI 对齐到 `4.111.0`。
- 完成内容：全局 Wrangler 从 `4.104.0` 升级到 `4.111.0`；确认 CI 已固定为同一版本。
- 修改文件：`memory.md`；`.github/workflows/push-cloudflare.yaml` 仅核验。
- 验证结果：版本检查和全局 Wrangler dry-run 均通过，未部署远程资源。
- 下一步：无。
