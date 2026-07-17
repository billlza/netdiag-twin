# NetDiag Twin 更新版发布流程

这份流程用于发布新的 macOS 桌面版 NetDiag Twin。目标是让每次更新都走同一条链路：

1. 本地确认代码质量。
2. 升级版本号并提交。
3. 创建 `v<semver>` tag。
4. 由 GitHub Actions 构建 signed/notarized DMG。
5. 自动发布 GitHub Release、Sparkle appcast 和 Homebrew cask。
6. 用旧版 App 做一次 Sparkle 更新 smoke。

不要手动改 DMG、appcast 或 Homebrew cask。它们必须由 release workflow 生成。

## 0. 发布前条件

确认本机和 GitHub 仓库满足这些条件：

- 当前工作基于 `main`。
- 发布环境、审核规则和环境级 Secrets 已配置完整。
- 本机能运行 Rust gates。
- Sparkle archive 已在 `vendor/Sparkle/`。
- 仓库已启用 GitHub Immutable Releases。
- 版本号遵循 SemVer，例如 `0.3.2`，tag 使用 `v0.3.2`。
- 真实实验室设备证明当前为 `pending_lab_access` /
  `not_validated`。在拿到设备并生成 reviewed evidence manifest 前，不得把
  v0.5.3 描述为已通过 physical lab-device validation。

Release workflow 只接受 `v*` annotated tag 的 push，不提供手工触发入口。发布凭据必须按
用途存放在受保护的 GitHub Environments 中，不能保留仓库级副本：

- `release-signing`：限制为 `v*` tag，配置独立 required reviewer，并存放以下 Secrets：

```text
NETDIAG_CODESIGN_P12_BASE64
NETDIAG_CODESIGN_P12_PASSWORD
SPARKLE_PRIVATE_KEY
NETDIAG_NOTARY_KEY_P8_BASE64
```

  同一环境还需配置以下非敏感 Variables；不要把公开标识继续当成 Secret：

```text
CODESIGN_IDENTITY
NETDIAG_SPARKLE_PUBLIC_KEY
NETDIAG_NOTARY_PROFILE
NETDIAG_NOTARY_KEY_ID
NETDIAG_NOTARY_ISSUER
```

- `release-publication`：限制为 `v*` tag，配置独立 required reviewer；不存放长期凭据，
  只负责批准临时 `GITHUB_TOKEN` 的 Release 写入权限。
- `release-homebrew`：限制为 `v*` tag，配置独立 required reviewer，只存放：

```text
HOMEBREW_TAP_TOKEN
```

- `github-pages`：允许 `v*` tag 的部署，并由 Pages job 记录 deployment URL。

迁移时必须由凭据持有人把敏感值重新录入环境 Secrets，并把公开标识重新录入环境
Variables；GitHub API 只能列出 Secret 元数据，不能读取现有值。环境级设置验证无误后，
删除所有同名仓库级 Secret，避免其他 workflow 绕过环境审核读取凭据。不要先删仓库级
Secret：没有可恢复明文时会造成发布凭据永久丢失。

所有发布环境应启用 required reviewers、prevent self-review、禁止管理员绕过，并且只配置
一条 `v*` tag deployment policy。Release workflow 会在任何环境 job 启动前用只读 API
逐项验证这些规则。还必须用 ruleset 保护 `main` 和 `v*` tag，要求 PR、精确 CI checks、
禁止 force-push/删除，并限制 tag 创建者。没有独立 reviewer 时，不能把环境视为已保护，
也不得推送发布 tag。

可用以下只读命令核对环境与 Secret 名称（命令不会显示 Secret 值）：

```bash
gh api --header 'X-GitHub-Api-Version: 2026-03-10' \
  'repos/billlza/netdiag-twin/environments?per_page=100'
gh secret list --repo billlza/netdiag-twin --env release-signing
gh variable list --repo billlza/netdiag-twin --env release-signing
gh secret list --repo billlza/netdiag-twin --env release-homebrew
```

任何环境规则或所需 Secret 缺失时，release workflow 都会 fail-fast，不会发布半成品。

## 1. 拉取并确认状态

```bash
cd "/Users/bill/Desktop/NetDiag Twin"
git fetch origin --tags
git status --short --branch
```

要求：

- 没有意外的未提交文件。
- 本地 `main` 与远端同步，或你明确知道当前改动就是要发布的内容。

如果有未提交改动，先检查：

```bash
git diff --stat
git diff --check
```

不要用 `git reset --hard` 清理不确定的改动。先确认这些改动是否属于本次发布。

## 2. 升级版本号

使用脚本升级版本号，不要手动到处替换：

```bash
scripts/bump_version.sh <semver>
```

示例：

```bash
scripts/bump_version.sh 0.3.2
```

如果你正在一个已有改动的发布分支中准备版本号，允许 dirty tree：

```bash
scripts/bump_version.sh --allow-dirty 0.3.2
```

脚本会更新：

- `Cargo.toml`
- `Cargo.lock`
- `README.md`
- `docs/getting-started.md`
- `.github/workflows/release.yml` 中的示例版本

确认版本：

```bash
awk -F ' = ' '/^version =/ {gsub("\"", "", $2); print $2; exit}' Cargo.toml
```

## 3. 本地质量门禁

发布前必须跑完 strict gate。这个 gate 会固定使用并校验
`cargo-nextest`、`cargo-llvm-cov`、`cargo-deny` 和 `cargo-machete`，并且把
rustc/clippy/cargo-deny warning 当成发布阻断项：

```bash
python3 -m venv --clear --copies .venv-jsonschema
.venv-jsonschema/bin/python -m pip install --disable-pip-version-check --only-binary=:all: --require-hashes -r requirements-jsonschema.lock
scripts/check_rust_quality.sh strict
git diff --check
bash -n scripts/*.sh
```

要求：

- 0 clippy warnings。
- 0 rustc warnings。
- 0 cargo-deny warnings；新增 duplicate dependency 默认失败，现有 duplicate 必须在 `deny.toml` 中精确锁版本并写明原因。
- 测试全通过。
- v0.5 Pilot/CLI 发布关键面覆盖率至少 90%，measured core/CLI workspace
  覆盖率不能低于 ratchet floor。
- 桌面端凭据生命周期、密钥存储、API 测试状态和破坏性操作确认模块使用独立的
  lib+bin 插桩门禁：聚合覆盖率至少 80%，每个生产文件至少 50%；该结果不能抬高
  core/CLI/platform 覆盖率。
- `scripts/check_real_device_readiness.py` 通过；如果实验室设备不可用，状态必须保持
  `pending_lab_access` / `not_validated`，不能伪造验证通过。
- adapter sample 同时通过 JSON schema 与 Rust ingest 校验。
- 性能预算通过。
- 架构 guard 通过，避免继续扩大核心大文件。
- benchmark report 生成 `benchmark_report.json` 和 `benchmark_report.md`。
- shell 脚本语法检查通过。

如果任何一步失败，先修代码，不要跳过 gate。

## 4. 本地打包 smoke

本地 release smoke 不替代 GitHub release，但可以提前发现签名、Sparkle、Info.plist 问题。

```bash
CODESIGN_IDENTITY="Developer ID Application: <Name> (<TEAMID>)" \
NETDIAG_SPARKLE_PUBLIC_KEY="<sparkle-public-key>" \
NETDIAG_NOTARY_PROFILE="<notarytool-profile>" \
NETDIAG_NOTARIZE=1 \
scripts/package_macos_app.sh release
```

生成物：

```text
target/release/NetDiag Twin.app
target/release/NetDiag-Twin-<semver>.dmg
```

验证：

```bash
hdiutil verify "target/release/NetDiag-Twin-<semver>.dmg"
codesign --verify --deep --strict --verbose=2 "target/release/NetDiag Twin.app"
xcrun stapler validate "target/release/NetDiag-Twin-<semver>.dmg"
spctl --assess --type open --context context:primary-signature --verbose=4 "target/release/NetDiag-Twin-<semver>.dmg"
```

本地手动生成 appcast 时：

```bash
SPARKLE_PRIVATE_KEY="<sparkle-private-key>" \
scripts/generate_appcast.sh target/release
```

通常正式发布不需要手动生成 appcast，因为 GitHub Actions 会重新生成并上传。

## 5. 提交发布改动

检查变更：

```bash
git status --short
git diff --stat
```

提交：

```bash
git add Cargo.toml Cargo.lock .gitignore README.md docs .github scripts security crates examples third_party tools perf-baseline.json
git commit -m "Release NetDiag Twin v<semver>"
```

如果本次只改文档，就只 stage 相关文档。不要为了方便把无关临时文件一起提交。

## 6. 通过 PR 合并并验证 main

```bash
git push -u origin HEAD
gh pr create --fill --base main
gh pr checks --watch
```

按仓库 ruleset 合并 PR，不要直接 push `main`。合并后必须等待**该精确 main commit SHA**
的 push CI 完整成功；PR head 的结果不能替代 merge/main commit 的结果：

```bash
gh run list --repo billlza/netdiag-twin --workflow CI --branch main --limit 5
gh run watch --repo billlza/netdiag-twin <run-id>
```

确认 macOS strict、adapter、Ubuntu platform 和 `windows-2025` platform jobs 全部成功。
此时还不能依赖 PR head 的结果，也不能提前创建或推送 tag。

## 7. 创建并推送 tag

tag 必须是 annotated tag，和 `Cargo.toml` 版本一致，并精确指向刚刚通过 main push CI
的 commit：

```bash
git switch main
git pull --ff-only origin main
test "$(gh api \
  --header 'X-GitHub-Api-Version: 2026-03-10' \
  'repos/billlza/netdiag-twin/immutable-releases' \
  --jq '.enabled')" = "true"
git tag -a "v<semver>" -m "NetDiag Twin v<semver>"
test "$(git rev-parse HEAD)" = "$(git rev-list -n 1 "v<semver>")"
git push origin "v<semver>"
```

不可变发布设置的只读 API 需要仓库 `Administration: read`。GitHub Actions 的低权限
`GITHUB_TOKEN` 不能声明该权限，因此不要为了自动探测而给 release workflow 注入长期
管理员 PAT。由发布操作者用本地管理员身份在 tag 前执行上述检查；workflow 发布后还会
独立要求 `isImmutable=true`，并验证 Release 与每项资产的 attestation。若设置检查失败，
不得创建或推送 tag。

示例 tag：`v0.5.3`。

推送前再次确认 tag commit 仍是远端 main tip：

```bash
git fetch origin main
test "$(git rev-list -n 1 "v<semver>")" = "$(git rev-parse origin/main)"
```

禁止把 `main` 和 tag 一次推送。Release workflow 会再次运行原生平台门禁，并在进入
`release-signing` 环境前验证：tag 为 annotated tag、tag 指向精确的 `origin/main`、版本
一致，且 GitHub Actions API 中存在该 SHA 的成功 main push CI。任一条件不满足都会
fail-fast，不会上传半成品。同一版本的 tag push 和原 run 重跑共享一个不可取消的并发锁；如果
正式 Release 已存在，新的完整运行会在构建前失败。需要恢复部分失败的发布时，必须先
检查远端 Release 是否已创建，再决定是否重跑原 workflow run 的失败 job；不得删除或
覆盖已经对外可见的同名 Release。

如果普通 `git push` 因网络被 reset，可以先不要做 destructive 修复。确认网络或 SSH/HTTPS 后重试。只有在明确需要时，才用 GitHub API 创建远端 ref，并在发布记录里说明本地 SHA 与远端 API commit SHA 的差异。

## 8. 监控 GitHub Actions

查看 release run：

```bash
gh run list --repo billlza/netdiag-twin --workflow Release --limit 5
gh run watch --repo billlza/netdiag-twin <run-id>
```

Release workflow 会依次执行：

1. 校验 tag 格式。
2. 校验 annotated tag、精确 main SHA、成功 CI 和 `Cargo.toml` 版本。
3. 在 Linux 重新运行完整 platform/consumer 测试；Windows 编译并 lint 所有 consumer，
   原生运行全部 platform 测试和明确的 fail-before-write mutation contract。
4. 在无任何发布 secret 的独立 macOS compile job 中只 checkout 已验证的精确 SHA、安装
   固定 Rust 工具链、执行一次 `cargo build --locked --release`，再把“二进制 + 严格格式
   SHA-256 manifest”作为唯一两项 artifact 上传。完整 fmt/clippy/test/coverage/perf 门禁
   由第 2 步绑定的精确 main CI 提供。
5. 新的 macOS signing runner 再次只 checkout 精确 SHA，下载并验证 artifact 的精确文件
   集、manifest、源二进制与复制后二进制哈希。签名 job 禁止 Cargo 和工作树切换，从而
   隔离 build script 对环境、PATH、target 或工作树的副作用。该 job 必须先通过
   `release-signing` 环境审核，并且每个步骤只接收自己使用的环境级 Secret。
6. 对签名、公证和 Sparkle 密钥分别做显式非空校验；以私有权限准备临时 signing
   keychain，P12/P8 导入后立即删除原始文件。
7. 从校验和固定的 Sparkle archive 无条件重建 framework，再以 `--no-build` 模式打包
   sealed binary，构建 signed DMG，notarize + staple，并验证
   DMG、App、Gatekeeper。密钥可见窗口不再运行 Cargo、Python、Go 或 Homebrew。
8. 立即删除临时 signing keychain。
9. 生成并验证 Sparkle appcast 和 `SHA256SUMS`。
10. 通过只读 artifact 边界把签名构建与写权限发布 jobs 分离。
11. 通过 `release-publication` 环境审核后，使用 `gh release create --verify-tag` 原子创建
    GitHub Release；写入前再次确认同名 Release 不存在，不允许接管或覆盖现有资产。
12. 具备 `contents: read` 和 `attestations: read` 的独立只读 verifier 先要求
    `isImmutable=true`，再下载远端精确三项资产，验证 `SHA256SUMS` 并与构建 artifact
    逐字节比较，并用 GitHub release attestation 验证 Release 和每项资产。即使发布命令因
    响应丢失显示失败，只要 macOS 构建成功，verifier 仍会运行。
13. verifier 成功后发布 GitHub Pages appcast，并用 cache-busting 有界轮询，直到公开文件与
    已验证 artifact 逐字节一致。
14. verifier 成功后，在 `release-homebrew` 环境审核后审计并更新 Homebrew cask；公开
    tap checkout 使用只读 job token，Homebrew PAT 只在最终 push 步骤暴露。push 后重新读取
    远端 branch SHA，浅克隆该精确提交，并逐字节复验 cask。

任何一步失败，都先看日志里的第一处失败原因。不要重新跑之前先改版本或删 tag。

如果 `Publish GitHub Release` 失败，先检查服务端状态：

```bash
gh release view "v<semver>" \
  --repo billlza/netdiag-twin \
  --json tagName,isImmutable,isDraft,isPrerelease,assets,url
```

- Release 不存在：修复明确原因后，只重跑原 run 中失败的 jobs，复用原构建 artifact。
- Release 已存在：不要删除、重建或重跑写入 job；检查同一 run 的
  `Verify published GitHub Release`。它只有在 tag、正式状态、精确三项资产、校验和及
  逐字节内容全部匹配时才通过。若 verifier 本身是暂时性网络失败，可只重跑该 job。
- Release 存在但 verifier 不通过：停止发布 Pages/Homebrew，保留现场并处理真实差异，
  不得用覆盖上传制造通过。

## 9. 验证 GitHub Release

```bash
gh release view "v<semver>" \
  --repo billlza/netdiag-twin \
  --json tagName,name,isImmutable,isDraft,isPrerelease,assets,url
```

要求：

- `isImmutable=true`
- `isDraft=false`
- `isPrerelease=false`
- `gh release verify "v<semver>" --repo billlza/netdiag-twin` 通过
- assets 包含：
  - `NetDiag-Twin-<semver>.dmg`
  - `appcast.xml`
  - `SHA256SUMS`

## 10. 验证 Sparkle appcast

```bash
curl -fsSL https://billlza.github.io/netdiag-twin/appcast.xml \
  | grep -E '<semver>|NetDiag-Twin-<semver>\\.dmg|sparkle:edSignature|sparkle:version'
```

要求：

- appcast 包含新版本号。
- enclosure URL 指向 GitHub Release DMG。
- enclosure 有 `sparkle:edSignature`。
- `sparkle:version` 的 build number 大于旧版 App 的 `CFBundleVersion`。

检查已安装 App 的版本：

```bash
/usr/libexec/PlistBuddy \
  -c 'Print :CFBundleShortVersionString' \
  -c 'Print :CFBundleVersion' \
  "/Applications/NetDiag Twin.app/Contents/Info.plist"
```

## 11. 验证 Homebrew cask

```bash
gh api 'repos/billlza/homebrew-netdiag-twin/contents/Casks/netdiag-twin.rb?ref=main' \
  --jq '.content' | base64 -d
```

要求：

- `version "<semver>"`
- `sha256` 与 Release DMG 一致。
- URL 指向 `NetDiag-Twin-<semver>.dmg`。

可选本机 smoke：

```bash
brew update
brew info --cask billlza/netdiag-twin/netdiag-twin
```

不要在主力机器上盲目 `brew reinstall`，除非你准备覆盖当前 `/Applications/NetDiag Twin.app`。

## 12. Sparkle 旧版更新 smoke

这是验证“用户旧版能收到更新”的关键步骤。

先确认本机安装的是旧版，例如 `0.3.0`：

```bash
/usr/libexec/PlistBuddy \
  -c 'Print :CFBundleShortVersionString' \
  -c 'Print :CFBundleVersion' \
  "/Applications/NetDiag Twin.app/Contents/Info.plist"
```

打开旧版：

```bash
open -a "/Applications/NetDiag Twin.app"
```

在菜单栏执行：

```text
NetDiag Twin -> 检查更新...
```

期望行为：

- 出现 Sparkle 更新窗口，或出现 `Updating NetDiag Twin`。
- 下载并安装完成后 App 退出或重启。
- `/Applications/NetDiag Twin.app` 版本变为新版本。

验证更新后版本：

```bash
/usr/libexec/PlistBuddy \
  -c 'Print :CFBundleShortVersionString' \
  -c 'Print :CFBundleVersion' \
  "/Applications/NetDiag Twin.app/Contents/Info.plist"
```

验证签名和公证：

```bash
spctl --assess --type execute --verbose=4 "/Applications/NetDiag Twin.app"
codesign --verify --deep --strict --verbose=2 "/Applications/NetDiag Twin.app"
```

最后启动：

```bash
open -a "/Applications/NetDiag Twin.app"
```

## 13. 发布后记录

发布完成后记录这些信息：

- 版本号。
- local commit SHA。
- remote commit SHA。
- tag SHA。
- Release URL。
- Release workflow URL。
- DMG sha256。
- appcast URL。
- Homebrew tap commit。
- Sparkle old-version smoke 结果。

推荐格式：

```text
Version: v<semver>
Release: https://github.com/billlza/netdiag-twin/releases/tag/v<semver>
Workflow: https://github.com/billlza/netdiag-twin/actions/runs/<run-id>
DMG: NetDiag-Twin-<semver>.dmg
Sparkle: old <old-version>/<old-build> -> new <semver>/<new-build>
Gatekeeper: accepted
Codesign: valid
Homebrew: billlza/homebrew-netdiag-twin updated
```

## 14. 常见失败处理

### tag 版本和 Cargo 版本不一致

现象：

```text
tag version (...) does not match Cargo.toml workspace version (...)
```

处理：

1. 不要继续发布。
2. 删除错误 tag。
3. 修正版本号。
4. 重新跑 gates。
5. 重新创建 tag。

本地删除未推送 tag：

```bash
git tag -d "v<semver>"
```

已推送错误 tag 时，先确认没有 release asset 被用户使用，再处理：

```bash
git push origin ":refs/tags/v<semver>"
git tag -d "v<semver>"
```

### 发布环境或环境级 Secrets 缺失

不要重新推同名 tag。先确认失败 job 对应的 `release-signing`、`release-publication`、
`release-homebrew` 或 `github-pages` 环境已存在，允许 `v*` tag，required reviewer 已配置，
且所需 Secret 位于正确环境。补齐后只重跑原 workflow run 中失败的 job。若值只存在于
仓库级 Secret，必须由凭据持有人重新录入环境；不能通过 API 导出或复制明文。

### Notarization 失败

先看 `notarytool` 日志。常见原因：

- Developer ID 证书不匹配。
- `.p8` key、key id、issuer 不匹配。
- App 签名用了 ad-hoc 或非 hardened runtime。

不要发布未 notarized 的正式 DMG。

### Sparkle 点击检查更新无反应

按顺序检查：

1. App bundle 是否嵌入 `Sparkle.framework`。
2. `Info.plist` 是否有 `SUFeedURL`。
3. `Info.plist` 是否有正确 `SUPublicEDKey`。
4. Pages appcast 是否能访问。
5. appcast 是否有新版本且 `sparkle:version` 大于当前 `CFBundleVersion`。
6. appcast enclosure 是否有 `sparkle:edSignature`。

快速检查：

```bash
/usr/libexec/PlistBuddy \
  -c 'Print :SUFeedURL' \
  -c 'Print :SUPublicEDKey' \
  "/Applications/NetDiag Twin.app/Contents/Info.plist"

curl -fsSL https://billlza.github.io/netdiag-twin/appcast.xml
```

### Homebrew cask 没更新

检查 release workflow 的 `Publish Homebrew cask` 步骤。如果 workflow 成功但本机看不到更新，先运行：

```bash
brew update
brew tap --repair
```

然后重新查：

```bash
brew info --cask billlza/netdiag-twin/netdiag-twin
```

## 15. 最小命令清单

发布者最常用的完整命令如下：

```bash
cd "/Users/bill/Desktop/NetDiag Twin"
git fetch origin --tags
git status --short --branch

scripts/bump_version.sh <semver>

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
RUSTFLAGS="-D warnings" cargo test --locked --workspace
scripts/check_perf_budget.sh
git diff --check
bash -n scripts/*.sh
actionlint .github/workflows/*.yml

git add Cargo.toml Cargo.lock .gitignore README.md docs .github scripts security crates examples third_party tools perf-baseline.json
git commit -m "Release NetDiag Twin v<semver>"
git push -u origin HEAD
gh pr create --fill --base main
gh pr checks --watch
# 按仓库既定合并策略合并 PR；不要直接 push main。

git switch main
git pull --ff-only origin main

gh run list --repo billlza/netdiag-twin --workflow CI --branch main --limit 5
gh run watch --repo billlza/netdiag-twin <ci-run-id>

git tag -a "v<semver>" -m "NetDiag Twin v<semver>"
test "$(git rev-list -n 1 "v<semver>")" = "$(git rev-parse origin/main)"
git push origin "v<semver>"

gh run list --repo billlza/netdiag-twin --workflow Release --limit 5
```

发布完成后：

```bash
gh release view "v<semver>" --repo billlza/netdiag-twin --json tagName,assets,url
curl -fsSL https://billlza.github.io/netdiag-twin/appcast.xml \
  | grep -E '<semver>|NetDiag-Twin-<semver>\\.dmg|sparkle:edSignature'
```
