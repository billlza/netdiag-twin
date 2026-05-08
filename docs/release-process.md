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
- GitHub Secrets 已配置完整。
- 本机能运行 Rust gates。
- Sparkle archive 已在 `vendor/Sparkle/`。
- 版本号遵循 SemVer，例如 `0.3.2`，tag 使用 `v0.3.2`。

Release workflow 需要这些 GitHub Secrets：

```text
CODESIGN_IDENTITY
NETDIAG_CODESIGN_P12_BASE64
NETDIAG_CODESIGN_P12_PASSWORD
NETDIAG_SPARKLE_PUBLIC_KEY
SPARKLE_PRIVATE_KEY
NETDIAG_NOTARY_PROFILE
NETDIAG_NOTARY_KEY_P8_BASE64
NETDIAG_NOTARY_KEY_ID
NETDIAG_NOTARY_ISSUER
HOMEBREW_TAP_TOKEN
```

如果缺任何一个 secret，release workflow 会 fail-fast，不会发布半成品。

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

发布前必须跑完这些命令：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTFLAGS="-D warnings" cargo test --workspace
python3 -m venv .venv-jsonschema
.venv-jsonschema/bin/python -m pip install 'jsonschema[format]==4.25.1'
.venv-jsonschema/bin/python -m py_compile scripts/validate_adapter_samples.py examples/adapters/*/*.py
.venv-jsonschema/bin/python scripts/validate_adapter_samples.py
scripts/check_perf_budget.sh
scripts/check_architecture_guard.sh
cargo run -p netdiag-cli -- benchmark run --artifacts target/benchmark-artifacts --output target/benchmark-report
git diff --check
bash -n scripts/*.sh
```

要求：

- 0 clippy warnings。
- 0 rustc warnings。
- 测试全通过。
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
git add Cargo.toml Cargo.lock README.md docs .github scripts crates examples perf-baseline.json
git commit -m "Release NetDiag Twin v<semver>"
```

如果本次只改文档，就只 stage 相关文档。不要为了方便把无关临时文件一起提交。

## 6. 创建 tag

tag 必须和 `Cargo.toml` 版本一致。

```bash
git tag -a "v<semver>" -m "NetDiag Twin v<semver>"
```

示例：

```bash
git tag -a "v0.3.2" -m "NetDiag Twin v0.3.2"
```

确认 tag 指向当前 commit：

```bash
git rev-parse HEAD
git rev-list -n 1 "v<semver>"
```

两个 SHA 必须一致。

## 7. 推送 main 和 tag

```bash
git push origin main
git push origin "v<semver>"
```

也可以一次推：

```bash
git push origin main "v<semver>"
```

推送 tag 后会自动触发 release workflow。

如果普通 `git push` 因网络被 reset，可以先不要做 destructive 修复。确认网络或 SSH/HTTPS 后重试。只有在明确需要时，才用 GitHub API 创建远端 ref，并在发布记录里说明本地 SHA 与远端 API commit SHA 的差异。

## 8. 监控 GitHub Actions

查看 release run：

```bash
gh run list --repo billlza/netdiag-twin --workflow Release --limit 5
gh run watch --repo billlza/netdiag-twin <run-id>
```

Release workflow 会依次执行：

1. 校验 tag 格式。
2. 校验 tag 版本与 `Cargo.toml` 一致。
3. 校验 secrets。
4. 跑 fmt/clippy/test/warnings/perf gates。
5. 准备临时 signing keychain。
6. 构建 signed DMG。
7. notarize + staple。
8. 验证 DMG、App、Gatekeeper。
9. 生成 Sparkle appcast。
10. 上传 GitHub Release assets。
11. 发布 GitHub Pages appcast。
12. 更新 Homebrew cask。

任何一步失败，都先看日志里的第一处失败原因。不要重新跑之前先改版本或删 tag。

## 9. 验证 GitHub Release

```bash
gh release view "v<semver>" \
  --repo billlza/netdiag-twin \
  --json tagName,name,isDraft,isPrerelease,assets,url
```

要求：

- `isDraft=false`
- `isPrerelease=false`
- assets 包含：
  - `NetDiag-Twin-<semver>.dmg`
  - `appcast.xml`

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

### 缺 GitHub Secrets

Release workflow 会在 `Validate secrets` 失败。补齐 secret 后，重新运行 workflow 或重新推 tag。

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
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTFLAGS="-D warnings" cargo test --workspace
scripts/check_perf_budget.sh
git diff --check
bash -n scripts/*.sh

git add Cargo.toml Cargo.lock README.md docs .github scripts crates examples perf-baseline.json
git commit -m "Release NetDiag Twin v<semver>"
git tag -a "v<semver>" -m "NetDiag Twin v<semver>"
git push origin main "v<semver>"

gh run list --repo billlza/netdiag-twin --workflow Release --limit 5
```

发布完成后：

```bash
gh release view "v<semver>" --repo billlza/netdiag-twin --json tagName,assets,url
curl -fsSL https://billlza.github.io/netdiag-twin/appcast.xml \
  | grep -E '<semver>|NetDiag-Twin-<semver>\\.dmg|sparkle:edSignature'
```
