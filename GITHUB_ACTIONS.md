# GitHub Actions 工作流说明

本项目使用 GitHub Actions 进行自动化构建、测试和发布。

## 工作流文件

### 1. Build and Test (`.github/workflows/build.yml`)

**触发条件**:
- 针对 `main` 分支的 Pull Request

**功能**:
- 在 Windows、Linux、macOS 三个平台上构建
- 运行所有测试
- 执行 Clippy 静态分析
- 检查代码格式
- 上传构建产物

**构建矩阵**:
```yaml
- Windows (x86_64-pc-windows-msvc)
- Linux (x86_64-unknown-linux-gnu)
- macOS (x86_64-apple-darwin)
```

**缓存策略**:
- Cargo registry
- Cargo git
- 构建目标目录

### 2. Release (`.github/workflows/release.yml`)

**触发条件**:
- 推送符合 `vMAJOR.MINOR.PATCH` 的 tag（例如 `v0.2.0`）

**功能**:
- 创建 GitHub Release
- 在三个平台上构建 release 版本
- 打包并上传发布文件
- 自动生成 release notes

**发布产物**:
- `sshwarden-{version}-windows-x64.zip`
- `sshwarden-{version}-linux-x64.tar.gz`
- `sshwarden-{version}-macos-x64.tar.gz`

## 使用指南

### 日常开发

每次创建或更新针对 `main` 分支的 Pull Request 时，会自动触发构建和测试：

```bash
git switch -c feature/my-change
git add .
git commit -m "feat: add new feature"
git push -u origin feature/my-change
```

然后在 GitHub 上创建指向 `main` 的 Pull Request。

查看构建状态：
- 访问 https://github.com/Hureru/SSHWarden/actions
- 或在 README 中查看徽章状态

### 发布新版本

发布版本只通过 Git tag 声明；不要为了发布去修改 `Cargo.toml`。仓库中的 Cargo 版本保持 `0.0.0-dev` 作为开发占位值，Release workflow 会从 `vX.Y.Z` tag 注入 `SSHWARDEN_VERSION`，构建出的二进制版本和产物名称都会使用 tag 版本。

1. **确认 main 已准备好发布**

```bash
git switch main
git pull --ff-only
cargo test --verbose
```

2. **创建并推送 tag**

```bash
VERSION=0.2.0

git tag -a "v$VERSION" -m "Release v$VERSION"
git push origin "v$VERSION"
```

3. **自动发布**

推送 tag 后，GitHub Actions 会自动：
- 校验 tag 是否符合 `vMAJOR.MINOR.PATCH` 格式
- 将 tag 版本注入 release 构建
- 在三个平台上构建 release 版本
- 创建 GitHub Release
- 上传带版本号的二进制压缩包

4. **编辑 Release Notes（可选）**

访问 https://github.com/Hureru/SSHWarden/releases，编辑自动创建的 release，添加更新日志。

### 版本号规范

遵循 [语义化版本](https://semver.org/lang/zh-CN/)：

- **主版本号 (MAJOR)**: 不兼容的 API 修改
- **次版本号 (MINOR)**: 向下兼容的功能性新增
- **修订号 (PATCH)**: 向下兼容的问题修正

示例：
- `v0.1.0` → `v0.1.1`: Bug 修复
- `v0.1.0` → `v0.2.0`: 新功能
- `v0.1.0` → `v1.0.0`: 重大变更

## 本地测试工作流

在推送前，可以本地运行相同的检查：

```bash
# 构建
cargo build --verbose

# 测试
cargo test --verbose

# Clippy
cargo clippy --all-targets --all-features -- -D warnings

# 格式检查
cargo fmt --all -- --check

# Release 构建
cargo build --release --verbose
```

## 故障排除

### 构建失败

1. **检查构建日志**
   - 访问 Actions 页面
   - 点击失败的工作流
   - 查看详细日志

2. **常见问题**

   **Windows 构建失败**:
   ```
   error: linking with `link.exe` failed
   ```
   解决: 确保 Windows SDK 已安装（GitHub Actions 已预装）

   **依赖下载失败**:
   ```
   error: failed to download from `https://...`
   ```
   解决: 通常是临时网络问题，重新运行工作流

   **测试失败**:
   ```
   test result: FAILED. 0 passed; 1 failed
   ```
   解决: 修复失败的测试，确保本地测试通过后再推送

### Release 失败

1. **Tag 已存在**
   ```
   error: tag 'v0.1.0' already exists
   ```
   解决: 删除旧 tag 或使用新版本号
   ```bash
   git tag -d v0.1.0
   git push origin :refs/tags/v0.1.0
   ```

2. **Tag 格式不符合发布规范**
   ```
   Release tags must use vMAJOR.MINOR.PATCH, for example v1.2.3
   ```
   解决: 使用 `vX.Y.Z` 格式重新创建 tag，例如 `v0.2.0`。

3. **权限问题**
   ```
   Error: Resource not accessible by integration
   ```
   解决: 检查仓库设置 → Actions → General → Workflow permissions
   确保选择 "Read and write permissions"

## 自定义工作流

### 添加新的构建目标

编辑 `.github/workflows/build.yml`，在 `matrix` 中添加：

```yaml
matrix:
  include:
    - os: windows-latest
      target: aarch64-pc-windows-msvc  # ARM64 Windows
      artifact_name: sshwarden.exe
```

### 修改 Release 触发条件

编辑 `.github/workflows/release.yml`:

```yaml
on:
  push:
    tags:
      - 'v*'           # 所有 v 开头的 tag
      - 'release-*'    # 或 release- 开头的 tag
```

### 添加部署步骤

在 release workflow 中添加：

```yaml
- name: Deploy to server
  run: |
    # 部署脚本
    scp sshwarden-*.zip user@server:/path/
```

## 徽章

在 README 中显示构建状态：

```markdown
[![Build and Test](https://github.com/Hureru/SSHWarden/actions/workflows/build.yml/badge.svg)](https://github.com/Hureru/SSHWarden/actions/workflows/build.yml)
[![Release](https://github.com/Hureru/SSHWarden/actions/workflows/release.yml/badge.svg)](https://github.com/Hureru/SSHWarden/actions/workflows/release.yml)
```

## 参考资源

- [GitHub Actions 文档](https://docs.github.com/en/actions)
- [Rust GitHub Actions](https://github.com/actions-rs)
- [语义化版本](https://semver.org/lang/zh-CN/)
