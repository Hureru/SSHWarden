# SSHWarden 构建指南

## 开发环境要求

### 必需工具

- **Rust**: 1.70 或更高版本
  ```bash
  # 安装 Rust
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

  # 或在 Windows 上使用 rustup-init.exe
  # https://rustup.rs/
  ```

- **Windows SDK** (仅 Windows):
  - Windows 10 SDK 或更高版本
  - 用于 WinRT API（Toast 通知、Windows Hello）

### 可选工具

- **cargo-edit**: 管理依赖
  ```bash
  cargo install cargo-edit
  ```

- **cargo-watch**: 自动重新编译
  ```bash
  cargo install cargo-watch
  ```

## 构建步骤

### 1. 克隆仓库

```bash
git clone git@github.com:Hureru/SSHWarden.git
cd SSHWarden
```

### 2. 开发构建

```bash
# 构建所有 crate
cargo build

# 运行（开发模式）
cargo run -- run

# 运行特定命令
cargo run -- status
cargo run -- lock
cargo run -- unlock --method hello
```

### 3. Release 构建

```bash
# 构建优化的 release 版本
cargo build --release

# 输出位置
# Windows: target/release/sshwarden.exe
# Unix: target/release/sshwarden
```

### 4. 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定 crate 的测试
cargo test -p sshwarden-agent
cargo test -p sshwarden-api
```

### 5. 代码检查

```bash
# Clippy 静态分析
cargo clippy --all-targets --all-features

# 格式化检查
cargo fmt --check

# 自动格式化
cargo fmt
```

## Release 打包

### Windows

#### 方法 1: 手动打包

```bash
# 1. 构建 release 版本
cargo build --release

# 2. 创建发布目录
mkdir release
cd release

# 3. 复制可执行文件
cp ../target/release/sshwarden.exe .

# 4. 复制配置文件示例
cp ../config.toml.example .

# 5. 创建 README
cp ../README.md .

# 6. 打包为 zip
# 使用 7-Zip 或 Windows 资源管理器压缩
```

#### 方法 2: 使用脚本

创建 `scripts/package-windows.ps1`:

```powershell
# 读取发布版本：CI 设置 SSHWARDEN_VERSION，本地发布可在 vX.Y.Z tag 上运行
if ($env:SSHWARDEN_VERSION) {
    $version = $env:SSHWARDEN_VERSION
} else {
    $tag = git describe --tags --exact-match --match "v[0-9]*"
    if ($LASTEXITCODE -ne 0) {
        throw "Set SSHWARDEN_VERSION or run this script from a vX.Y.Z tag"
    }
    $version = $tag.Trim() -replace '^v', ''
}

# 构建 release；build.rs 会把版本注入二进制
$env:SSHWARDEN_VERSION = $version
cargo build --release

# 创建发布目录
$releaseDir = "release-package"
New-Item -ItemType Directory -Force -Path $releaseDir

# 复制文件
Copy-Item "target\release\sshwarden.exe" -Destination $releaseDir
Copy-Item "config.toml.example" -Destination $releaseDir
Copy-Item "README.md" -Destination $releaseDir
Copy-Item "LICENSE" -Destination $releaseDir -ErrorAction SilentlyContinue

# 创建 zip
$zipName = "sshwarden-$version-windows-x64.zip"
Compress-Archive -Path "$releaseDir\*" -DestinationPath $zipName -Force

Write-Host "Release package created: $zipName"
```

运行脚本:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/package-windows.ps1
```

### Unix/Linux

创建 `scripts/package-unix.sh`:

```bash
#!/bin/bash
set -e

# 读取发布版本：CI 设置 SSHWARDEN_VERSION，本地发布可在 vX.Y.Z tag 上运行
VERSION="${SSHWARDEN_VERSION:-}"
if [ -z "$VERSION" ]; then
    TAG=$(git describe --tags --exact-match --match 'v[0-9]*')
    VERSION="${TAG#v}"
fi
export SSHWARDEN_VERSION="$VERSION"

# 构建 release；build.rs 会把版本注入二进制
cargo build --release

# 创建发布目录
RELEASE_DIR="release-package"
mkdir -p "$RELEASE_DIR"

# 复制文件
cp target/release/sshwarden "$RELEASE_DIR/"
cp config.toml.example "$RELEASE_DIR/"
cp README.md "$RELEASE_DIR/"
[ -f LICENSE ] && cp LICENSE "$RELEASE_DIR/"

# 设置可执行权限
chmod +x "$RELEASE_DIR/sshwarden"

# 创建 tar.gz
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
TAR_NAME="sshwarden-$VERSION-$PLATFORM-$ARCH.tar.gz"

tar -czf "$TAR_NAME" -C "$RELEASE_DIR" .

echo "Release package created: $TAR_NAME"
```

运行脚本:
```bash
chmod +x scripts/package-unix.sh
./scripts/package-unix.sh
```

## 优化选项

### Cargo.toml 优化配置

在根目录 `Cargo.toml` 中添加:

```toml
[profile.release]
# 优化级别（0-3，s=size，z=size aggressive）
opt-level = 3

# 链接时优化（LTO）
lto = true

# 代码生成单元（减少以提高优化）
codegen-units = 1

# 去除调试符号
strip = true

# 减小二进制大小
panic = "abort"
```

### 构建更小的二进制文件

```bash
# 使用 upx 压缩（可选）
# 安装 upx: https://upx.github.io/
cargo build --release
upx --best --lzma target/release/sshwarden.exe
```

## 交叉编译

### Windows 上编译 Linux 版本

```bash
# 安装目标
rustup target add x86_64-unknown-linux-gnu

# 安装交叉编译工具链
# 需要 WSL 或 MinGW

# 构建
cargo build --release --target x86_64-unknown-linux-gnu
```

### Linux 上编译 Windows 版本

```bash
# 安装目标
rustup target add x86_64-pc-windows-gnu

# 安装 MinGW
sudo apt-get install mingw-w64

# 构建
cargo build --release --target x86_64-pc-windows-gnu
```

## 持续集成 (CI)

### GitHub Actions 发布

仓库中的 `.github/workflows/release.yml` 已配置 tag 发布：

- 只响应 `vMAJOR.MINOR.PATCH` 格式的 tag，例如 `v0.2.0`。
- workflow 从 tag 解析版本，并在 release 构建中设置 `SSHWARDEN_VERSION`。
- `build.rs` 会把该版本注入二进制的 `--version` 输出和 Windows 文件版本信息。
- 发布包名使用 `sshwarden-{version}-{platform}-{arch}` 格式。

发布时不要修改 `Cargo.toml` 里的版本；创建并推送 tag 即可触发发布：

```bash
VERSION=0.2.0
git tag -a "v$VERSION" -m "Release v$VERSION"
git push origin "v$VERSION"
```

## 故障排除

### Windows 构建问题

**问题**: 找不到 Windows SDK
```
解决: 安装 Visual Studio Build Tools 或完整的 Visual Studio
```

**问题**: WinRT 链接错误
```
解决: 确保安装了 Windows 10 SDK 10.0.17763.0 或更高版本
```

### 依赖问题

**问题**: 无法编译 bitwarden-russh
```bash
# 清理并重新构建
cargo clean
cargo build --release
```

**问题**: OpenSSL 相关错误（Unix）
```bash
# Ubuntu/Debian
sudo apt-get install pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install pkgconfig openssl-devel

# macOS
brew install openssl
```

## 性能分析

```bash
# 生成性能分析数据
cargo build --release --profile release-with-debug
perf record -g target/release/sshwarden run
perf report

# 或使用 flamegraph
cargo install flamegraph
cargo flamegraph -- daemon
```

## 文档生成

```bash
# 生成 API 文档
cargo doc --no-deps --open

# 生成所有 crate 的文档
cargo doc --workspace --no-deps --open
```
