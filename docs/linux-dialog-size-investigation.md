# Linux 弹窗尺寸异常排查记录

## 问题描述

在 Linux (niri Wayland compositor) 上，SSHWarden 的授权弹窗（Auth/PIN 等所有 Slint 弹窗）显示为 800×600 逻辑像素，但内容只渲染在左上角 380×230 区域内，剩余空间为空黑色背景。Windows 上表现正常。

## 环境

- 系统: Linux 7.1.1-2-cachyos, Wayland
- WM: niri 26.04
- 显示器: 2560×1600, scale 1.5
- 已安装二进制: `~/Tools/SSHWarden/sshwarden` v0.2.1 (2026-06-05 构建)
- Slint: 1.15.1, Winit: 0.30.12
- Rust: 1.96.0 (via mise global)

## 根因已定位

通过 `WAYLAND_DEBUG=1` 对比 Wayland 协议消息，发现：

### 正常情况（独立的复现程序 repro_linux_dialog）

```
xdg_toplevel#35.set_min_size(380, 230)
xdg_toplevel#35.set_max_size(380, 230)
xdg_toplevel#35.set_title("SSHWarden - Authorization")
xdg_toplevel#35.set_app_id("repro_linux_dialog")
xdg_toplevel#35.configure(380, 230, ...)   ← compositor 尊重了尺寸
```

### 异常情况（daemon 进程弹窗）

```
xdg_toplevel#37.set_title("SSHWarden - Authorization")
xdg_toplevel#37.set_min_size(380, 230)    ← 先设了正确值
xdg_toplevel#37.set_max_size(380, 230)
xdg_toplevel#37.set_min_size(800, 600)    ← 紧接着被覆盖为 800×600！
xdg_toplevel#37.set_max_size(800, 600)
xdg_toplevel#37.configure(800, 600, ...)  ← compositor 按 800×600 配置
```

**关键发现：窗口的 min/max size 先被正确设为 380×230，然后立刻被第二次调用覆盖为 800×600。**

另外异常情况下 `set_app_id` 也从未被调用（App ID 为空）。

## 复现条件

- 用独立程序直接 `show_auth_dialog()` 再 `slint::run_event_loop()` → **正常 380×230**
- 用独立程序模拟 daemon 流程（先 `run_event_loop_until_quit()`，再通过 `invoke_from_event_loop` 弹窗）→ **也正常 380×230**
- 强制 femtovg 渲染器 `SLINT_BACKEND=winit-femtovg` 运行 repro → **复现 800×600 bug！**
- 不设 SLINT_BACKEND（默认 software）运行 repro → **正常 380×230**

所以复现条件是：**使用 femtovg (OpenGL/EGL) 渲染器时触发此 bug**。

然而安装的二进制即使设置 `SLINT_BACKEND=winit-software` 也依然 800×600，说明安装版可能在构建时硬编码了 femtovg 为唯一渲染器，或者有另一个因素在起作用。

## 还未完全确认的点

1. 800×600 的来源 —— 这是 winit 在 Wayland 上未指定 inner_size 时的默认值，但 Slint 代码确实设了 380×230。第二次 `set_min/max_size(800, 600)` 调用的来源需要在 Slint winit backend 源码中追踪。

2. **为什么 femtovg 触发但 software 不触发？** 两者走不同的 `resume()` 路径：
   - femtovg: `glcontext::OpenGLContext::new_context(window_attributes, ...)` — 可能在 GL context 创建时重新设置了窗口大小
   - software: 直接 `active_event_loop.create_window(window_attributes)`

3. App ID 为空 —— `xdg_app_id()` 返回 None 意味着 `SlintContext::set_xdg_app_id()` 从未被调用。独立程序通过 `slint::slint!{}` 宏编译的组件自动设置了二进制名作为 app_id，但 daemon 模式下可能遗漏了。

## 相关代码位置

- 弹窗 Slint 定义: `crates/sshwarden-ui/src/notify/slint_dialog.rs` (width: 380px, height: 230px)
- 窗口放置: `crates/sshwarden-ui/src/window_placement.rs`
- Slint 事件循环: `src/main.rs:460` (`run_slint_event_loop`)
- Slint winit backend 窗口创建: `~/.cargo/registry/.../i-slint-backend-winit-1.15.1/winitwindowadapter.rs:430` (`ensure_window`)
- Femtovg resume: `~/.cargo/registry/.../i-slint-backend-winit-1.15.1/renderer/femtovg.rs:54`
- 复现示例: `crates/sshwarden-ui/examples/repro_linux_dialog.rs`

## 建议下一步

1. **最直接的修复方向**：在 Slint winit backend 的 `ensure_window()` 中，窗口创建后有一段约束同步逻辑（`winitwindowadapter.rs:1285` 的 `set_min_inner_size` / `set_max_inner_size`），可能在 femtovg 路径下使用了错误的默认值（800×600）覆盖了正确的约束。需要在该位置打断点或 patch 验证。

2. **快速验证修复**：在 `show_auth_dialog()` 显示窗口后，显式调用 winit 的 `request_inner_size()` 强制设为 380×230，看是否绕过。

3. **升级 slint**：检查 slint 1.16+ 是否已修复此问题（可能是已知 bug）。

## 已排除的因素

| 假设 | 结论 |
|---|---|
| niri 平铺改变窗口大小 | ❌ 窗口是浮动的 |
| 代码/依赖版本差异 | ❌ 完全一致 |
| 环境变量差异 | ❌ 无关键差异 |
| Xwayland | ❌ 原生 Wayland |
| DPI/Scale 问题 | ❌ fractional_scale 正常报告 180(1.5x) |
