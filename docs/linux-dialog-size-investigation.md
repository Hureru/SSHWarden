# Linux 弹窗尺寸异常排查记录

## 问题描述

在 Linux (niri Wayland compositor) 上，SSHWarden 的授权弹窗（Auth/PIN 等所有 Slint 弹窗）显示为 800×600 逻辑像素，但内容只渲染在左上角 380×230 区域内，剩余空间为空黑色背景。Windows 上表现正常。

## 环境

- 系统: Linux 7.1.1-2-cachyos, Wayland
- WM: niri 26.04
- 显示器: 2560×1600, scale 1.5
- Slint: 1.15.1, Winit: 0.30.12
- Rust: 1.96.0 (via mise global)

## 出现条件

这个问题只在 **winit 后端** 下出现，因此取决于构建时启用了哪些 Slint 后端：

- 启用 `backend-default`（含 Qt 后端）的构建：Slint 后端选择顺序是 Qt → winit，Qt 后端不会创建 winit 窗口，**没有此 bug**。
- 只启用 `backend-winit` 的构建（`86d1bdc` 裁剪 feature 之后）：走 winit，**出现此 bug**。

两个渲染器（femtovg / software）都走同一条 `winit::Window::new` + `set_resizable` 代码路径，所以这个 bug 与渲染器无关。

## 根因（已确认，源码级）

Slint 在 `show()` 里才惰性创建 winit 窗口（`i-slint-backend-winit/winitwindowadapter.rs` 的 `ensure_window()`），它交给 winit 的 `WindowAttributes` 里 `inner_size == None`，但同时带上了：

- `min_inner_size` / `max_inner_size` = 组件的 380×230
- `resizable = false`（组件宽高固定 ⇒ Slint 的 `window_is_resizable()` 返回 false）

winit 的 Wayland 实现于是这样处理（`winit-0.30.12`）：

```rust
// src/platform_impl/linux/wayland/window/mod.rs:97
let size: Size = attributes.inner_size.unwrap_or(LogicalSize::new(800., 600.).into()); // ← 默认值
...
window_state.set_min_inner_size(min_size);            // 380×230 ✓
window_state.set_max_inner_size(max_size);            // 380×230 ✓
window_state.set_resizable(attributes.resizable);     // false
```

```rust
// src/platform_impl/linux/wayland/window/state.rs:503
pub fn set_resizable(&mut self, resizable: bool) -> bool {
    ...
    if resizable {
        self.reload_min_max_hints();
    } else {
        self.set_min_inner_size(Some(self.size));   // ← self.size 是 800×600，覆盖 min
        self.set_max_inner_size(Some(self.size));   // ← 覆盖 max
    }
```

即：因为窗口创建时没有显式 inner size，winit 回退到 800×600；又因为窗口是“不可缩放”的，winit 把 min 和 max 都钉成当前尺寸（800×600），把 Slint 刚设好的 380×230 约束覆盖掉。最终 niri 按 800×600 configure 窗口，而 Slint 的内容仍按 380×230 布局，于是内容缩在左上角。

这与 `WAYLAND_DEBUG=1` 抓到的消息序列完全吻合：

```
xdg_toplevel#37.set_min_size(380, 230)    ← Slint 的正确约束
xdg_toplevel#37.set_max_size(380, 230)
xdg_toplevel#37.set_min_size(800, 600)    ← 被 winit 的 set_resizable(false) 覆盖
xdg_toplevel#37.set_max_size(800, 600)
xdg_toplevel#37.configure(800, 600, ...)  ← compositor 按 800×600 配置
```

## 修复

`crates/sshwarden-ui/src/window_placement.rs` 新增 `declare_fixed_size()`，并在三个弹窗调用 `dialog.show()` **之前** 调用它，把组件的逻辑尺寸显式写进窗口：

```rust
// 必须在 show() 之前调用
crate::window_placement::declare_fixed_size(dialog.window(), 380.0, 230.0);
```

`Window::set_size()` 在窗口尚未创建时会走到 `WinitWindowOrNone::None(attributes)` 分支，把尺寸写入 `attributes.inner_size` 并标记 `has_explicit_size`。这样：

1. winit 创建窗口时不再回退到 800×600，而是用 380×230；
2. `set_resizable(false)` 钉住的 min/max 因此是 380×230（与 Slint 的约束一致）；
3. `has_explicit_size` 为真，`set_visible()` 里“按 preferred size 自动 resize”那步被跳过。

三个弹窗的尺寸：

| 弹窗 | 逻辑尺寸 |
|---|---|
| `notify`（授权） | 380 × 230 |
| `unlock`（PIN） | 380 × 195 |
| `bind_hosts`（绑定主机） | 640 × 440 |

替代方案：恢复 Qt 后端（`Cargo.toml` 里加回 `backend-qt`）。行为 100% 回到从前，但二进制大 ~2.3 MB 且运行时依赖 Qt6。

## 验证

```bash
cargo build --release -p sshwarden-ui --example repro_linux_dialog
./target/release/examples/repro_linux_dialog &   # 触发一次授权弹窗
niri msg --json windows | jq '.[] | select(.app_id | test("sshwarden"; "i")) | .window_size'
```

期望 `window_size == [380, 230]`（修复前为 `[800, 600]`）。

## 备注：App ID 为空

daemon 模式下 `xdg_app_id()` 曾返回 `None`，即 `SlintContext::set_xdg_app_id()` 未被调用。这与尺寸 bug 无关，单独跟踪。
