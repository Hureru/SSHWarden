# SSH 密钥内存保护机制

本文档描述 SSH Agent 保护内存中私钥材料的纵深防御策略，涵盖内存清零分配器、进程隔离、socket 权限控制和软锁定机制。

## 防御层次总览

1. **ZeroAlloc 全局分配器** -- 内存释放时自动清零
2. **进程隔离** -- 阻止外部进程读取内存
3. **Socket/Pipe 权限** -- 限制 IPC 通道访问
4. **软锁定** -- 密码库锁定时移除私钥材料
5. **process_isolation crate** -- Linux LD_PRELOAD 预加载库

---

## 1. ZeroAlloc 全局分配器

`desktop/desktop_native/core/src/lib.rs:17-18` 声明 `ZeroAlloc<std::alloc::System>` 为全局分配器。此分配器包装标准系统分配器，在每次 `dealloc` 时将释放的内存区域清零，确保 SSH 私钥等敏感数据不会残留在已释放的堆内存中。

## 2. 进程隔离（按平台）

进程隔离代码位于 `desktop/desktop_native/core/src/process_isolation/` 目录，通过条件编译选择平台实现。

### Linux

- `desktop/desktop_native/core/src/process_isolation/linux.rs` (`isolate_process`): 调用 `libc::prctl(PR_SET_DUMPABLE, 0)` 阻止任何其他进程（包括 root 和同用户进程）通过 ptrace 附加或读取 `/proc/<pid>/mem`。
- `desktop/desktop_native/core/src/process_isolation/linux.rs` (`disable_coredumps`): 调用 `libc::setrlimit(RLIMIT_CORE, 0)` 将核心转储大小限制设为零，防止崩溃时内存内容写入磁盘。

### Windows

- `desktop/desktop_native/core/src/process_isolation/windows.rs` (`isolate_process`): 使用 `secmem_proc::harden_process()` 修改进程 DACL（自主访问控制列表），限制其他进程访问本进程内存。核心转储禁用**未实现**。

### macOS

- `desktop/desktop_native/core/src/process_isolation/macos.rs` (`isolate_process`): 使用 `secmem_proc::harden_process()` 内部调用 `PT_DENY_ATTACH` 阻止调试器附加。核心转储禁用**未实现**。

## 3. process_isolation crate（Linux LD_PRELOAD 库）

- `desktop/desktop_native/process_isolation/src/lib.rs`: 编译为 `cdylib` 共享库，仅 Linux 平台。
- **`preload_init`（`#[ctor::ctor]`）:** 在共享库加载时自动执行，调用 `isolate_process()` + `disable_coredumps()`，在 `main()` 之前即生效。
- **`unsetenv` hook（`#[unsafe(no_mangle)]`）:** 拦截 libc `unsetenv` 调用。当 Flatpak/zypak 环境尝试 `unsetenv("LD_PRELOAD")` 时，从 `PROCESS_ISOLATION_LD_PRELOAD` 环境变量恢复原值，确保子进程继续被隔离。

## 4. Socket/Pipe 权限控制

- **Unix:** `desktop/desktop_native/core/src/ssh_agent/unix.rs` (`set_user_permissions`) 对 socket 文件设置 `0o600` 权限（仅 owner 可读写）。
- **Windows:** Named pipe (`\\.\pipe\openssh-ssh-agent`) 的访问由 OS 级 ACL 管理，代码中无显式权限设置。结合进程隔离的 DACL 加固共同保护。

## 5. 软锁定机制

- **Lock 操作:** `BitwardenDesktopAgent::lock()` 遍历 keystore，将每个 `BitwardenSshKey.private_key` 设为 `None`，私钥从内存移除。公钥条目保留（允许列出密钥身份）。参见 `desktop/desktop_native/core/src/ssh_agent/mod.rs:256-273`。
- **Clear 操作:** `clear_keys()` 完全清空 HashMap 并设置 `needs_unlock = true`。参见 `mod.rs:275-282`。
- **触发时机:** 密码库锁定时渲染进程调用 `lock()`；账户切换时调用 `clearKeys()`。
- 配合 ZeroAlloc 分配器，被 `None` 替换的旧 `PrivateKey` 值在 drop 后其内存区域会被自动清零。

## 6. 纵深防御总结

| 防御层 | 保护目标 | 实现位置 |
|--------|---------|---------|
| ZeroAlloc | 已释放内存中的密钥残留 | `core/src/lib.rs` |
| 进程隔离 | 运行时内存被外部进程读取 | `core/src/process_isolation/` |
| LD_PRELOAD 库 | Linux 子进程也受隔离保护 | `process_isolation/src/lib.rs` |
| Socket 权限 | IPC 通道未授权访问 | `core/src/ssh_agent/unix.rs` |
| 软锁定 | 密码库锁定后私钥可用性 | `core/src/ssh_agent/mod.rs` |
