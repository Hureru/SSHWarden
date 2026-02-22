# Coding Conventions

This document provides a high-level summary of the enforced coding standards across the Rust native layer and the Electron/TypeScript application layer.

## 1. Core Summary

The project enforces strict Clippy lints (deny on `unwrap_used`, `unused_async`, `print_stdout`, `print_stderr`, `disallowed-macros`), mandates `tracing` over the `log` crate, pins all dependency versions to exact semver (`=x.y.z`), and requires strict Electron main/renderer process separation with IPC-based communication.

## 2. Source of Truth

### Rust Lints and Formatting

- **Workspace Lints:** `desktop/desktop_native/Cargo.toml:87-97` - Defines workspace-level Clippy rules: `unwrap_used = "deny"`, `unused_async = "deny"`, `print_stdout = "deny"`, `print_stderr = "deny"`, `disallowed-macros = "deny"`, `string_slice = "warn"`.
- **Clippy Config:** `desktop/desktop_native/clippy.toml` - Disallows all `log::*` macros, requiring `tracing::*` replacements. Permits `unwrap`/`expect` in test code only.
- **Rustfmt Config:** `desktop/desktop_native/rustfmt.toml` - Comment width 100, `wrap_comments = true`, imports grouped by `StdExternalCrate` with crate-level granularity.
- **Cargo Deny:** `desktop/desktop_native/deny.toml` - Enforces license allowlist (MIT, Apache-2.0, BSD, etc.), flags unmaintained crates at workspace level, planned ban on `log` crate.

### Key Rust Rules

- **No `unwrap()`/`expect()` in production code.** Use `anyhow::Result` or `thiserror` for error propagation.
- **No `println!`/`eprintln!`.** Use `tracing::{trace, debug, info, warn, error}` for all observability.
- **No `log` crate macros.** The `log::*` family is disallowed via Clippy; use `tracing::*` instead.
- **No unused async.** Functions marked `async` must actually await something.
- **Pinned dependencies.** All workspace dependencies use exact version pins (`=x.y.z`).

### NAPI Layer Pattern

- **NAPI Crate:** `desktop/desktop_native/napi/` - Thin FFI wrappers only. Depends on `desktop_core` for all business logic.
- **Core Crate:** `desktop/desktop_native/core/` - Contains all platform-specific logic, SSH agent implementation, and crypto operations.
- **Rule:** Never place business logic in the `napi` crate; it should only marshal types between JS and Rust.

### Electron Architecture

- **Process Separation:** `desktop/CLAUDE.md` - Main process (`src/main/`) uses Node.js + Electron APIs; renderer process runs the Angular app in a browser-like sandbox.
- **IPC Required:** Cross-process communication must go through Electron IPC. Never import Node.js modules in the renderer.
- **Preload Scripts:** See `desktop/src/*/preload.ts` files for the bridge pattern between main and renderer.

### TypeScript

- **Config Files:** `desktop/tsconfig.json`, `desktop/tsconfig.main.json`, `desktop/tsconfig.preload.json`, `desktop/tsconfig.renderer.json` - Separate TypeScript configurations for each Electron process context.
- **No ESLint/Prettier found locally** - Linting configuration is likely inherited from the parent Bitwarden clients monorepo.
