# Git Conventions

This document provides repository origin, licensing, and workspace structure information for the sshwarden project.

## 1. Core Summary

This project is an extracted subset of the Bitwarden Desktop client from the `bitwarden/clients` monorepo (`https://github.com/bitwarden/clients.git`). It does not carry its own git history. The package is `@bitwarden/desktop` (version 2026.2.0), licensed under GPL-3.0. Commit conventions, branch strategy, and CI workflows should be referenced from the upstream monorepo.

## 2. Source of Truth

- **Origin Repository:** `https://github.com/bitwarden/clients.git` - The upstream Bitwarden clients monorepo containing browser, desktop, web, and CLI clients.
- **License:** GPL-3.0 - Declared in both `desktop/package.json:17` and `desktop/desktop_native/Cargo.toml:18`.
- **Package Identity:** `desktop/package.json` (`@bitwarden/desktop`) - Electron desktop application entry point.
- **Rust Workspace:** `desktop/desktop_native/Cargo.toml` - Workspace root for native Rust crates (resolver v2, edition 2021, `publish = false`).

## 3. Workspace Structure

| Layer | Path | Contents |
|---|---|---|
| Electron App | `desktop/` | Angular renderer, Electron main process, preload scripts, webpack configs |
| Rust Workspace | `desktop/desktop_native/` | 10 member crates: `core`, `napi`, `ssh_agent`, `proxy`, `process_isolation`, `autotype`, `autofill_provider`, `chromium_importer`, `bitwarden_chromium_import_helper`, `windows_plugin_authenticator` |

## 4. Upstream Reference

Since this project is extracted without git history, the following should be consulted from the upstream `bitwarden/clients` repository:

- **Commit message conventions** (conventional commits style used by Bitwarden)
- **Branch and PR workflow**
- **CI/CD pipeline configuration**
- **Contributing guidelines** (`CONTRIBUTING.md` in the monorepo root)
