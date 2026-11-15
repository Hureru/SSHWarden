//! Agent-side key selection: which identities one connection is offered, and
//! in what order (ADR 0027).
//!
//! Selection only reorders (or, for an explicit pick, narrows) the list. It is
//! never an authorization decision: the inputs include the client's argv, which
//! any local process can forge.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sshwarden_agent::{ListSelection, OperationKind, SshAgentListRequest, SshAgentUIRequest};
use sshwarden_config::bindings::HostBindingsFile;
use sshwarden_config::SelectionRule;
use tracing::info;

use crate::path_util::write_private_file;
use crate::runtime::UIRequestTx;
use crate::ssh_target::{invocation_for_pid, SshInvocation};

/// Recently used keys remembered per context, newest first.
const HISTORY_KEYS_PER_CONTEXT: usize = 3;
/// How long a pick is reused for parallel connections to the same context.
const PICK_REUSE: std::time::Duration = std::time::Duration::from_secs(30);
/// Below sshd's default `LoginGraceTime` (120s), which bounds the whole login.
const PICKER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(100);

/// What is known about the connection a key is being chosen for.
#[derive(Debug, Default)]
struct SelectContext {
    host: Option<String>,
    user: Option<String>,
    repo: Option<String>,
    /// SHA-256 of the session-bound host key (OpenSSH >= 8.9 clients only).
    host_key_fp: Option<String>,
}

impl SelectContext {
    fn new(invocation: Option<SshInvocation>, host_key: &[u8]) -> Self {
        let (host, user, repo) = match invocation {
            Some(inv) => (Some(inv.host), inv.user, inv.repo),
            None => (None, None, None),
        };
        Self {
            host,
            user,
            repo,
            host_key_fp: (!host_key.is_empty()).then(|| {
                format!(
                    "SHA256:{}",
                    STANDARD_NO_PAD.encode(Sha256::digest(host_key))
                )
            }),
        }
    }

    /// The local client's argv describes the first hop, so it says nothing
    /// about a forwarded connection; only the bound host key does.
    fn for_peer(pid: u32, is_forwarding: bool, host_key: &[u8]) -> Self {
        let invocation = if is_forwarding {
            None
        } else {
            invocation_for_pid(pid)
        };
        Self::new(invocation, host_key)
    }

    /// History bucket: the server, split by repository owner so two accounts
    /// on one Git host learn separate keys (a heuristic: the first path segment).
    fn history_key(&self) -> Option<String> {
        let server = match (&self.host_key_fp, &self.host) {
            (Some(fp), _) => fp.clone(),
            (None, Some(host)) => format!("host:{}", host.to_ascii_lowercase()),
            (None, None) => return None,
        };
        let owner = self.repo.as_deref().and_then(|repo| repo.split('/').next());
        Some(format!("{server}|{}", owner.unwrap_or("")))
    }

    fn describe(&self) -> String {
        let server = self
            .host
            .clone()
            .or_else(|| self.host_key_fp.clone())
            .unwrap_or_else(|| "unknown host".to_string());
        match &self.repo {
            Some(repo) => format!("{server} ({repo})"),
            None => server,
        }
    }
}

/// Where a login request is going, for the authorization prompt. Display only:
/// it comes from the client's command line. `None` for anything but a login.
pub(crate) fn describe_target(request: &SshAgentUIRequest) -> Option<String> {
    (request.operation_kind == OperationKind::SshAuthentication).then(|| {
        SelectContext::for_peer(request.pid, request.is_forwarding, &request.host_key).describe()
    })
}

/// `*` and `?` glob match, ASCII case-insensitive.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            backtrack = Some((pi, ti));
            pi += 1;
        } else if let Some((star, matched)) = backtrack {
            backtrack = Some((star, matched + 1));
            pi = star + 1;
            ti = matched + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// OpenSSH `Host` semantics: some pattern matches and no `!pattern` does.
fn host_patterns_match<'a>(patterns: impl IntoIterator<Item = &'a str>, host: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        match pattern.strip_prefix('!') {
            Some(negated) if glob_match(negated, host) => return false,
            Some(_) => {}
            None => matched |= glob_match(pattern, host),
        }
    }
    matched
}

fn rule_matches(rule: &SelectionRule, ctx: &SelectContext) -> bool {
    fn holds(want: Option<&str>, have: Option<&str>, test: impl Fn(&str, &str) -> bool) -> bool {
        match (want, have) {
            (None, _) => true,
            (Some(want), Some(have)) => test(want, have),
            (Some(_), None) => false,
        }
    }
    // A rule that names neither a host nor a repository would match everything.
    (rule.host.is_some() || rule.repo.is_some())
        && holds(rule.host.as_deref(), ctx.host.as_deref(), |want, have| {
            host_patterns_match(want.split_whitespace(), have)
        })
        && holds(rule.user.as_deref(), ctx.user.as_deref(), |want, have| {
            want == have
        })
        && holds(rule.repo.as_deref(), ctx.repo.as_deref(), glob_match)
}

/// Resolve a rule's `key` (vault item id, or a unique display name).
fn resolve_key<'a>(query: &str, keys: &'a [(String, String)]) -> Option<&'a str> {
    if let Some((id, _)) = keys.iter().find(|(id, _)| id == query) {
        return Some(id);
    }
    let mut by_name = keys
        .iter()
        .filter(|(_, name)| name.eq_ignore_ascii_case(query));
    match (by_name.next(), by_name.next()) {
        (Some((id, _)), None) => Some(id),
        _ => None,
    }
}

/// Keys to offer first, best first, and where the best one came from.
fn preferred(
    ctx: &SelectContext,
    rules: &[SelectionRule],
    bindings: &HostBindingsFile,
    history: &KeyHistory,
    keys: &[(String, String)],
) -> (Vec<String>, &'static str) {
    let mut found: Vec<(String, &'static str)> = Vec::new();

    if let Some(rule) = rules.iter().find(|rule| rule_matches(rule, ctx)) {
        match resolve_key(&rule.key, keys) {
            Some(id) => found.push((id.to_string(), "rule")),
            None => tracing::warn!(key = %rule.key, "Selection rule names no unique SSH key"),
        }
    }
    if let Some(host) = &ctx.host {
        for (id, binding) in &bindings.bindings {
            if host_patterns_match(binding.hosts.iter().map(String::as_str), host) {
                found.push((id.clone(), "binding"));
            }
        }
    }
    if let Some(recent) = ctx.history_key().and_then(|key| history.entries.get(&key)) {
        found.extend(recent.iter().map(|id| (id.clone(), "history")));
    }

    // Deleted keys may linger in bindings and history; keep only listable ones.
    let mut kept: Vec<(String, &'static str)> = Vec::new();
    for (id, source) in found {
        if keys.iter().any(|(known, _)| *known == id) && !kept.iter().any(|(k, _)| *k == id) {
            kept.push((id, source));
        }
    }
    let reason = kept.first().map_or("none", |(_, source)| source);
    (kept.into_iter().map(|(id, _)| id).collect(), reason)
}

/// `preferred` first, then every other key in a stable name order.
fn order(preferred: Vec<String>, keys: &[(String, String)]) -> Vec<String> {
    let mut rest: Vec<&(String, String)> = keys
        .iter()
        .filter(|(id, _)| !preferred.contains(id))
        .collect();
    rest.sort_by_key(|(id, name)| (name.to_lowercase(), id.clone()));
    let mut ids = preferred;
    ids.extend(rest.into_iter().map(|(id, _)| id.clone()));
    ids
}

/// Which key each server last accepted, learned from signing requests.
#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyHistory {
    #[serde(default)]
    entries: BTreeMap<String, Vec<String>>,
}

impl KeyHistory {
    /// Move `cipher_id` to the front of `context`; `false` if already there.
    fn record(&mut self, context: String, cipher_id: &str) -> bool {
        let recent = self.entries.entry(context).or_default();
        if recent.first().map(String::as_str) == Some(cipher_id) {
            return false;
        }
        recent.retain(|id| id != cipher_id);
        recent.insert(0, cipher_id.to_string());
        recent.truncate(HISTORY_KEYS_PER_CONTEXT);
        true
    }
}

/// Daemon-wide key selection state.
pub(crate) struct KeySelector {
    rules: Vec<SelectionRule>,
    picker_enabled: bool,
    history: std::sync::Mutex<KeyHistory>,
    history_path: Option<PathBuf>,
    /// One picker at a time, so parallel connections can share its answer.
    picker_lock: tokio::sync::Mutex<()>,
    recent_picks: std::sync::Mutex<HashMap<String, (String, std::time::Instant)>>,
}

impl KeySelector {
    pub(crate) fn load(config: &sshwarden_config::Config) -> Self {
        for rule in &config.rules {
            if rule.host.is_none() && rule.repo.is_none() {
                tracing::warn!(key = %rule.key, "Ignoring selection rule without `host` or `repo`");
            }
        }
        let history_path = sshwarden_config::device_data_dir()
            .map(|dir| dir.join("key-history.json"))
            .inspect_err(|e| tracing::warn!("Key selection history disabled: {e}"))
            .ok();
        let history = history_path
            .as_ref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|content| {
                serde_json::from_str(&content)
                    .inspect_err(|e| tracing::warn!("Ignoring unreadable key history: {e}"))
                    .ok()
            })
            .unwrap_or_default();
        Self {
            rules: config.rules.clone(),
            picker_enabled: config.agent.key_picker,
            history: std::sync::Mutex::new(history),
            history_path,
            picker_lock: tokio::sync::Mutex::new(()),
            recent_picks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Decide what a key list request is answered with.
    pub(crate) async fn select(
        &self,
        request: &SshAgentListRequest,
        ui_request_tx: &UIRequestTx,
    ) -> ListSelection {
        let ctx = SelectContext::for_peer(request.pid, request.is_forwarding, &request.host_key);
        // Read on every request: `sshwarden keys bind` may change it at any time.
        let bindings = HostBindingsFile::load().unwrap_or_else(|e| {
            tracing::debug!("Host bindings unavailable for key selection: {e}");
            HostBindingsFile::default()
        });
        let (preferred, reason) = preferred(
            &ctx,
            &self.rules,
            &bindings,
            &self.history.lock().unwrap_or_else(|e| e.into_inner()),
            &request.keys,
        );

        if preferred.is_empty() && self.picker_enabled && request.keys.len() > 1 {
            // No context means this is not a login (`ssh-add -l`): list everything.
            if let Some(context) = ctx.history_key() {
                return self.pick(request, &ctx, context, ui_request_tx).await;
            }
        }

        info!(
            process = %request.process_name,
            target = %ctx.describe(),
            reason,
            "Key list request - ordered"
        );
        ListSelection {
            cipher_ids: order(preferred, &request.keys),
            user_picked: false,
        }
    }

    async fn pick(
        &self,
        request: &SshAgentListRequest,
        ctx: &SelectContext,
        context: String,
        ui_request_tx: &UIRequestTx,
    ) -> ListSelection {
        let _one_at_a_time = self.picker_lock.lock().await;
        let reused = self
            .recent_picks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&context)
            .filter(|(_, at)| at.elapsed() < PICK_REUSE)
            .map(|(id, _)| id.clone());
        if let Some(id) = reused {
            // Reusing a pick saves a second dialog, but only the connection the
            // user actually answered for counts as picked (and so as approved).
            info!(target = %ctx.describe(), "Key list request - reusing recent pick");
            return ListSelection {
                cipher_ids: vec![id],
                user_picked: false,
            };
        }

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let dialog = sshwarden_ui::UIRequest::PickKeyDialog {
            request: sshwarden_ui::PickKeyRequest {
                keys: order(Vec::new(), &request.keys)
                    .into_iter()
                    .filter_map(|id| request.keys.iter().find(|(known, _)| *known == id).cloned())
                    .collect(),
                process_name: request.process_name.clone(),
                target: ctx.describe(),
                is_forwarding: request.is_forwarding,
            },
            response_tx,
        };
        let picked = match ui_request_tx.send(dialog).await {
            Ok(()) => tokio::time::timeout(PICKER_TIMEOUT, response_rx)
                .await
                .ok()
                .and_then(Result::ok)
                .flatten(),
            Err(_) => None,
        }
        .filter(|id| request.keys.iter().any(|(known, _)| known == id));

        info!(
            process = %request.process_name,
            target = %ctx.describe(),
            picked = picked.is_some(),
            "Key list request - key picker answered"
        );
        match picked {
            Some(id) => {
                self.recent_picks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(context, (id.clone(), std::time::Instant::now()));
                ListSelection {
                    cipher_ids: vec![id],
                    user_picked: true,
                }
            }
            // Cancelled or timed out: offer no agent key rather than all of them.
            None => ListSelection {
                cipher_ids: Vec::new(),
                user_picked: false,
            },
        }
    }

    /// Remember which key a server accepted.
    ///
    /// OpenSSH asks for a signature only after the server said it would accept
    /// that public key, so the signing request itself is the evidence — whether
    /// or not the user then approves it.
    pub(crate) fn record_use(&self, request: &SshAgentUIRequest) {
        if request.operation_kind != OperationKind::SshAuthentication {
            return;
        }
        let ctx = SelectContext::for_peer(request.pid, request.is_forwarding, &request.host_key);
        let (Some(context), Some(cipher_id)) = (ctx.history_key(), &request.cipher_id) else {
            return;
        };
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        if !history.record(context, cipher_id) {
            return;
        }
        let Some(path) = &self.history_path else {
            return;
        };
        let saved = serde_json::to_string_pretty(&*history)
            .map_err(anyhow::Error::from)
            .and_then(|content| write_private_file(path, content));
        if let Err(e) = saved {
            tracing::warn!("Failed to save key selection history: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_target_only_for_logins_and_never_from_argv_when_forwarded() {
        let mut request = SshAgentUIRequest {
            request_id: 1,
            cipher_id: None,
            process_name: "ssh".to_string(),
            // Our own pid: its argv must not be consulted on a forwarded connection.
            pid: std::process::id(),
            namespace: None,
            operation_kind: OperationKind::SshAuthentication,
            is_forwarding: true,
            host_key: b"host-key".to_vec(),
            preselected: false,
        };
        let target = describe_target(&request).expect("login has a target");
        assert!(target.starts_with("SHA256:"), "{target}");

        request.operation_kind = OperationKind::GitSigning;
        assert_eq!(describe_target(&request), None);
    }

    fn keys() -> Vec<(String, String)> {
        [
            ("id-work", "Work"),
            ("id-home", "home"),
            ("id-misc", "Alpha"),
        ]
        .map(|(id, name)| (id.to_string(), name.to_string()))
        .to_vec()
    }

    fn ctx(host: &str, user: Option<&str>, repo: Option<&str>) -> SelectContext {
        SelectContext::new(
            Some(SshInvocation {
                host: host.to_string(),
                user: user.map(String::from),
                repo: repo.map(String::from),
            }),
            &[],
        )
    }

    fn rule(key: &str, host: Option<&str>, repo: Option<&str>) -> SelectionRule {
        SelectionRule {
            key: key.to_string(),
            host: host.map(String::from),
            user: None,
            repo: repo.map(String::from),
        }
    }

    #[test]
    fn glob_and_host_patterns() {
        assert!(glob_match("*.example.com", "db.EXAMPLE.com"));
        assert!(glob_match("10.0.?.*", "10.0.3.17"));
        assert!(glob_match("acme/*", "acme/widgets"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(!glob_match("github.com", "github.com.evil"));
        assert!(!glob_match("a*b*c", "aXbX"));

        assert!(host_patterns_match(["*.corp", "!bad.corp"], "ok.corp"));
        assert!(!host_patterns_match(["*.corp", "!bad.corp"], "bad.corp"));
        assert!(
            !host_patterns_match(["!bad.corp"], "ok.corp"),
            "negation alone never matches"
        );
    }

    #[test]
    fn default_order_is_stable_by_name() {
        assert_eq!(
            order(Vec::new(), &keys()),
            ["id-misc", "id-home", "id-work"]
        );
        assert_eq!(
            order(vec!["id-work".to_string()], &keys()),
            ["id-work", "id-misc", "id-home"],
            "preferred key first, nothing dropped"
        );
    }

    #[test]
    fn first_matching_rule_wins_and_needs_every_condition() {
        let rules = [
            rule("Work", Some("github.com"), Some("acme/*")),
            rule("home", Some("github.com"), None),
            rule("Alpha", None, None), // invalid: would match everything
        ];
        let none = (HostBindingsFile::default(), KeyHistory::default());
        let pick = |ctx: &SelectContext| preferred(ctx, &rules, &none.0, &none.1, &keys());

        assert_eq!(
            pick(&ctx("github.com", Some("git"), Some("acme/widgets"))),
            (vec!["id-work".to_string()], "rule")
        );
        assert_eq!(
            pick(&ctx("github.com", Some("git"), Some("me/dotfiles"))),
            (vec!["id-home".to_string()], "rule")
        );
        assert_eq!(pick(&ctx("example.org", None, None)), (Vec::new(), "none"));

        let mut user_rule = rule("Work", Some("*"), None);
        user_rule.user = Some("deploy".to_string());
        let by_user = |user| {
            preferred(
                &ctx("h", user, None),
                &[user_rule.clone()],
                &none.0,
                &none.1,
                &keys(),
            )
            .0
        };
        assert_eq!(by_user(Some("deploy")), ["id-work"]);
        assert!(by_user(Some("root")).is_empty());
        assert!(by_user(None).is_empty());
    }

    #[test]
    fn rule_then_binding_then_history_without_duplicates_or_unknown_keys() {
        let mut bindings = HostBindingsFile::default();
        bindings
            .add_host("id-home", "*.example.com")
            .expect("valid pattern");
        bindings
            .add_host("id-gone", "*.example.com")
            .expect("valid pattern");
        let target = ctx("db.example.com", None, None);
        let mut history = KeyHistory::default();
        let context = target.history_key().expect("host context");
        history.record(context.clone(), "id-home");
        history.record(context, "id-misc");

        assert_eq!(
            preferred(&target, &[], &bindings, &history, &keys()),
            (
                vec!["id-home".to_string(), "id-misc".to_string()],
                "binding"
            )
        );
        assert_eq!(
            preferred(
                &target,
                &[rule("id-work", Some("db.*"), None)],
                &bindings,
                &history,
                &keys()
            )
            .0,
            ["id-work", "id-home", "id-misc"]
        );
    }

    #[test]
    fn history_is_recent_first_bounded_and_split_by_repo_owner() {
        let mut history = KeyHistory::default();
        assert!(history.record("ctx".to_string(), "a"));
        assert!(
            !history.record("ctx".to_string(), "a"),
            "unchanged order needs no write"
        );
        for id in ["b", "c", "d", "b"] {
            history.record("ctx".to_string(), id);
        }
        assert_eq!(history.entries["ctx"], ["b", "d", "c"]);

        let acme = ctx("github.com", Some("git"), Some("acme/widgets")).history_key();
        assert_eq!(
            acme,
            ctx("github.com", Some("git"), Some("acme/gears")).history_key()
        );
        assert_ne!(
            acme,
            ctx("github.com", Some("git"), Some("me/dotfiles")).history_key()
        );
    }

    #[test]
    fn host_key_identifies_the_server_and_no_context_means_no_history() {
        let bound = SelectContext::new(None, b"host key blob");
        let key = bound.history_key().expect("host key is context enough");
        assert!(key.starts_with("SHA256:"), "{key}");
        assert_eq!(SelectContext::new(None, &[]).history_key(), None);

        // A forwarded connection must not inherit the first hop's argv.
        let forwarded = SelectContext::for_peer(std::process::id(), true, b"host key blob");
        assert_eq!(forwarded.host, None);
        assert_eq!(forwarded.history_key(), Some(key));
    }
}
