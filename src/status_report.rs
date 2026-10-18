//! The `status` report: one model behind the text view, plus the key lists the
//! machine-readable view must expose.
//!
//! Rules this module exists to enforce:
//!
//! 1. Every row states an observed fact or an explicit `unknown`. A row must
//!    never fall back to a healthy-sounding value — `Sync: up to date` used to
//!    be printed for a device that had never reached the server at all.
//! 2. Rows are independent questions: "is there a session", "is the hub socket
//!    delivering", and "is the cache current" are three different things and are
//!    reported separately instead of one standing in for another.
//! 3. The agent-unreachable view has the same shape as the live one, so scripts
//!    do not have to special-case it.

use crate::runtime::{
    humanize_age, notification_health_label, NotificationHealth, NOTIFICATION_JSON_KEYS,
};

/// Version of the `status --json` field set.
///
/// Bump when a key is removed or changes meaning. Keys are only added or
/// re-documented within a version.
pub(crate) const STATUS_SCHEMA_VERSION: u32 = 2;

/// Top-level keys of the `status --json` object.
///
/// Must stay in sync with `control::build_status_response`. [`missing_detail_keys`]
/// lets `cmd_status` flag drift against a live daemon response instead of
/// letting a user's script discover it.
pub(crate) const DETAIL_JSON_KEYS: &[&str] = &[
    "schema_version",
    "agent_running",
    "agent_pid",
    "authenticated",
    "locked",
    "key_count",
    "signable_key_count",
    "has_pin",
    "has_local_key_cache",
    "pending_sync",
    "data_dir",
    "shared_data_dir",
    "device_data_dir",
    "local_state_dir",
    "log_path",
    "device_id",
    "multi_device",
    "ssh_config_path_style",
    "notification",
];

/// Width of the label column, including its colon.
const LABEL_WIDTH: usize = 11;

/// A rendered `status` view.
///
/// Rows are pre-rendered strings: the only transformation left is alignment, so
/// the online and offline views cannot drift apart in structure.
pub(crate) struct StatusReport {
    pub(crate) agent: String,
    pub(crate) device: String,
    pub(crate) vault: String,
    pub(crate) bitwarden: String,
    pub(crate) notify: String,
    pub(crate) sync: String,
    /// Present only when the local key cache is out of date.
    pub(crate) cache: Option<String>,
    pub(crate) keys: String,
    pub(crate) log_path: Option<String>,
    pub(crate) next: Option<String>,
}

/// The subset of a daemon response the text view needs.
struct Facts<'a> {
    agent_running: bool,
    device_remembered: bool,
    locked: Option<bool>,
    authenticated: Option<bool>,
    pending_sync: Option<bool>,
    has_pin: bool,
    key_count: u64,
    signable_key_count: u64,
    /// The daemon's own pid; authoritative, unlike re-reading the pid file from
    /// a client binary that may live elsewhere (see `process_is_sshwarden`).
    agent_pid: Option<u32>,
    log_path: Option<String>,
    notification: &'a serde_json::Value,
}

impl StatusReport {
    /// Build from the daemon's `status-json` details.
    pub(crate) fn from_details(details: &serde_json::Value) -> Self {
        let notification = details
            .get("notification")
            .unwrap_or(&serde_json::Value::Null);
        Self::build(Facts {
            agent_running: flag(details, "agent_running").unwrap_or(false),
            device_remembered: flag(details, "has_local_key_cache").unwrap_or(false),
            locked: flag(details, "locked"),
            authenticated: flag(details, "authenticated"),
            pending_sync: flag(details, "pending_sync"),
            has_pin: flag(details, "has_pin").unwrap_or(false),
            key_count: count(details, "key_count"),
            signable_key_count: count(details, "signable_key_count"),
            agent_pid: details
                .get("agent_pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok()),
            log_path: details
                .get("log_path")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            notification,
        })
    }

    /// The agent does not answer: report only what the filesystem can prove.
    ///
    /// Everything else stays `unknown` rather than being inferred from local
    /// files, which is how an unreachable agent used to look half-configured.
    pub(crate) fn offline(device_remembered: bool, log_path: String) -> Self {
        let unknown = "unknown".to_string();
        Self {
            agent: "not running".to_string(),
            device: if device_remembered {
                "remembered"
            } else {
                "not set up"
            }
            .to_string(),
            vault: unknown.clone(),
            bitwarden: unknown.clone(),
            notify: unknown.clone(),
            sync: unknown.clone(),
            cache: None,
            keys: unknown,
            log_path: Some(log_path),
            next: Some(if device_remembered {
                "sshwarden run        (start the agent, then `unlock`)".to_string()
            } else {
                "sshwarden login      (set up this device)".to_string()
            }),
        }
    }

    fn build(facts: Facts<'_>) -> Self {
        let notify_state = facts
            .notification
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let notify_health =
            json_health_label(facts.notification, facts.authenticated.unwrap_or(false));

        let cache = if flag(facts.notification, "stale_cache").unwrap_or(false) {
            let reason = facts
                .notification
                .get("stale_cache_error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown refresh error");
            Some(format!("out of date — refresh failed: {reason}"))
        } else {
            None
        };

        let agent = if facts.agent_running {
            // Prefer the daemon's own pid; the local pid file only matches when
            // this client binary sits at the same path as the daemon.
            match facts.agent_pid.or_else(crate::process::running_agent_pid) {
                Some(pid) => format!("running (pid {pid})"),
                None => "running".to_string(),
            }
        } else {
            "not serving SSH — run `sshwarden doctor`".to_string()
        };

        let keys = {
            let base = format!(
                "{} listed, {} signable",
                facts.key_count, facts.signable_key_count
            );
            if facts.signable_key_count < facts.key_count {
                match facts.locked {
                    Some(true) => format!("{base} (signing resumes after unlock)"),
                    Some(false) => format!("{base} (no private material for some keys)"),
                    None => base,
                }
            } else {
                base
            }
        };

        Self {
            agent,
            device: if facts.device_remembered {
                "remembered"
            } else {
                "not set up"
            }
            .to_string(),
            vault: match facts.locked {
                Some(true) => "locked".to_string(),
                Some(false) => "unlocked".to_string(),
                None => "unknown (not reported by the daemon)".to_string(),
            },
            bitwarden: match facts.authenticated {
                Some(true) => "logged in".to_string(),
                // "offline" used to conflate "no API session" with "no network".
                Some(false) => "no session".to_string(),
                None => "unknown (not reported by the daemon)".to_string(),
            },
            notify: notify_health,
            sync: sync_row(&facts, notify_state),
            cache,
            keys,
            log_path: facts.log_path.clone(),
            next: next_step(&facts),
        }
    }

    /// Label-aligned text lines.
    pub(crate) fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![
            row("Agent", &self.agent),
            row("Device", &self.device),
            row("Vault", &self.vault),
            row("Bitwarden", &self.bitwarden),
            row("Notify", &self.notify),
            row("Sync", &self.sync),
        ];
        if let Some(cache) = &self.cache {
            lines.push(row("Cache", cache));
        }
        lines.push(row("Keys", &self.keys));
        if let Some(log_path) = &self.log_path {
            lines.push(row("Log", log_path));
        }
        if let Some(next) = &self.next {
            lines.push(row("Next", next));
        }
        lines
    }
}

/// Connection health rendered from a `status --json` `notification` object.
///
/// Shared with `doctor`, so both surfaces describe the connection the same way.
pub(crate) fn json_health_label(notification: &serde_json::Value, authenticated: bool) -> String {
    notification_health_label(&NotificationHealth {
        state: notification
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown"),
        connects: count(notification, "connects"),
        consecutive_failures: count(notification, "consecutive_failures") as u32,
        next_retry_in_secs: notification
            .get("next_retry_in_secs")
            .and_then(serde_json::Value::as_u64),
        last_error: notification
            .get("last_error")
            .and_then(serde_json::Value::as_str),
        up_for_secs: notification
            .get("last_connected_age_secs")
            .and_then(serde_json::Value::as_u64),
        authenticated,
    })
}

/// Freshness of the cached key material, said out loud.
///
/// `up to date` is only claimed when a sync actually succeeded *and* the hub is
/// delivering; otherwise the row says how old the last sync is and why that is
/// all we know.
fn sync_row(facts: &Facts<'_>, notify_state: &str) -> String {
    if facts.pending_sync == Some(true) {
        return "pending (loads on next unlock)".to_string();
    }
    if facts.authenticated == Some(false) {
        return "unknown (no Bitwarden session)".to_string();
    }
    let Some(age) = facts
        .notification
        .get("last_sync_age_secs")
        .and_then(serde_json::Value::as_u64)
    else {
        return "unknown (no successful sync yet)".to_string();
    };
    if notify_state == "running" {
        format!("up to date (last sync {})", humanize_age(age))
    } else {
        format!(
            "last sync {} ago, notifications not delivering",
            humanize_age(age)
        )
    }
}

/// The single authoritative "what to do next".
fn next_step(facts: &Facts<'_>) -> Option<String> {
    if !facts.device_remembered {
        return Some("sshwarden login      (set up this device)".to_string());
    }
    if facts.locked == Some(true) {
        return Some(if facts.has_pin {
            "sshwarden unlock      (PIN available, works offline)".to_string()
        } else {
            "sshwarden unlock".to_string()
        });
    }
    if facts.key_count == 0 {
        return Some("sshwarden sync       (no keys cached yet)".to_string());
    }
    if flag(facts.notification, "stale_cache").unwrap_or(false) {
        return Some("sshwarden sync       (refresh the local key cache)".to_string());
    }
    None
}

fn row(label: &str, value: &str) -> String {
    let mut line = String::with_capacity(LABEL_WIDTH + value.len());
    line.push_str(label);
    line.push(':');
    while line.chars().count() < LABEL_WIDTH {
        line.push(' ');
    }
    line.push_str(value);
    line
}

fn flag(value: &serde_json::Value, key: &str) -> Option<bool> {
    value.get(key).and_then(serde_json::Value::as_bool)
}

fn count(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// Keys a live `status --json` response should carry but did not.
pub(crate) fn missing_detail_keys(details: &serde_json::Value) -> Vec<&'static str> {
    DETAIL_JSON_KEYS
        .iter()
        .copied()
        .filter(|key| details.get(*key).is_none())
        .collect()
}

/// A `status --json` object with every key present but nothing known.
///
/// Values are `null` rather than optimistic defaults, and the shape matches a
/// live response so one parser handles both.
pub(crate) fn offline_details_json(
    device_remembered: bool,
    log_path: &str,
    local_state_dir: &str,
) -> serde_json::Value {
    let mut notification = serde_json::Map::with_capacity(NOTIFICATION_JSON_KEYS.len());
    for key in NOTIFICATION_JSON_KEYS {
        notification.insert((*key).to_string(), serde_json::Value::Null);
    }
    serde_json::json!({
        "schema_version": STATUS_SCHEMA_VERSION,
        "agent_running": false,
        "agent_pid": serde_json::Value::Null,
        "authenticated": serde_json::Value::Null,
        "locked": serde_json::Value::Null,
        "key_count": serde_json::Value::Null,
        "signable_key_count": serde_json::Value::Null,
        "has_pin": serde_json::Value::Null,
        "has_local_key_cache": device_remembered,
        // Legacy key from the pre-schema offline view; kept for one version.
        "has_remembered_device": device_remembered,
        "pending_sync": serde_json::Value::Null,
        "data_dir": serde_json::Value::Null,
        "shared_data_dir": serde_json::Value::Null,
        "device_data_dir": serde_json::Value::Null,
        "local_state_dir": local_state_dir,
        "log_path": log_path,
        "device_id": serde_json::Value::Null,
        "multi_device": serde_json::Value::Null,
        "ssh_config_path_style": serde_json::Value::Null,
        "notification": serde_json::Value::Object(notification),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The state this project was in when the reporting bugs were found: agent
    /// up, device remembered, vault locked, no Bitwarden session, hub never
    /// started, keys listed but not signable.
    ///
    /// Also serves as the canonical example of a complete live response.
    fn observed_locked_state() -> serde_json::Value {
        serde_json::json!({
            "schema_version": STATUS_SCHEMA_VERSION,
            "agent_running": true,
            "agent_pid": 1451,
            "authenticated": false,
            "locked": true,
            "key_count": 7,
            "signable_key_count": 0,
            "has_pin": true,
            "has_local_key_cache": true,
            "pending_sync": false,
            "data_dir": "/home/zheng/Tools/SSHWarden",
            "shared_data_dir": "/home/zheng/Tools/SSHWarden",
            "device_data_dir": "/home/zheng/Tools/SSHWarden",
            "local_state_dir": "/home/zheng/.local/state/sshwarden/SSHWarden",
            "log_path": "/home/zheng/.local/state/sshwarden/SSHWarden/sshwarden.log",
            "device_id": "hureru-cachyos-zheng",
            "multi_device": false,
            "ssh_config_path_style": "absolute",
            "notification": {
                "state": "not_started",
                "url": null,
                "last_error": null,
                "reconnect_attempts": 0,
                "consecutive_failures": 0,
                "total_failures": 0,
                "next_retry_in_secs": null,
                "connects": 0,
                "last_connected_age_secs": null,
                "last_event_age_secs": null,
                "last_fallback_sync_age_secs": null,
                "last_sync_age_secs": null,
                "stale_cache": false,
                "stale_cache_error": null,
            },
        })
    }

    fn rendered(details: &serde_json::Value) -> String {
        StatusReport::from_details(details)
            .render_lines()
            .join("\n")
    }

    #[test]
    fn never_synced_devices_do_not_claim_to_be_up_to_date() {
        let text = rendered(&observed_locked_state());
        assert!(!text.contains("up to date"), "{text}");
        assert!(
            text.contains("Sync:      unknown (no Bitwarden session)"),
            "{text}"
        );
    }

    #[test]
    fn agent_row_uses_the_pid_the_daemon_reports() {
        // A client binary at a different path than the daemon cannot verify the
        // pid file (see process_is_sshwarden), so the daemon's own pid is what
        // keeps this row from silently degrading to a bare "running".
        let report = StatusReport::from_details(&observed_locked_state());
        assert_eq!(report.agent, "running (pid 1451)");
    }

    #[test]
    fn connected_rows_describe_health_not_just_state() {
        let mut details = observed_locked_state();
        details["authenticated"] = serde_json::json!(true);
        details["notification"]["state"] = serde_json::json!("running");
        details["notification"]["connects"] = serde_json::json!(3);
        details["notification"]["last_connected_age_secs"] = serde_json::json!(90);
        details["notification"]["last_sync_age_secs"] = serde_json::json!(150);
        let text = rendered(&details);
        assert!(
            text.contains("Notify:    connected (2 reconnects, up 1m)"),
            "{text}"
        );
        assert!(
            text.contains("Sync:      up to date (last sync 2m)"),
            "{text}"
        );
    }

    #[test]
    fn a_dropped_connection_is_visible_and_does_not_claim_freshness() {
        let mut details = observed_locked_state();
        details["locked"] = serde_json::json!(false);
        details["authenticated"] = serde_json::json!(true);
        details["notification"]["state"] = serde_json::json!("failed");
        details["notification"]["consecutive_failures"] = serde_json::json!(4);
        details["notification"]["next_retry_in_secs"] = serde_json::json!(30);
        details["notification"]["last_error"] = serde_json::json!("HTTP error: 401");
        details["notification"]["last_sync_age_secs"] = serde_json::json!(3600);
        let text = rendered(&details);
        assert!(
            text.contains(
                "Notify:    retrying (4 failed attempt(s), next attempt in 30s: HTTP error: 401)"
            ),
            "{text}"
        );
        assert!(
            text.contains("Sync:      last sync 1h00m ago, notifications not delivering"),
            "{text}"
        );
        assert!(!text.contains("up to date"), "{text}");
    }

    #[test]
    fn local_cache_failure_gets_its_own_row_with_the_real_reason() {
        let mut details = observed_locked_state();
        // Unlocked, so the next step is about the cache rather than unlocking.
        details["locked"] = serde_json::json!(false);
        details["notification"]["stale_cache"] = serde_json::json!(true);
        details["notification"]["stale_cache_error"] = serde_json::json!("bad envelope");
        let report = StatusReport::from_details(&details);
        let lines = report.render_lines().join("\n");
        assert!(
            lines.contains("Cache:     out of date — refresh failed: bad envelope"),
            "{lines}"
        );
        // The cause is local, so the sync row must not blame the server.
        assert!(!lines.contains("Sync:      stale"), "{lines}");
        assert!(
            report
                .next
                .as_deref()
                .unwrap()
                .contains("refresh the local key cache"),
            "{:?}",
            report.next
        );
    }

    #[test]
    fn locked_keys_explain_why_they_are_not_signable() {
        let text = rendered(&observed_locked_state());
        assert!(
            text.contains("Keys:      7 listed, 0 signable (signing resumes after unlock)"),
            "{text}"
        );
    }

    #[test]
    fn pin_availability_is_surfaced_in_the_next_step() {
        let report = StatusReport::from_details(&observed_locked_state());
        assert_eq!(
            report.next.as_deref(),
            Some("sshwarden unlock      (PIN available, works offline)")
        );

        let mut no_pin = observed_locked_state();
        no_pin["has_pin"] = serde_json::json!(false);
        let report = StatusReport::from_details(&no_pin);
        assert_eq!(report.next.as_deref(), Some("sshwarden unlock"));
    }

    #[test]
    fn missing_facts_are_unknown_never_optimistic() {
        let report = StatusReport::from_details(&serde_json::json!({}));
        let text = report.render_lines().join("\n");
        assert!(
            text.contains("Vault:     unknown (not reported by the daemon)"),
            "{text}"
        );
        assert!(
            text.contains("Bitwarden: unknown (not reported by the daemon)"),
            "{text}"
        );
        assert!(text.contains("Notify:    unknown"), "{text}");
        assert!(
            text.contains("Sync:      unknown (no successful sync yet)"),
            "{text}"
        );
        assert!(text.contains("Keys:      0 listed, 0 signable"), "{text}");
        assert!(!text.contains("up to date"), "{text}");
    }

    #[test]
    fn every_row_aligns_its_value_column() {
        let report = StatusReport::from_details(&observed_locked_state());
        for line in report.render_lines() {
            let label_end = line.find(':').unwrap();
            assert!(label_end < LABEL_WIDTH, "{line}");
            assert!(
                !line[LABEL_WIDTH..].starts_with(' '),
                "value column is not at {LABEL_WIDTH}: {line}"
            );
            assert!(
                line[..LABEL_WIDTH].trim_end().ends_with(':'),
                "label column bleeds into the value: {line}"
            );
        }
    }

    #[test]
    fn offline_view_matches_the_live_shape() {
        let offline = offline_details_json(true, "/tmp/sshwarden.log", "/tmp/state");
        assert!(missing_detail_keys(&offline).is_empty());
        let live = observed_locked_state();
        for key in DETAIL_JSON_KEYS {
            assert!(live.get(*key).is_some(), "sample live response lacks {key}");
        }
        for key in NOTIFICATION_JSON_KEYS {
            assert!(
                offline["notification"].get(*key).is_some(),
                "offline notification object lacks {key}"
            );
            assert!(
                crate::runtime::NotificationRuntimeState::default()
                    .to_json()
                    .get(*key)
                    .is_some(),
                "runtime state no longer emits {key}; update NOTIFICATION_JSON_KEYS"
            );
        }
    }

    #[test]
    fn offline_view_says_nothing_it_cannot_know() {
        let report = StatusReport::offline(true, "/tmp/sshwarden.log".to_string());
        let lines = report.render_lines();
        assert_eq!(lines[0], "Agent:     not running");
        assert_eq!(lines[1], "Device:    remembered");
        for line in &lines[2..7] {
            assert!(line.ends_with("unknown"), "{line}");
        }
        assert!(lines.iter().any(|line| line.starts_with("Log:")));
        assert!(report.next.unwrap().starts_with("sshwarden run"));
    }
}
