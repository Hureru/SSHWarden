# Notification connection state is reported, and a lost connection triggers a recovery sync

## Status

Accepted

## Context

ADR 0021 made the notification hub the near-real-time path with reconnect-first fallback sync. Two things were left implicit, and both turned out to be wrong in practice.

**Connection state was write-once.** `NotificationRuntimeState` was filled in at connect time and never updated afterwards. The reconnect loop kept its own counters, backoff, and disconnect reasons entirely to itself. From the daemon's point of view a socket that dropped five minutes ago and a socket that is delivering events were the same object, so `status` could not tell them apart, and a user could not either.

**`status` answered a different question than the user asked.** It printed one `Bitwarden: offline` row derived from "is there an API session", one `Sync: up to date` row derived from "no pending-sync flag", and one unexplained `0 signable` count. Three independent questions — *is there a session*, *is the hub delivering*, *is the cache current* — were collapsed into two rows that both defaulted to a healthy-sounding answer. A device that had never contacted the server in this session still read `Sync: up to date`.

**Reconnect was assumed to be an outage, not a gap.** ADR 0021 triggers fallback sync "after repeated reconnect failures or a configured elapsed threshold". The elapsed-threshold branch was never implemented, and measurement of the actual hub shows it is the wrong instrument:

- `warden-worker`'s notification Durable Object (`src/durable/notify_do.rs`) validates the access token *at the WebSocket upgrade* and answers HTTP 401 for an invalid or expired one, so a stale token surfaces as a failed connect rather than a silent subscription. An expired token is therefore already covered by the consecutive-failure path.
- The same Durable Object echoes incoming binary frames back to the sender and emits no heartbeats of its own. SSHWarden's 30-second MessagePack ping is what makes the 90-second idle probe meaningful: if the object stops answering, the probe fires within 90 seconds.
- It keeps no message log and ignores SignalR `?id=`. Bitwarden, Vaultwarden, and `warden-worker` all lack server-side replay or backfill.

The last point is the decisive one: **when an established socket drops, whatever was published meanwhile is gone**. Waiting for a failure counter to trip measures how long the client takes to give up, not how long data has been missing. Since the hub cannot replay, the loss itself is the event that matters.

A "no business events for N minutes means degraded" heuristic was considered and rejected. A quiet but healthy socket is the normal state for a vault that is not being edited, and on this hub it is indistinguishable from a socket that is connected and subscribed but permanently silent — while a socket that is actually dead stops being echoed and is caught by the idle probe. Such a rule would produce false positives without covering anything the probe misses.

## Decision

**1. The API layer reports connection state.** `sshwarden-api` publishes `SyncEvent::ConnectionStatus(NotificationStatus)` on every transition — `not_started`, `starting`, `running`, `failed` (retrying), `stopped` — carrying consecutive and total failures, the delay until the next attempt, the last error, and the reconnect count. Status snapshots are advisory and pushed with `try_send`: a busy consumer drops one and the next transition carries the same information. Aspect events (`CipherChanged`, `LogOut`) and `FallbackSyncDue` keep their blocking, lossless path.

**2. Losing an established connection requests a recovery sync.** Immediately on disconnect the client emits `FallbackSyncDue`, throttled by `fallback_sync_interval` and sharing that throttle with the degraded-retry cadence so a flapping socket cannot multiply the sync rate. A zero interval still disables fallback sync entirely, as ADR 0021 allows. The existing consecutive-failure cadence is kept as the second, slower layer.

**3. Degradation detection stays echo-based.** 30-second keepalive ping, 90-second idle timeout, fallback after 3 consecutive connect failures, exponential backoff to 60 seconds. No elapsed-time-without-events rule.

**4. Connection state has a documented vocabulary.** `status` and `doctor` describe the same four facts separately, and the JSON key names are stable:

| Fact | Row | Values |
|---|---|---|
| Session | `Bitwarden` | `logged in`, `no session`, `unknown (not reported by the daemon)` |
| Delivery | `Notify` | `off (no Bitwarden session)`, `connecting…`, `connected…`, `retrying (…)`, `stopped`, `unknown` |
| Freshness | `Sync` | `up to date (last sync 2m)`, `last sync 3h07m ago, notifications not delivering`, `pending (loads on next unlock)`, `unknown (no successful sync yet)`, `unknown (no Bitwarden session)` |
| Local cache | `Cache` | present only when broken: `out of date — refresh failed: <reason>` |

`up to date` now requires two observed facts: at least one successful sync this session, and a hub that is currently delivering. Otherwise the row says how old the last sync is and why that is all that is known. A row that cannot be observed reads `unknown`; nothing defaults to a healthy value.

**5. `Stale Cache` is cleared by a successful refresh.** The flag means "the refresh after the last sync failed", not "permanent defect", so a subsequent successful `Cache Refresh` clears it and its reason. The failure is reported on the `Cache` row instead of the `Sync` row, because it is local, not a server-freshness problem.

**6. The access-token refresh tick is 5 minutes, not 30.** The hub rejects a stale token at the upgrade with 401, so a lazy tick costs a reconnect window plus a fallback-sync window for no benefit.

**7. `status --json` gains `schema_version: 2` and `agent_pid`.** Keys stay additive; `details` remains the payload. `reconnect_attempts` is retained and now means *consecutive* failed attempts, which is what a monitor wants to alert on. The agent-unreachable view emits every documented key with `null` values so one parser handles both. The daemon reports its own pid so `status` does not depend on the client binary sitting at the same path as the daemon (see `process_is_sshwarden`).

## Rationale

- Reporting state from the loop that owns the state is the only way the daemon's view can be current; mirroring it at connect time is what made a dropped socket invisible.
- Because no supported hub can replay, "lost an established connection" is a stronger and more honest trigger than "failed N reconnect attempts".
- Measuring the hub (token rejection at the upgrade, binary-frame echo, no message log, no `?id=`) chose the mechanism instead of guessing at it: it rules out the silent-subscription failure mode, keeps the idle probe effective, and rules out the elapsed-threshold heuristic as unnecessary.
- `unknown` is a legitimate answer. The previous rows were optimistic defaults, which is worse than an admission of ignorance because it is acted upon.
- Separating session, delivery, freshness, and cache refresh means each row can be fixed independently and each is true on its own.

## Consequences

- `status` output changes shape: `Lock` becomes `Vault`, `Bitwarden` no longer reports `offline` (that word conflated "no session" with "no network"), and `Notify`, `Cache`, and `Log` rows are added. The `Next:` line can now mention that a PIN makes unlock work offline.
- `Sync: up to date` can become `unknown (no successful sync yet)`. That is the intended correction, and it is what the earlier output was hiding.
- Consumers of `reconnect_attempts` see it reset to `0` on a successful connect instead of counting attempts since startup; `total_failures` carries the cumulative count.
- A reconnect now causes one throttled sync where it previously caused none. Because the throttle is shared, the worst-case sync rate is unchanged from the degraded cadence.
- ADR 0021's "configured elapsed threshold" clause is superseded by the loss-triggered recovery sync; its reconnect-first and no-aggressive-polling decisions stand.
- The 5-minute token tick means up to five minutes of "connected with an expired token" before the client rebuilds, during which the hub answers 401 and the degradation path is visible in `Notify` rather than silent.
