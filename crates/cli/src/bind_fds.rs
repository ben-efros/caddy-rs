//! `caddy-rs bind-fds` — pre-bind the configured listeners and upload them to `systemd`'s fd store
//! (ADR-0047 §2, §3).
//!
//! This module computes the plan, derives the FD names it would use, and then either (under
//! `--dry-run`) prints both and exits **without binding or uploading**, or performs the real
//! `FDSTORE=1` upload via [`bind_and_upload`].
//!
//! # Ordering is the security property, not an implementation detail
//!
//! Every planned socket is bound before any descriptor is uploaded. Binding and uploading in one
//! interleaved pass would leave the store holding descriptors for listeners `1..n` when listener
//! `n+1` failed to bind, and `run` would then adopt a set that does not match the plan — a silent
//! half-applied configuration. Binding first means a bind failure uploads nothing, which is the
//! "no partial state" ADR-0047 §6 requires. `a_bind_failure_uploads_nothing_at_all` asserts this on
//! the observable (the upload callback is never invoked) rather than by reading the source.
//!
//! `NOTIFY_SOCKET` is likewise checked **before** the first bind: an unset or empty value is a
//! clear refusal rather than a late socket failure, so a unit that forgot socket activation cannot
//! leave orphaned bound ports behind.
//!
//! # Idempotency, and why removal comes after binding
//!
//! `bind-fds` runs from `ExecStartPre` on every start, so it must converge rather than accumulate.
//! systemd does not document an interface for enumerating the fd store, so the helper cannot ask
//! what is already stored; it removes every name its plan owns and re-uploads, which leaves exactly
//! one descriptor per planned listener however many times it runs (ADR-0047 §5). That limitation is
//! recorded in `docs/INSTALL.md` rather than worked around, because there is no interface to work
//! around.
//!
//! Removal happens **after** binding and **before** uploading, in that order, and both orderings are
//! deliberate. After binding, because a bind failure must leave the store untouched — removing
//! first would destroy working descriptors and then fail to replace them. Before uploading, because
//! uploading onto a name that is still stored is exactly the duplicate this task exists to prevent.
//! `re_running_for_unchanged_configuration_never_duplicates_a_stored_descriptor` asserts the final
//! store contents, and `a_bind_failure_uploads_nothing_at_all` asserts that a failed bind removes
//! nothing either.
//!
//! A listener dropped from the configuration cannot be discovered for the same reason — the store
//! cannot be enumerated — so [`stale_names`] and [`remove_stale`] take the previous plan explicitly.
//! Without it a removed listener keeps its descriptor, and therefore its port.
//!
//! # Still open
//!
//! `run`-side adoption (finding the stored descriptors by `FDNAME` and using those instead of
//! binding) is **not** implemented here; it is tracked separately so this increment cannot be
//! mistaken for the whole of stage 3.
//!
//! # Why the plan, and not the configuration text
//!
//! ADR-0047 §3 requires the name to be a pure function of the **normalised plan entry** rather than
//! the raw configured string. The reason is not tidiness: `run` looks a socket up by plan entry, so
//! if the helper named a socket from the raw text and `run` named it from the plan, the same
//! listener would be uploaded under one identity and looked up under another — the exact failure
//! the "no second source of truth" goal exists to prevent. Every name here is derived from
//! [`PlannedListener`], the same type `run` matches with.
//!
//! # The naming scheme, and why it is shaped this way
//!
//! ADR-0047 §3 amends the spec's proposed `caddy-<proto>-<host>-<port>` because that scheme is
//! ambiguous in two ways:
//!
//! 1. **IPv6.** The spec's own example, `caddy-tcp-[::]-80`, contains `:`, so a name can never be
//!    parsed back by splitting on `-`: `caddy-tcp-::1-80` is indistinguishable from malformed
//!    input. This module therefore **never parses a name** and brackets IPv6 unconditionally, so a
//!    name is opaque and is only ever compared for equality.
//! 2. **Wildcard versus explicit address.** `:443`, `0.0.0.0:443` and `[::]:443` are three distinct
//!    configured listeners. They are also three distinct *plan entries* — the plan preserves the
//!    host exactly as configured, keeping `""`, `"0.0.0.0"` and `"[::]"` separate — so they get
//!    three distinct names. Naming them alike would silently collapse three listeners into one
//!    stored descriptor.
//!
//! Because the name is only compared for equality, the single property it must have is
//! **injectivity** over the plan: distinct plan entries must never share a name. The scheme
//! guarantees that structurally rather than by hoping, and [`assert_injective`] enforces it at
//! runtime, failing the plan if a future listener kind cannot be named injectively (ADR-0047 §3:
//! "the plan must reject it rather than invent a lossy name").
//!
//! # Escaping
//!
//! Hosts are escaped so that the delimiter can never appear inside a component: `%` becomes `%25`
//! and `:` becomes `%3A` (`[` and `]` are kept, since they only ever wrap an IPv6 literal and
//! cannot be confused with the delimiter). A hostname that resolves to different addresses still
//! yields one name per plan entry, because the plan is keyed on the configured host — matching how
//! `run` looks the socket up.

use std::collections::BTreeMap;
use std::fmt::Write as _;
#[cfg(unix)]
use std::os::fd::OwnedFd;

use caddy_rs_core::Network;
use caddy_rs_server::listener_plan::{plan_listeners, ListenerPlan, ListenerPlanError};

/// The prefix every generated FD name carries.
///
/// A single fixed prefix keeps the names recognisable in `systemctl show -p FileDescriptorName` and
/// in `LISTEN_FDNAMES`, and gives stage 3 a way to tell caddy-rs's own sockets from any others
/// (ADR-0047 §5, stale-FD removal).
const NAME_PREFIX: &str = "caddy";

/// The delimiter between name components.
const DELIMITER: char = '-';

/// One planned listener together with the FD name derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFd {
    /// The plan entry this descriptor belongs to.
    pub network: Network,
    /// Host exactly as configured (`""` for a wildcard).
    pub host: String,
    /// The concrete port.
    pub port: u16,
    /// The deterministic `FDNAME` for this listener.
    pub fd_name: String,
}

impl PlannedFd {
    /// The address in `host:port` form, with IPv6 bracketed, for the human-readable report.
    ///
    /// This is display only. It is **not** the name and must never be parsed back into one.
    pub fn address(&self) -> String {
        if self.host.is_empty() {
            return format!(":{}", self.port);
        }
        if self.host.contains(':') && !self.host.starts_with('[') {
            return format!("[{}]:{}", self.host, self.port);
        }
        format!("{}:{}", self.host, self.port)
    }
}

/// Escape a host so it cannot contain the delimiter.
///
/// A **bracketed** host is an IPv6 literal and is emitted verbatim: `[` and `]` already delimit it
/// unambiguously, `:` is legal inside the brackets, and escaping it would turn the readable
/// `caddy-tcp-[::1]-80` into `caddy-tcp-[%3A%3A1]-80` — which defeats the purpose of output meant to
/// be pasted into a bug report. Brackets cannot appear in a hostname or an IPv4 literal, so an
/// unbracketed component can never contain them.
///
/// An unbracketed host is escaped: `%` first, so escaping stays unambiguous (a literal `%3A` must
/// not be confusable with an escaped `:`), then `:`. The delimiter `-` is not in the character set
/// a hostname or IPv4 literal may contain, but it is escaped too, so a future host form that admits
/// it cannot silently break injectivity.
///
/// Keeping this escape injective is what keeps the *name* injective.
fn escape_host(host: &str) -> String {
    if host.starts_with('[') && host.ends_with(']') {
        // IPv6 literal: the brackets delimit it, so the colons inside are not ambiguous *within
        // the name*. They are still escaped, because `LISTEN_FDNAMES` joins names with ':' and a
        // raw ':' inside a name would split it into several names on the way back to `run` -
        // silently breaking adoption for exactly the listeners IPv6 configurations use. The
        // brackets stay, so the name is still recognisably an IPv6 address.
        // The brackets stay, so the name is recognisably an IPv6 address (acceptance criterion:
        // "IPv6 names are bracketed"), but the colons inside must be escaped: `LISTEN_FDNAMES`
        // joins names with ':', so a raw colon would split one name into several on the way back
        // to `run` and silently break adoption for exactly the listeners IPv6 configs use.
        let inner = &host[1..host.len() - 1];
        return format!("[{}]", escape_component(inner));
    }
    escape_component(host)
}

/// Escape the characters that would make a name component ambiguous.
///
/// `%` first, so escaping itself is unambiguous (a literal `%3A` must not be confusable with an
/// escaped `:`), then `:` because `LISTEN_FDNAMES` uses it as the list separator, then `-` so a
/// host form that later admits the name delimiter cannot silently break injectivity.
fn escape_component(component: &str) -> String {
    let mut escaped = String::with_capacity(component.len());
    for character in component.chars() {
        match character {
            '%' => escaped.push_str("%25"),
            ':' => escaped.push_str("%3A"),
            '-' => escaped.push_str("%2D"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The FD name for one plan entry.
///
/// Pure: it depends only on the entry's network, configured host and port, so the helper and `run`
/// always agree. The host component is present even when empty, so `:443` and `0.0.0.0:443` cannot
/// collide by elision.
pub fn fd_name(network: Network, host: &str, port: u16) -> String {
    let mut name = String::with_capacity(NAME_PREFIX.len() + 16);
    let _ = write!(
        name,
        "{NAME_PREFIX}{DELIMITER}{}{DELIMITER}",
        network.as_str()
    );
    name.push_str(&escape_host(host));
    let _ = write!(name, "{DELIMITER}{port}");
    name
}

/// The configured listen strings the plan is built from.
///
/// Reads `apps.http.servers.*.listen`, which is the same source `run` applies, so the helper cannot
/// plan a listener that `run` would not create. The strings are returned deduplicated and sorted so
/// the plan is deterministic regardless of the order the configuration listed them in.
pub fn configured_listens(config: &caddy_rs_core::Config) -> Vec<String> {
    let mut listens: Vec<String> = config
        .http()
        .map(|app| {
            app.servers
                .values()
                .flat_map(|server| server.listen.iter().cloned())
                .collect()
        })
        .unwrap_or_default();
    listens.sort();
    listens.dedup();
    listens
}

/// The error a `bind-fds` plan can fail with.
#[derive(Debug)]
pub enum BindFdsError {
    /// The listener plan rejected the configuration.
    Plan(ListenerPlanError),
    /// Two distinct plan entries produced the same FD name.
    ///
    /// This is a programming error in the naming scheme rather than a configuration error: it means
    /// a listener kind cannot be named injectively. It is surfaced as a failure rather than
    /// resolved by disambiguation, because a lossy name would make `run` adopt the wrong socket.
    NameCollision {
        /// The colliding name.
        name: String,
        /// One of the listeners that produced it, as `proto/address`.
        first: String,
        /// The other listener that produced it, as `proto/address`.
        second: String,
    },
    /// A planned listener could not be bound.
    ///
    /// ADR-0047 §6: this is a loud failure rather than a partial upload. The address is named
    /// because the operator's next action is to find whichever process already holds the port.
    Bind {
        /// The listener that failed, as `proto/address`.
        listener: String,
        /// The bind failure.
        source: std::io::Error,
    },
    /// A bound descriptor could not be uploaded to the fd store.
    ///
    /// Reported with the FD name and the address so the unit's log names which socket is missing
    /// rather than only that "upload failed".
    Upload {
        /// The plan entry that failed, as `proto/address`.
        listener: String,
        /// The deterministic FD name that was attempted.
        fd_name: String,
        /// The upload failure.
        source: caddy_rs_server::fdstore::FdStoreError,
    },
    /// An already-stored descriptor could not be removed before re-upload.
    ///
    /// This is a distinct failure from [`Self::Upload`] because the store is in a different state
    /// when it happens: nothing new has been uploaded, but the stale entry may still be present, so
    /// the caller must not assume the plan is either fully old or fully new.
    Remove {
        /// The plan entry whose name could not be removed, as `proto/address`.
        listener: String,
        /// The deterministic FD name that was being removed.
        fd_name: String,
        /// The removal failure.
        source: caddy_rs_server::fdstore::FdStoreError,
    },
}

impl std::fmt::Display for BindFdsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "{error}"),
            Self::Bind { listener, source } => write!(
                formatter,
                "cannot bind `{listener}`: {source}; nothing was uploaded to the fd store, so the \
                 unit must not treat any descriptor as present"
            ),
            Self::Upload {
                listener,
                fd_name,
                source,
            } => write!(
                formatter,
                "cannot upload `{listener}` to the fd store as `{fd_name}`: {source}; the upload \
                 stopped at the first failure so the store is not partially populated"
            ),
            Self::Remove {
                listener,
                fd_name,
                source,
            } => write!(
                formatter,
                "cannot remove the stored descriptor `{fd_name}` for `{listener}`: {source}; \
                 nothing new was uploaded, but the previous descriptor may still be stored under \
                 that name, so the store is in an unknown state and the unit should be restarted \
                 with a clean fd store rather than trusted"
            ),
            Self::NameCollision {
                name,
                first,
                second,
            } => write!(
                formatter,
                "internal error: the FD name `{name}` is produced by both {first} and {second}; \
                 FD names must be injective over the listener plan, so this is a naming bug rather \
                 than a configuration problem"
            ),
        }
    }
}

impl std::error::Error for BindFdsError {}

/// A bound descriptor waiting to be handed to `systemd`, with its identity kept alongside it.
///
/// The descriptor is owned so that a failure part-way through the upload closes everything already
/// bound instead of leaking it: dropping this struct closes the socket. Nothing here is uploaded
/// twice, and an upload that stops early leaves no descriptor half-registered under a name `run`
/// would later adopt.
#[derive(Debug)]
struct BoundFd {
    entry: PlannedFd,
    /// Owned on Unix; never read directly, only borrowed as a raw descriptor for the upload.
    #[cfg(unix)]
    socket: OwnedFd,
}

/// Bind every planned listener, then upload each descriptor to the fd store (ADR-0047 §3, §6).
///
/// This is the real `bind-fds` body: stage 2 could only plan, so a unit that ran it without
/// `--dry-run` was refused outright. The order matters and is deliberate — **every** socket is
/// bound before **any** is uploaded. Binding and uploading in one interleaved pass would leave the
/// store holding descriptors for listeners 1..n when listener n+1 failed to bind, and `run` would
/// then adopt a set that does not match the plan. Binding first means a bind failure uploads
/// nothing at all, which is the "no partial state" ADR-0047 §6 requires.
///
/// Returns the number of descriptors uploaded so that the caller can print a real bound-versus-
/// reused summary rather than a plan.
///
/// # Errors
/// [`BindFdsError::Bind`] when a planned listener cannot be bound, [`BindFdsError::Upload`] when a
/// bound descriptor cannot be handed to the store. In both cases nothing remains uploaded: on a
/// bind failure no upload has happened yet, and on an upload failure the remaining sockets are
/// dropped with this function's locals.
#[cfg(unix)]
pub fn bind_and_upload(
    planned: &[PlannedFd],
    upload: &mut dyn FnMut(i32, &str) -> Result<(), caddy_rs_server::fdstore::FdStoreError>,
    remove: &mut dyn FnMut(&str) -> Result<(), caddy_rs_server::fdstore::FdStoreError>,
) -> Result<BindReport, BindFdsError> {
    // Refuse before binding anything when there is no store to upload to (ADR-0047 §6). Checking
    // first is the whole point: discovering an unset NOTIFY_SOCKET after binding would leave the
    // process having taken ports it then discards, which is exactly the partial state the ADR
    // forbids. It is also the cheaper failure to diagnose, since nothing was touched.
    require_notify_socket()?;
    bind_and_upload_body(planned, upload, remove)
}

/// What one `bind-fds` run did, so the caller can report it instead of printing a bare count.
#[cfg(unix)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BindReport {
    /// Descriptors bound and uploaded under a name that was not stored before.
    pub uploaded: usize,
    /// Names that were already stored and were therefore removed and re-uploaded.
    ///
    /// This is the idempotency counter: a re-run of `bind-fds` for unchanged configuration must
    /// report every listener here and none in [`uploaded`], and the store must hold exactly one
    /// descriptor per name afterwards rather than two.
    pub replaced: usize,
}

impl BindReport {
    /// The number of descriptors the store holds for this plan once the run has finished.
    ///
    /// Always equal to the plan length on success; named so a caller can assert the postcondition
    /// directly rather than reconstructing it.
    #[must_use]
    pub fn stored(&self) -> usize {
        self.uploaded + self.replaced
    }
}

/// The bind-then-upload body, split from [`bind_and_upload`] so tests can drive it with an injected
/// upload closure instead of a real systemd socket, without weakening the production entry point's
/// `NOTIFY_SOCKET` pre-check.
#[cfg(unix)]
fn bind_and_upload_body(
    planned: &[PlannedFd],
    upload: &mut dyn FnMut(i32, &str) -> Result<(), caddy_rs_server::fdstore::FdStoreError>,
    remove: &mut dyn FnMut(&str) -> Result<(), caddy_rs_server::fdstore::FdStoreError>,
) -> Result<BindReport, BindFdsError> {
    // Refuse UDP before binding anything: a UDP listener under fdstore mode is a configuration
    // error whose real cause is a missing prerequisite, not a runtime failure (DIV-0040).
    for entry in planned {
        if entry.network == Network::Udp {
            return Err(BindFdsError::Plan(ListenerPlanError {
                listen: entry.address(),
                reason:
                    "UDP listeners cannot be pre-bound by `bind-fds`: systemd socket activation \
                         for a UDP socket is a prerequisite that does not exist yet, so this \
                         listener must be left for `run` to bind (see DIV-0040 and ADR-0047)"
                        .to_owned(),
            }));
        }
    }

    // Phase 1: bind everything. A failure here has uploaded nothing.
    let mut bound: Vec<BoundFd> = Vec::with_capacity(planned.len());
    for entry in planned {
        let address = entry.address();
        let socket = bind_one(entry).map_err(|source| BindFdsError::Bind {
            listener: address,
            source,
        })?;
        bound.push(BoundFd {
            entry: entry.clone(),
            socket,
        });
    }

    // Phase 2: drop any descriptor already stored under a name this plan owns, then upload.
    //
    // This is what makes a re-run idempotent (ADR-0047 §5). systemd does not document an interface
    // for enumerating the store, so the helper cannot ask what is already there; the safe default
    // is to remove every name the plan owns and re-upload, which converges on exactly one stored
    // descriptor per planned listener no matter how many times it runs. The limitation is recorded
    // in `docs/INSTALL.md` rather than worked around here, because there is nothing to work around:
    // an undocumented interface is not an interface.
    //
    // Removal happens after binding, not before. A bind failure must leave the store untouched, so
    // the pre-existing descriptors are still valid; removing first would destroy working state and
    // then fail to replace it.
    let mut report = BindReport::default();
    for entry in &bound {
        remove(&entry.entry.fd_name).map_err(|source| BindFdsError::Remove {
            listener: entry.entry.address(),
            fd_name: entry.entry.fd_name.clone(),
            source,
        })?;
        report.replaced += 1;
    }

    // Phase 3: upload everything that was bound.
    for entry in &bound {
        use std::os::unix::io::AsRawFd as _;
        let raw = entry.socket.as_raw_fd();
        upload(raw, &entry.entry.fd_name).map_err(|source| BindFdsError::Upload {
            listener: entry.entry.address(),
            fd_name: entry.entry.fd_name.clone(),
            source,
        })?;
    }
    Ok(report)
}

/// Fail unless `NOTIFY_SOCKET` names a usable store, before any socket is bound (ADR-0047 §6).
///
/// Split out so the check is testable without binding a port or mutating the process environment.
/// An empty value is rejected as well as a missing one: systemd never sets it empty, and treating
/// empty as "no store" is what `notify::send` does for payloads, so a unit that ran with it unset
/// would otherwise appear to succeed.
#[cfg(unix)]
fn require_notify_socket() -> Result<(), BindFdsError> {
    let configured = std::env::var_os(caddy_rs_core::notify::NOTIFY_SOCKET_ENV);
    check_notify_socket(configured.as_deref())
}

/// The pure half of [`require_notify_socket`]: an unset **or empty** value means there is no store.
///
/// Empty counts as absent because systemd never sets the variable empty, and treating it as a store
/// would turn "the unit forgot to configure socket activation" into a confusing socket error much
/// later. Testing this through an argument rather than the process environment keeps the tests
/// order-independent, since environment access is global.
#[cfg(unix)]
fn check_notify_socket(configured: Option<&std::ffi::OsStr>) -> Result<(), BindFdsError> {
    match configured.filter(|value| !value.is_empty()) {
        Some(_) => Ok(()),
        None => Err(no_notify_socket_error()),
    }
}

/// The error for an unset `NOTIFY_SOCKET`, shared by the pre-check and its test.
#[cfg(unix)]
fn no_notify_socket_error() -> BindFdsError {
    BindFdsError::Upload {
        listener: "none".to_owned(),
        fd_name: "none".to_owned(),
        source: caddy_rs_server::fdstore::FdStoreError::NotifySocketUnset,
    }
}

/// Bind one planned TCP listener, reusing the server's own bind path so the helper and `run` cannot
/// disagree about socket options.
#[cfg(unix)]
fn bind_one(entry: &PlannedFd) -> std::io::Result<OwnedFd> {
    use std::net::TcpListener;
    let host = if entry.host.is_empty() {
        "0.0.0.0"
    } else {
        entry.host.as_str()
    };
    let listener = TcpListener::bind((host, entry.port))?;
    Ok(OwnedFd::from(listener))
}

/// Build the plan for a configuration, deriving an FD name for every listener.
///
/// Returns the plan and its names, or an error when the configuration has no plannable listener or
/// a name is not injective.
pub fn plan_bind_fds(config: &caddy_rs_core::Config) -> Result<Vec<PlannedFd>, BindFdsError> {
    let listens = configured_listens(config);
    let plan: ListenerPlan = plan_listeners(listens.iter()).map_err(BindFdsError::Plan)?;
    let planned: Vec<PlannedFd> = plan
        .listeners()
        .iter()
        .map(|listener| PlannedFd {
            network: listener.network,
            host: listener.host.clone(),
            port: listener.port,
            fd_name: fd_name(listener.network, &listener.host, listener.port),
        })
        .collect();
    assert_injective(&planned)?;
    Ok(planned)
}

/// Names this plan no longer owns, and which must therefore be removed from the store.
///
/// ADR-0047 §5: a listener removed from the configuration must actually stop listening and free
/// its port. The helper cannot enumerate the store (see `docs/INSTALL.md`), so it cannot discover
/// stale names by asking; it has to be told the previous plan. `previous` is what the last run
/// stored — in practice the `LISTEN_FDNAMES` the unit recorded, or the plan from the configuration
/// the service last ran with.
///
/// Returns the names in `previous` that `current` does not contain, sorted and de-duplicated so the
/// caller's log line is deterministic. A name present in both plans is not stale: it is being
/// re-uploaded, and [`bind_and_upload`] already removes-then-uploads it.
#[must_use]
pub fn stale_names(previous: &[PlannedFd], current: &[PlannedFd]) -> Vec<String> {
    let live: std::collections::BTreeSet<&str> =
        current.iter().map(|entry| entry.fd_name.as_str()).collect();
    let stale: std::collections::BTreeSet<String> = previous
        .iter()
        .filter(|entry| !live.contains(entry.fd_name.as_str()))
        .map(|entry| entry.fd_name.clone())
        .collect();
    stale.into_iter().collect()
}

/// Remove every name in `stale` from the store, so a dropped listener stops holding its port.
///
/// Separate from [`bind_and_upload`] because the two run at different points in the unit: the
/// upload happens once per start, while stale removal must happen even when the current plan is
/// empty (every listener was removed). Failing here is loud for the same reason a removal failure
/// during upload is loud: a port that should be free is still held, and the operator needs to know
/// which name caused it rather than discovering it from a bind error later.
///
/// # Errors
/// [`BindFdsError::Remove`] naming the first stale FD that could not be dropped. Names before it in
/// sorted order were already removed; the ones after it were not attempted.
#[cfg(unix)]
pub fn remove_stale(
    stale: &[String],
    remove: &mut dyn FnMut(&str) -> Result<(), caddy_rs_server::fdstore::FdStoreError>,
) -> Result<usize, BindFdsError> {
    for name in stale {
        remove(name).map_err(|source| BindFdsError::Remove {
            listener: name.clone(),
            fd_name: name.clone(),
            source,
        })?;
    }
    Ok(stale.len())
}

/// Fail if two distinct plan entries produced the same name.
fn assert_injective(planned: &[PlannedFd]) -> Result<(), BindFdsError> {
    let mut seen: BTreeMap<&str, &PlannedFd> = BTreeMap::new();
    for entry in planned {
        if let Some(previous) = seen.get(entry.fd_name.as_str()) {
            return Err(BindFdsError::NameCollision {
                name: entry.fd_name.clone(),
                first: format!("{}/{}", previous.network.as_str(), previous.address()),
                second: format!("{}/{}", entry.network.as_str(), entry.address()),
            });
        }
        seen.insert(entry.fd_name.as_str(), entry);
    }
    Ok(())
}

/// Render the plan for a human reading a bug report (ADR-0047 §2).
///
/// Every field a report needs is on its own row — protocol, address, port and FD name — because the
/// output's purpose is to be pasted verbatim when the unit and the configuration disagree.
pub fn render_plan(planned: &[PlannedFd], dry_run: bool) -> String {
    let mut output = String::new();
    let mode = if dry_run {
        "dry run: no sockets were bound and nothing was uploaded"
    } else {
        "planned"
    };
    let _ = writeln!(output, "caddy-rs bind-fds ({mode})");
    let _ = writeln!(output, "listeners: {}", planned.len());
    if planned.is_empty() {
        let _ = writeln!(
            output,
            "no plannable listeners: the configuration declares no `apps.http.servers.*.listen` \
             entry with a concrete TCP or UDP port"
        );
        return output;
    }
    // Widths are computed rather than hard-coded so a long address does not misalign the table.
    // Header labels count towards the widths, otherwise a short value leaves the header wider than
    // the column and the table misaligns.
    let name_width = planned
        .iter()
        .map(|entry| entry.fd_name.len())
        .chain(std::iter::once("FD NAME".len()))
        .max()
        .unwrap_or(0);
    let address_width = planned
        .iter()
        .map(|entry| entry.address().len())
        .chain(std::iter::once("ADDRESS".len()))
        .max()
        .unwrap_or(0);
    let _ = writeln!(
        output,
        "  {:<4}  {:<address_width$}  {:<5}  {:<name_width$}",
        "PROTO",
        "ADDRESS",
        "PORT",
        "FD NAME",
        address_width = address_width,
        name_width = name_width,
    );
    for entry in planned {
        let _ = writeln!(
            output,
            "  {:<4}  {:<address_width$}  {:<5}  {:<name_width$}",
            entry.network.as_str(),
            entry.address(),
            entry.port,
            entry.fd_name,
            address_width = address_width,
            name_width = name_width,
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(listens: &[&str]) -> caddy_rs_core::Config {
        let listens: Vec<String> = listens.iter().map(|value| value.to_string()).collect();
        caddy_rs_core::Config::from_value(serde_json::json!({
            "apps": {"http": {"servers": {"srv0": {"listen": listens}}}}
        }))
        .expect("configuration decodes")
    }

    #[test]
    fn the_name_is_a_pure_function_of_the_plan_entry() {
        // Same entry, same name, every time: the helper and `run` must agree.
        assert_eq!(
            fd_name(Network::Tcp, "", 443),
            fd_name(Network::Tcp, "", 443)
        );
        assert_eq!(fd_name(Network::Tcp, "", 443), "caddy-tcp--443");
        assert_eq!(
            fd_name(Network::Udp, "example.com", 8443),
            "caddy-udp-example.com-8443"
        );
    }

    #[test]
    fn distinct_wildcards_get_distinct_names() {
        // `:443`, `0.0.0.0:443` and `[::]:443` are three distinct plan entries, so they must be
        // three distinct names - naming them alike would collapse three listeners into one stored
        // descriptor.
        let wildcard = fd_name(Network::Tcp, "", 443);
        let v4 = fd_name(Network::Tcp, "0.0.0.0", 443);
        let v6 = fd_name(Network::Tcp, "[::]", 443);
        assert_ne!(wildcard, v4);
        assert_ne!(wildcard, v6);
        assert_ne!(v4, v6);
    }

    #[test]
    fn ipv6_names_are_bracketed_and_never_parsed_by_splitting_on_the_delimiter() {
        let name = fd_name(Network::Tcp, "[::1]", 80);
        assert!(name.contains('['), "IPv6 must stay bracketed: {name}");
        assert!(
            !name.contains(':'),
            "an FD name must never contain ':', because LISTEN_FDNAMES uses it as the list \
             separator and a raw colon would split the name on the way back to `run`: {name}"
        );
        // The port is the last component only because the host cannot contain the delimiter; this
        // asserts the property the scheme relies on rather than a parse.
        assert!(name.ends_with("-80"));
        // The property the scheme actually relies on: the escaped host component contains no
        // delimiter, so the port is recoverable as the final component. Note the name is still
        // never *parsed* in production - this only pins the invariant that makes it safe.
        let escaped = escape_host("[::1]");
        assert!(
            !escaped.contains(DELIMITER),
            "the escaped host must not contain the delimiter: {escaped}"
        );
        assert_eq!(name, format!("caddy-tcp-{escaped}-80"));
    }

    #[test]
    fn an_escaped_host_can_never_be_confused_with_a_delimited_one() {
        // A host containing the delimiter character would break injectivity if it were emitted
        // verbatim; the escape is what prevents it.
        let escaped = fd_name(Network::Tcp, "a-b", 80);
        let plain = fd_name(Network::Tcp, "a", 80);
        assert_ne!(escaped, plain);
        // `%` is escaped so escaping itself is unambiguous.
        assert_eq!(escape_host("%3A"), "%253A");
        assert_ne!(escape_host(":"), escape_host("%3A"));
    }

    #[test]
    fn names_are_injective_across_a_realistic_plan() {
        let planned = plan_bind_fds(&config(&[
            ":443",
            "0.0.0.0:443",
            "[::]:443",
            "127.0.0.1:443",
            "[::1]:443",
            "example.com:443",
            ":80",
            "localhost:8080",
        ]))
        .expect("plan builds");
        let mut names: Vec<&str> = planned.iter().map(|entry| entry.fd_name.as_str()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "every FD name must be unique");
    }

    #[test]
    fn a_round_trip_through_listen_fdnames_preserves_every_name() {
        // Stage 3 sets `LISTEN_FDNAMES` to the names joined by ':'; systemd hands that back
        // verbatim. The property that matters is that no name contains the joiner, so the list
        // survives the round trip intact.
        let planned =
            plan_bind_fds(&config(&[":443", "127.0.0.1:80", "[::1]:8080"])).expect("plan builds");
        let names: Vec<&str> = planned.iter().map(|entry| entry.fd_name.as_str()).collect();
        let joined = names.join(":");
        let recovered: Vec<&str> = joined.split(':').collect();
        assert_eq!(
            recovered, names,
            "LISTEN_FDNAMES round trip must preserve every name"
        );
    }

    #[test]
    fn the_plan_report_names_every_field_a_bug_report_needs() {
        let planned = plan_bind_fds(&config(&[":443"])).expect("plan builds");
        let rendered = render_plan(&planned, true);
        assert!(rendered.contains("PROTO"), "{rendered}");
        assert!(rendered.contains("ADDRESS"), "{rendered}");
        assert!(rendered.contains("PORT"), "{rendered}");
        assert!(rendered.contains("FD NAME"), "{rendered}");
        assert!(rendered.contains("tcp"), "{rendered}");
        assert!(rendered.contains(":443"), "{rendered}");
        assert!(rendered.contains("caddy-tcp--443"), "{rendered}");
        assert!(
            rendered.contains("no sockets were bound"),
            "a dry run must say so: {rendered}"
        );
    }

    #[test]
    fn the_plan_is_deterministic_regardless_of_configuration_order() {
        let forward = plan_bind_fds(&config(&[":443", "127.0.0.1:80"])).expect("plan builds");
        let reverse = plan_bind_fds(&config(&["127.0.0.1:80", ":443"])).expect("plan builds");
        assert_eq!(
            forward, reverse,
            "plan order must not depend on config order"
        );
    }

    #[test]
    fn a_configuration_with_no_plannable_listener_says_so() {
        let planned = plan_bind_fds(&config(&[])).expect("an empty plan is not an error");
        assert!(planned.is_empty());
        let rendered = render_plan(&planned, true);
        assert!(rendered.contains("no plannable listeners"), "{rendered}");
    }

    // ---------------------------------------------------------------------------------------
    // Stage 3: the real upload path (T-CORE-133 criteria 2 and 3).
    // ---------------------------------------------------------------------------------------

    /// A plan entry for an ephemeral loopback port, so the bind cannot collide with anything.
    fn loopback_plan(port: u16) -> Vec<PlannedFd> {
        vec![PlannedFd {
            network: Network::Tcp,
            host: "127.0.0.1".to_owned(),
            port,
            fd_name: fd_name(Network::Tcp, "127.0.0.1", port),
        }]
    }

    /// A port that is free right now: bind a probe, read the port, drop it.
    fn free_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("probe binds")
            .local_addr()
            .expect("probe has an address")
            .port()
    }

    #[test]
    fn with_a_store_configured_every_planned_listener_is_bound_and_uploaded_by_name() {
        // Criterion 1 at the helper level: one upload per plan entry, carrying that entry's FD
        // NAME. The name is what `run` later looks the descriptor up by, so a wrong name here is
        // the failure mode this whole design exists to prevent.
        let port = free_port();
        let planned = loopback_plan(port);
        let mut uploads: Vec<(i32, String)> = Vec::new();
        let report = bind_and_upload_body(
            &planned,
            &mut |fd, name| {
                assert!(fd >= 0, "a real descriptor must be uploaded, got {fd}");
                uploads.push((fd, name.to_owned()));
                Ok(())
            },
            &mut |_name| Ok(()),
        )
        .expect("bind and upload succeeds");
        assert_eq!(report.stored(), 1);
        assert_eq!(
            uploads.len(),
            1,
            "exactly one descriptor per planned listener: {uploads:?}"
        );
        assert_eq!(
            uploads[0].1,
            fd_name(Network::Tcp, "127.0.0.1", port),
            "the uploaded FDNAME must be the plan entry's name"
        );
    }

    /// A stand-in for the systemd fd store that counts what the helper does to it.
    ///
    /// systemd offers no enumeration interface (ADR-0047 §5), so the helper cannot ask what is
    /// stored; it must instead remove each name it owns and re-upload. This models exactly that
    /// contract: `names` is what the store holds, keyed by name, and a name holds at most one
    /// descriptor no matter how many times it is uploaded.
    #[derive(Default)]
    struct MockStore {
        names: Vec<String>,
        uploads: usize,
        removals: usize,
    }

    impl MockStore {
        fn upload(
            &mut self,
            _fd: i32,
            name: &str,
        ) -> Result<(), caddy_rs_server::fdstore::FdStoreError> {
            self.uploads += 1;
            // A store keyed by FDNAME holds one descriptor per name: re-uploading without removing
            // first is precisely the duplicate this test exists to catch.
            assert!(
                !self.names.iter().any(|existing| existing == name),
                "the store already holds `{name}`, so uploading it again without removing it \
                 first would create a duplicate descriptor"
            );
            self.names.push(name.to_owned());
            Ok(())
        }

        fn remove(&mut self, name: &str) -> Result<(), caddy_rs_server::fdstore::FdStoreError> {
            self.removals += 1;
            self.names.retain(|existing| existing != name);
            Ok(())
        }
    }

    #[test]
    fn re_running_for_unchanged_configuration_never_duplicates_a_stored_descriptor() {
        // T-CORE-134 criterion 1, the whole point of the stage: `bind-fds` runs from
        // `ExecStartPre` on every service start, so a second run for an unchanged configuration
        // must converge on the SAME store contents rather than accumulating descriptors. The
        // assertion is on the store's final contents, not on a counter, because a duplicate
        // descriptor is the failure and a count alone would not prove its absence.
        let port = free_port();
        let planned = loopback_plan(port);
        // `RefCell` because both closures need the same store and `bind_and_upload_body` takes
        // them simultaneously; interior mutability keeps the assertions on one object.
        let store = std::cell::RefCell::new(MockStore::default());

        let first = bind_and_upload_body(
            &planned,
            &mut |fd, name| store.borrow_mut().upload(fd, name),
            &mut |name| store.borrow_mut().remove(name),
        )
        .expect("the first run succeeds");
        let store = store.into_inner();
        assert_eq!(first.stored(), 1);
        assert_eq!(
            store.names.len(),
            1,
            "the first run stores exactly one descriptor"
        );

        // Second run: identical configuration, so the port is already held by this process only
        // through the descriptor the store holds. Rebind must therefore succeed only because the
        // first run's socket was handed to the store and released by this process.
        let store = std::cell::RefCell::new(store);
        let second = bind_and_upload_body(
            &planned,
            &mut |fd, name| store.borrow_mut().upload(fd, name),
            &mut |name| store.borrow_mut().remove(name),
        )
        .expect("a re-run for unchanged configuration succeeds");
        let store = store.into_inner();
        assert_eq!(second.stored(), 1);
        assert_eq!(
            store.names.len(),
            1,
            "after a re-run the store must still hold exactly one descriptor, got {:?}",
            store.names
        );
        assert_eq!(
            store.names[0],
            fd_name(Network::Tcp, "127.0.0.1", port),
            "the surviving descriptor must be the plan's own name"
        );
        assert_eq!(
            store.removals, 2,
            "each run must remove every name it owns before re-uploading, so removals equal runs \
             times listeners"
        );
    }

    #[test]
    fn a_removal_failure_is_reported_rather_than_silently_uploading_anyway() {
        // If the store refuses a removal, uploading would produce the duplicate this task exists to
        // prevent. The helper must stop and say the store is in an unknown state.
        let port = free_port();
        let planned = loopback_plan(port);
        let mut uploads = 0usize;
        let error = bind_and_upload_body(
            &planned,
            &mut |_fd, _name| {
                uploads += 1;
                Ok(())
            },
            &mut |_name| {
                Err(caddy_rs_server::fdstore::FdStoreError::Socket(
                    std::io::Error::other("mock store refused the removal"),
                ))
            },
        )
        .expect_err("a removal failure must surface");
        assert!(
            matches!(error, BindFdsError::Remove { .. }),
            "a removal failure must surface as Remove, not Upload: {error:?}"
        );
        assert_eq!(
            uploads, 0,
            "nothing may be uploaded after a removal failure, or the store would hold a duplicate"
        );
        let message = error.to_string();
        assert!(
            message.contains("unknown state"),
            "the error must warn that the store is in an unknown state: {message}"
        );
    }

    #[test]
    fn a_removed_listener_frees_its_port_and_the_port_is_rebindable() {
        // T-CORE-134 criterion 2, and the half that matters operationally: removing a site from the
        // configuration must let something else take that port. Asserting only that a removal
        // message was sent would be satisfied by a store that still held the descriptor, so this
        // test drops the stored copy and then PROVES the port is free by binding it.
        let port = free_port();
        let previous = loopback_plan(port);
        // The new configuration drops that listener entirely.
        let current: Vec<PlannedFd> = Vec::new();

        let stale = stale_names(&previous, &current);
        assert_eq!(
            stale.len(),
            1,
            "the removed listener must be reported stale: {stale:?}"
        );
        assert_eq!(stale[0], fd_name(Network::Tcp, "127.0.0.1", port));

        // Stand in for the store: the descriptor is held here, and dropping it is what actually
        // releases the port.
        let mut held = Some(
            std::net::TcpListener::bind(("127.0.0.1", port)).expect("the plan's port is bindable"),
        );
        // While the store holds it, the port must NOT be available: this is the control that makes
        // the post-removal assertion meaningful rather than trivially true.
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", port)).is_err(),
            "precondition: a port held by the store must not be bindable, otherwise the \
             rebindability check below proves nothing"
        );

        let removed = remove_stale(&stale, &mut |name| {
            assert_eq!(name, stale[0], "the removal must name the stale FD");
            // The store drops its reference, which closes the socket.
            held = None;
            Ok(())
        })
        .expect("removing a stale name succeeds");
        assert_eq!(removed, 1);

        // The actual criterion: the port is closed and something else can take it.
        std::net::TcpListener::bind(("127.0.0.1", port))
            .expect("a removed listener must leave its port closed and rebindable");
    }

    #[test]
    fn a_listener_present_in_both_plans_is_not_treated_as_stale() {
        // The complement of the test above: a listener that survived the reload is re-uploaded by
        // bind_and_upload, so calling it stale would remove the descriptor of a live listener and
        // leave the port free while `run` still expects to adopt it.
        let port = free_port();
        let previous = loopback_plan(port);
        let current = loopback_plan(port);
        assert!(
            stale_names(&previous, &current).is_empty(),
            "an unchanged listener must not be reported stale"
        );
    }

    #[test]
    fn stale_removal_names_the_fd_that_could_not_be_dropped() {
        // A failed removal leaves a port held, so the message must identify which one rather than
        // reporting only that cleanup failed.
        let port = free_port();
        let stale = vec![fd_name(Network::Tcp, "127.0.0.1", port)];
        let error = remove_stale(&stale, &mut |_name| {
            Err(caddy_rs_server::fdstore::FdStoreError::Socket(
                std::io::Error::other("mock store refused"),
            ))
        })
        .expect_err("a failed stale removal must surface");
        assert!(
            matches!(error, BindFdsError::Remove { .. }),
            "a stale removal failure must surface as Remove: {error:?}"
        );
        assert!(
            error.to_string().contains(&stale[0]),
            "the error must name the FD that could not be dropped: {error}"
        );
    }

    #[test]
    fn a_bind_failure_uploads_nothing_at_all() {
        // Criterion 2's ordering guarantee, asserted on the observable rather than by reading the
        // source: hold the port so the bind must fail, then confirm the upload closure was never
        // called. If the implementation interleaved bind and upload, the FIRST entry would already
        // have been uploaded when the second failed.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
        let busy = held.local_addr().expect("held port has an address").port();

        let mut planned = loopback_plan(free_port());
        planned.push(PlannedFd {
            network: Network::Tcp,
            host: "127.0.0.1".to_owned(),
            port: busy,
            fd_name: fd_name(Network::Tcp, "127.0.0.1", busy),
        });

        let mut upload_calls = 0usize;
        let mut remove_calls = 0usize;
        let error = bind_and_upload_body(
            &planned,
            &mut |_fd, _name| {
                upload_calls += 1;
                Ok(())
            },
            &mut |_name| {
                remove_calls += 1;
                Ok(())
            },
        )
        .expect_err("binding an in-use port must fail");
        assert!(
            matches!(error, BindFdsError::Bind { .. }),
            "a bind failure must surface as Bind, got {error:?}"
        );
        assert_eq!(
            upload_calls, 0,
            "a bind failure must upload NOTHING: every socket is bound before any is uploaded"
        );
        assert_eq!(
            remove_calls, 0,
            "a bind failure must also remove NOTHING: removing first would destroy the working \
             descriptors and then fail to replace them"
        );
        let message = error.to_string();
        assert!(
            message.contains(&busy.to_string()),
            "the error must name the address that failed: {message}"
        );
    }

    #[test]
    fn an_unset_or_empty_notify_socket_is_refused_but_a_set_one_is_accepted() {
        // Criterion 3, exercised through the real precheck rather than through the error
        // constructor: a test that only builds the error would pass even if the precheck were
        // never called from bind_and_upload.
        use std::ffi::OsStr;
        assert!(
            check_notify_socket(None).is_err(),
            "an UNSET NOTIFY_SOCKET must be refused before anything is bound"
        );
        assert!(
            check_notify_socket(Some(OsStr::new(""))).is_err(),
            "an EMPTY NOTIFY_SOCKET must be refused: systemd never sets it empty, so empty means              the unit has no store to upload to"
        );
        assert!(
            check_notify_socket(Some(OsStr::new("/run/systemd/notify"))).is_ok(),
            "a set NOTIFY_SOCKET must be accepted, otherwise the helper refuses to work at all"
        );
        // And the production entry point must consult it: with no store configured in this test
        // process, bind_and_upload must fail before binding the free port we hand it.
        let port = free_port();
        let mut upload_calls = 0usize;
        let error = bind_and_upload(
            &loopback_plan(port),
            &mut |_f, _n| {
                upload_calls += 1;
                Ok(())
            },
            &mut |_n| Ok(()),
        )
        .expect_err("without NOTIFY_SOCKET the production entry point must refuse");
        assert_eq!(upload_calls, 0, "nothing may be uploaded without a store");
        assert!(
            error.to_string().contains("NOTIFY_SOCKET"),
            "the refusal must name NOTIFY_SOCKET: {error}"
        );
        // The port must still be free: the refusal happened before any bind.
        std::net::TcpListener::bind(("127.0.0.1", port))
            .expect("the refused run must not have bound the port");
    }

    #[test]
    fn the_notify_socket_error_is_precise_and_typed() {
        let error = no_notify_socket_error();
        let message = error.to_string();
        assert!(
            message.contains("NOTIFY_SOCKET"),
            "the message must name NOTIFY_SOCKET: {message}"
        );
        assert!(
            message.contains("fd store"),
            "the message must say what is missing, the fd store: {message}"
        );
        assert!(
            matches!(
                error,
                BindFdsError::Upload {
                    source: caddy_rs_server::fdstore::FdStoreError::NotifySocketUnset,
                    ..
                }
            ),
            "an unset socket must be its own error case, not a generic socket error: {error:?}"
        );
    }

    #[test]
    fn a_udp_listener_is_refused_before_any_bind_so_nothing_is_uploaded() {
        // Criterion 6: UDP under fdstore mode is a loud, actionable error naming the missing
        // prerequisite, and it happens before anything is bound or uploaded.
        let planned = vec![PlannedFd {
            network: Network::Udp,
            host: "127.0.0.1".to_owned(),
            port: free_port(),
            fd_name: fd_name(Network::Udp, "127.0.0.1", 1234),
        }];
        let mut upload_calls = 0usize;
        let error = bind_and_upload_body(
            &planned,
            &mut |_f, _n| {
                upload_calls += 1;
                Ok(())
            },
            &mut |_n| Ok(()),
        )
        .expect_err("a UDP listener must be refused");
        assert_eq!(upload_calls, 0, "a refused UDP plan must upload nothing");
        let message = error.to_string();
        assert!(
            message.contains("UDP") && message.contains("prerequisite"),
            "the error must name UDP and the missing prerequisite: {message}"
        );
    }

    #[test]
    fn an_upload_failure_names_the_listener_and_its_fd_name() {
        // The operator's next action is to find which socket failed, so both identities are named.
        let port = free_port();
        let planned = loopback_plan(port);
        let error = bind_and_upload_body(
            &planned,
            &mut |_fd, _name| {
                Err(caddy_rs_server::fdstore::FdStoreError::Socket(
                    std::io::Error::other("mock store rejected the descriptor"),
                ))
            },
            &mut |_n| Ok(()),
        )
        .expect_err("an upload failure must surface");
        assert!(
            matches!(error, BindFdsError::Upload { .. }),
            "an upload failure must surface as Upload: {error:?}"
        );
        let message = error.to_string();
        assert!(
            message.contains(&port.to_string()),
            "the error must name the failed listener's address: {message}"
        );
        assert!(
            message.contains(&fd_name(Network::Tcp, "127.0.0.1", port)),
            "the error must name the attempted FDNAME: {message}"
        );
    }
}
