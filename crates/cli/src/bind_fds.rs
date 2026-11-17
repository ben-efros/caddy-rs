//! `caddy-rs bind-fds` — pre-bind the configured listeners and upload them to `systemd`'s fd store
//! (ADR-0047 §2, §3).
//!
//! Stage 2 of the five stages ADR-0047 specifies: this module computes the plan, derives the FD
//! names it would use, and (under `--dry-run`) prints both and exits **without binding or
//! uploading**. Stage 3 adds the real `FDSTORE=1` upload and `run` adoption; `T-CORE-133` owns it.
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
}

impl std::fmt::Display for BindFdsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "{error}"),
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
}
