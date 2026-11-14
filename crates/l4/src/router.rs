//! SNI route table with generation-scoped atomic reloads.
//!
//! [`SniRouter`] holds the current [`SniTable`] in an [`ArcSwap`], so a reload swaps a complete,
//! immutable generation in one atomic store: new connections see the new table, while connections
//! that already looked up a [`Route`] keep their `Arc<Route>` and finish on the generation they
//! started with. A route table is never mutated in place.
//!
//! # Matching
//!
//! 1. Exact hostnames win (case-insensitive; SNI is normalised to lowercase).
//! 2. Wildcard routes (`*.example.com`) match any SNI that ends in `.example.com` with at least one
//!    label in front (`a.example.com`, `a.b.example.com`); the apex `example.com` does not match.
//!    When several wildcards match, the **longest suffix wins** (`*.b.example.com` beats
//!    `*.example.com` for `a.b.example.com`).
//! 3. Everything else — including a missing or empty SNI — gets the fallback route.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::actions::{validate_dns_name, ActionConfigError, SniAction};

/// A validated route definition: an exact hostname or a `*.` wildcard plus its action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDefinition {
    host: String,
    action: SniAction,
}

impl RouteDefinition {
    /// Validates `host` (exact or `*.` wildcard) and pairs it with an already-validated action.
    pub fn new(host: impl Into<String>, action: SniAction) -> Result<Self, RouteError> {
        let host = host.into();
        let (normalized, _) = validate_route_host(&host)?;
        Ok(Self {
            host: normalized,
            action,
        })
    }

    /// The normalised hostname pattern (`example.com` or `*.example.com`).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The action this route runs.
    pub fn action(&self) -> &SniAction {
        &self.action
    }
}

/// A compiled route. In-flight connections hold an `Arc<Route>` so a reload cannot change it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    host: String,
    wildcard_suffix: Option<String>,
    action: SniAction,
}

impl Route {
    /// The fallback route (empty host) that serves unmatched lookups.
    pub(crate) fn fallback(action: SniAction) -> Self {
        Self {
            host: String::new(),
            wildcard_suffix: None,
            action,
        }
    }

    /// The route pattern (`example.com`, `*.example.com`, or `""` for the fallback route).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether this route was declared as a wildcard.
    pub fn is_wildcard(&self) -> bool {
        self.wildcard_suffix.is_some()
    }

    /// The suffix a wildcard matches (`.example.com`), if this is a wildcard route.
    pub fn wildcard_suffix(&self) -> Option<&str> {
        self.wildcard_suffix.as_deref()
    }

    /// The validated action for this route.
    pub fn action(&self) -> &SniAction {
        &self.action
    }

    /// Short name of the action, for logs and tests.
    pub fn action_kind(&self) -> &'static str {
        self.action.kind()
    }
}

/// An invalid route table: a malformed hostname or a duplicate pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// The hostname pattern is not valid.
    InvalidHost {
        /// The rejected pattern.
        host: String,
        /// Why it was rejected.
        source: ActionConfigError,
    },
    /// The same pattern was defined twice.
    DuplicateHost(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost { host, source } => {
                write!(f, "invalid route host {host:?}: {source}")
            }
            Self::DuplicateHost(host) => write!(f, "duplicate route host {host:?}"),
        }
    }
}

impl std::error::Error for RouteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHost { source, .. } => Some(source),
            Self::DuplicateHost(_) => None,
        }
    }
}

/// Validates and normalises a route hostname; returns `(normalised, wildcard suffix)`.
fn validate_route_host(host: &str) -> Result<(String, Option<String>), RouteError> {
    let trimmed = host.trim();
    let invalid = |source: ActionConfigError| RouteError::InvalidHost {
        host: host.to_owned(),
        source,
    };
    if let Some(rest) = trimmed.strip_prefix("*.") {
        let suffix = validate_dns_name("host", rest).map_err(invalid)?;
        return Ok((format!("*.{suffix}"), Some(format!(".{suffix}"))));
    }
    let exact = validate_dns_name("host", trimmed).map_err(invalid)?;
    Ok((exact, None))
}

/// An immutable generation of the route table.
#[derive(Debug)]
pub struct SniTable {
    exact: HashMap<String, Arc<Route>>,
    /// Sorted by suffix length, longest first, so the first match is the longest suffix.
    wildcards: Vec<(String, Arc<Route>)>,
    fallback: Arc<Route>,
}

impl SniTable {
    /// Builds a table from validated definitions, with `fallback` used for unmatched lookups.
    fn build(routes: &[RouteDefinition], fallback: Arc<Route>) -> Result<Self, RouteError> {
        let mut exact = HashMap::new();
        // Insert wildcards through a map so a duplicate is rejected wherever it appears in the
        // definition list, not just next to its twin after the length sort.
        let mut wildcard_map: HashMap<String, Arc<Route>> = HashMap::new();
        for definition in routes {
            let (normalized, suffix) = validate_route_host(&definition.host)?;
            let route = Arc::new(Route {
                host: normalized.clone(),
                wildcard_suffix: suffix.clone(),
                action: definition.action.clone(),
            });
            match suffix {
                Some(suffix) => {
                    if wildcard_map.insert(suffix.clone(), route).is_some() {
                        return Err(RouteError::DuplicateHost(format!("*{suffix}")));
                    }
                }
                None => {
                    if exact.insert(normalized.clone(), route).is_some() {
                        return Err(RouteError::DuplicateHost(normalized));
                    }
                }
            }
        }
        let mut wildcards: Vec<(String, Arc<Route>)> = wildcard_map.into_iter().collect();
        wildcards.sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        Ok(Self {
            exact,
            wildcards,
            fallback,
        })
    }

    /// Looks up an SNI in this generation, returning the fallback route when nothing matches.
    ///
    /// The returned `Arc<Route>` is independent of the generation: a later reload cannot change it.
    pub fn lookup(&self, sni: Option<&str>) -> Arc<Route> {
        let Some(sni) = sni else {
            return Arc::clone(&self.fallback);
        };
        let sni = sni.trim().to_ascii_lowercase();
        if sni.is_empty() {
            return Arc::clone(&self.fallback);
        }
        if let Some(route) = self.exact.get(&sni) {
            return Arc::clone(route);
        }
        for (suffix, route) in &self.wildcards {
            if let Some(prefix) = sni.strip_suffix(suffix.as_str()) {
                // Only match at a label boundary and require at least one well-formed label
                // before the suffix: "a.b.example.com" matches, ".example.com" and
                // "a..example.com" (empty labels) do not.
                let well_formed_prefix = !prefix.is_empty()
                    && !prefix.ends_with('.')
                    && !prefix.split('.').any(|label| label.is_empty());
                if well_formed_prefix {
                    return Arc::clone(route);
                }
            }
        }
        Arc::clone(&self.fallback)
    }

    /// Number of routes (exact + wildcard) in this generation.
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }

    /// Whether this generation has no routes.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }

    /// Number of wildcard routes.
    pub fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }

    /// The fallback route of this generation.
    pub fn fallback(&self) -> &Arc<Route> {
        &self.fallback
    }
}

/// The SNI router: an atomically replaceable route table plus its stable fallback.
#[derive(Debug)]
pub struct SniRouter {
    generation: ArcSwap<SniTable>,
    fallback: Arc<Route>,
}

impl SniRouter {
    /// Builds a router whose first generation contains `routes`; unmatched lookups use
    /// `fallback_action` (validated by the caller's [`SniAction`] constructors).
    pub fn new(
        routes: Vec<RouteDefinition>,
        fallback_action: SniAction,
    ) -> Result<Self, RouteError> {
        let fallback = Arc::new(Route::fallback(fallback_action));
        let table = SniTable::build(&routes, Arc::clone(&fallback))?;
        Ok(Self {
            generation: ArcSwap::from_pointee(table),
            fallback,
        })
    }

    /// Builds a router with no routes; every lookup uses the fallback.
    pub fn empty(fallback_action: SniAction) -> Self {
        Self::new(Vec::new(), fallback_action).expect("an empty table is always valid")
    }

    /// Atomically replaces the route table and returns the generation that was replaced.
    ///
    /// The new table is built and validated **before** the swap, so a failed reload leaves the
    /// previous generation serving traffic unchanged.
    pub fn load(&self, routes: Vec<RouteDefinition>) -> Result<Arc<SniTable>, RouteError> {
        let next = SniTable::build(&routes, Arc::clone(&self.fallback))?;
        Ok(self.generation.swap(Arc::new(next)))
    }

    /// A full handle to the current generation (keeps it alive across a concurrent reload).
    pub fn generation(&self) -> Arc<SniTable> {
        self.generation.load_full()
    }

    /// Looks up `sni` in the current generation; the returned `Arc<Route>` outlives reloads.
    pub fn lookup(&self, sni: Option<&str>) -> Arc<Route> {
        self.generation.load().lookup(sni)
    }

    /// The stable fallback route.
    pub fn fallback(&self) -> &Arc<Route> {
        &self.fallback
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{RouteDefinition, RouteError, SniRouter, SniTable};
    use crate::actions::{
        FallbackConfig, FallbackReason, HttpConfig, PassthroughConfig, SniAction, TerminateConfig,
    };

    fn terminate(host: &str) -> SniAction {
        SniAction::Terminate(TerminateConfig::new(host).unwrap())
    }

    fn passthrough(upstream: &str) -> SniAction {
        SniAction::Passthrough(PassthroughConfig::new(upstream).unwrap())
    }

    fn fallback() -> SniAction {
        SniAction::Fallback(FallbackConfig::new(FallbackReason::NoRoute))
    }

    fn route(host: &str, action: SniAction) -> RouteDefinition {
        RouteDefinition::new(host, action).unwrap()
    }

    #[test]
    fn matches_exact_hosts_case_insensitively() {
        let router = SniRouter::new(
            vec![route("example.com", terminate("example.com"))],
            fallback(),
        )
        .unwrap();
        assert_eq!(router.lookup(Some("example.com")).host(), "example.com");
        assert_eq!(router.lookup(Some("EXAMPLE.com")).host(), "example.com");
        assert_eq!(router.lookup(Some("other.com")).action_kind(), "fallback");
    }

    #[test]
    fn wildcards_match_label_boundaries_and_longest_suffix_wins() {
        let router = SniRouter::new(
            vec![
                route("*.example.com", terminate("example.com")),
                route("*.b.example.com", passthrough("127.0.0.1:8443")),
                route("*.example.net", passthrough("127.0.0.1:8444")),
            ],
            fallback(),
        )
        .unwrap();
        // Exact suffix shape: apex is not matched by a wildcard.
        assert_eq!(router.lookup(Some("example.com")).action_kind(), "fallback");
        assert_eq!(
            router.lookup(Some("a.example.com")).action_kind(),
            "terminate"
        );
        // At a label boundary only (no partial-label match).
        assert_eq!(
            router.lookup(Some("badexample.com")).action_kind(),
            "fallback"
        );
        // Longest suffix wins when several wildcards match.
        assert_eq!(
            router.lookup(Some("a.b.example.com")).host(),
            "*.b.example.com"
        );
        assert_eq!(
            router.lookup(Some("c.example.net")).action_kind(),
            "passthrough"
        );
        assert_eq!(router.generation().wildcard_count(), 3);
    }

    #[test]
    fn fallback_covers_missing_and_unknown_sni() {
        let router = SniRouter::new(
            vec![route("example.com", terminate("example.com"))],
            SniAction::Http(HttpConfig::new(None).unwrap()),
        )
        .unwrap();
        assert_eq!(router.lookup(None).action_kind(), "http");
        assert_eq!(router.lookup(Some("")).action_kind(), "http");
        assert_eq!(router.lookup(Some("unknown.example")).action_kind(), "http");
        assert_eq!(router.fallback().host(), "");
    }

    #[test]
    fn reload_swaps_a_complete_generation_and_returns_the_previous_one() {
        let router = SniRouter::new(
            vec![route("example.com", terminate("example.com"))],
            fallback(),
        )
        .unwrap();
        let first = router.generation();
        assert_eq!(first.len(), 1);

        let previous = router
            .load(vec![
                route("example.com", passthrough("127.0.0.1:9443")),
                route("new.example", terminate("new.example")),
            ])
            .unwrap();
        assert_eq!(previous.len(), 1, "the replaced generation is returned");
        assert_eq!(
            previous.lookup(Some("example.com")).action_kind(),
            "terminate"
        );
        assert_eq!(router.generation().len(), 2);
        assert_eq!(
            router.lookup(Some("example.com")).action_kind(),
            "passthrough"
        );
        assert_eq!(
            router.lookup(Some("new.example")).action_kind(),
            "terminate"
        );
    }

    #[test]
    fn a_failed_reload_keeps_the_active_generation() {
        let router = SniRouter::new(
            vec![route("example.com", terminate("example.com"))],
            fallback(),
        )
        .unwrap();
        let before = router.generation();
        // The new table is built and validated before the swap: a duplicate pattern makes the
        // reload fail while the old generation keeps serving.
        let error = router
            .load(vec![
                route("example.com", passthrough("127.0.0.1:9443")),
                route("EXAMPLE.com", terminate("example.com")),
            ])
            .expect_err("duplicate host must be rejected");
        assert_eq!(error, RouteError::DuplicateHost("example.com".to_string()));
        assert_eq!(router.generation().len(), before.len());
        assert_eq!(
            router.lookup(Some("example.com")).action_kind(),
            "terminate"
        );
    }

    #[test]
    fn duplicate_patterns_are_rejected() {
        let error = SniRouter::new(
            vec![
                route("example.com", terminate("example.com")),
                route("EXAMPLE.com", terminate("example.com")),
            ],
            fallback(),
        )
        .expect_err("duplicate exact route");
        assert_eq!(error, RouteError::DuplicateHost("example.com".to_string()));

        let error = SniRouter::new(
            vec![
                route("*.example.com", terminate("example.com")),
                route("*.Example.COM", terminate("example.com")),
            ],
            fallback(),
        )
        .expect_err("duplicate wildcard route");
        assert!(matches!(error, RouteError::DuplicateHost(_)));

        // Equal-length wildcards separated by another same-length wildcard: the stable length
        // sort does not make them adjacent, so duplicates must be detected on insert.
        let error = SniRouter::new(
            vec![
                route("*.a.example", terminate("a.example")),
                route("*.b.example", passthrough("127.0.0.1:9443")),
                route("*.a.example", passthrough("127.0.0.1:9444")),
            ],
            fallback(),
        )
        .expect_err("non-adjacent duplicate wildcard route");
        assert_eq!(error, RouteError::DuplicateHost("*.a.example".to_string()));

        let error = SniRouter::new(
            vec![
                route("*.a.example", terminate("a.example")),
                route("*.b.example", terminate("b.example")),
                route("*.c.example", terminate("c.example")),
                route("*.a.example", terminate("a.example")),
            ],
            fallback(),
        )
        .expect_err("non-adjacent duplicate wildcard at the end");
        assert_eq!(error, RouteError::DuplicateHost("*.a.example".to_string()));
    }

    #[test]
    fn wildcard_lookup_rejects_malformed_label_prefixes() {
        let router = SniRouter::new(
            vec![route("*.example.com", terminate("example.com"))],
            fallback(),
        )
        .unwrap();
        // Well-formed names at a label boundary match...
        assert_eq!(
            router.lookup(Some("www.example.com")).host(),
            "*.example.com"
        );
        assert_eq!(
            router.lookup(Some("a.b.example.com")).host(),
            "*.example.com"
        );
        // ...while empty labels / missing labels do not.
        for malformed in [
            "example.com",
            ".example.com",
            "..example.com",
            "a..example.com",
            "a..b.example.com",
        ] {
            assert_eq!(
                router.lookup(Some(malformed)).action_kind(),
                "fallback",
                "{malformed:?} must not match *.example.com"
            );
        }
    }

    #[test]
    fn empty_router_and_table_introspection() {
        let router = SniRouter::empty(fallback());
        assert!(router.generation().is_empty());
        assert_eq!(router.generation().len(), 0);
        assert_eq!(router.lookup(Some("anything")).action_kind(), "fallback");
        let table: Arc<SniTable> = router.generation();
        assert_eq!(table.fallback().host(), "");
    }
}
