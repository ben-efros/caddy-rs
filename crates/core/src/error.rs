//! Typed configuration and registry errors. Every error names the offending input.

use std::path::PathBuf;

/// Errors produced by the configuration model, validation, and lifecycle layers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A structural or semantic configuration problem, located by JSON path.
    #[error("invalid configuration at `{path}`: {message}")]
    Invalid {
        /// JSON path of the offending value (for example `apps.http.servers.srv0.listen[1]`).
        path: String,
        /// Human-readable diagnosis naming the offending value.
        message: String,
    },

    /// A module name that the registry does not know how to load.
    ///
    /// `hint` is pre-rendered (empty, or `` (did you mean `reverse_proxy`?) ``) so the message can
    /// stay a plain `thiserror` format string; see [`Error::unknown_module`] and
    /// [`crate::ModuleRegistry::unknown_module`], which choose it from the registry.
    #[error("unknown {kind} module `{name}` at `{path}`{hint}")]
    UnknownModule {
        /// Module category, for example `HTTP handler`.
        kind: &'static str,
        /// Name as written in the configuration.
        name: String,
        /// JSON path of the reference.
        path: String,
        /// Pre-rendered "did you mean" suffix (empty when no candidate is close enough).
        hint: String,
    },

    /// A listen address that cannot be parsed.
    #[error("invalid listen address `{value}` at `{path}`: {reason}")]
    InvalidListen {
        /// The address as written.
        value: String,
        /// JSON path of the address.
        path: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The configuration document could not be read from disk.
    #[error("cannot read config file `{}`: {source}", path.display())]
    ConfigIo {
        /// File that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configuration document was not valid JSON or did not match the model.
    #[error("cannot decode config JSON: {source}")]
    Json {
        /// Underlying serde error.
        #[from]
        source: serde_json::Error,
    },

    /// A recognised Caddy configuration construct that this build intentionally does not
    /// implement.
    ///
    /// Unlike [`Error::Invalid`], this is not a malformed configuration: Caddy accepts it, and
    /// caddy-rs rejects it loudly (DIV-0016) with a tracking task instead of silently
    /// approximating its behaviour. The message must stay recognisable to the compatibility
    /// tooling's "unsupported" class, hence the "not supported by this build" wording.
    ///
    /// `tracking_suffix` is empty when the construct is known to Caddy but no implementation
    /// task exists yet; otherwise it is `` (tracked as T-...) ``. Keeping the suffix
    /// pre-rendered lets the `feature` text be dynamic (for example a rejected option name)
    /// without allocating a leaked `&'static str`.
    #[error(
        "configuration at `{path}` is not supported by this build: {feature}{tracking_suffix}"
    )]
    Unsupported {
        /// JSON path of the unsupported construct.
        path: String,
        /// Human-readable construct name, e.g. ``reverse_proxy `dynamic_upstreams```.
        feature: String,
        /// Pre-rendered ` (tracked as T-...)` suffix, or empty when untracked.
        tracking_suffix: String,
    },

    /// Two modules were registered with the same id.
    #[error("module registry: module id `{0}` is already registered")]
    DuplicateModule(&'static str),

    /// Two modules of the same kind were registered with the same JSON key.
    ///
    /// Resolution is by `(kind, json key)`, so a key must map to exactly one module id; a second
    /// registration would silently shadow the first.
    #[error(
        "module registry: {kind} key `{key}` already resolves to `{existing}` \
         (cannot also resolve to `{incoming}`)"
    )]
    ModuleKeyConflict {
        /// Module category label (see [`crate::ModuleKind::label`]).
        kind: &'static str,
        /// Short JSON key that collides.
        key: &'static str,
        /// Module id the key already resolves to.
        existing: &'static str,
        /// Module id that tried to claim the key.
        incoming: &'static str,
    },

    /// A module definition is malformed (empty id/key, illegal characters, ...).
    ///
    /// Dynamic registrations are validated at registration time so a plugin cannot poison the
    /// registry with ids that can never be resolved or listed deterministically.
    #[error("module registry: invalid module definition: {message}")]
    InvalidModuleDefinition {
        /// Diagnosis naming the offending field and value.
        message: String,
    },

    /// A requested capability is recognised but intentionally not implemented yet.
    #[error("not implemented: {feature} ({tracking_id})")]
    NotImplemented {
        /// Capability.
        feature: &'static str,
        /// Plan task or divergence id tracking the gap.
        tracking_id: &'static str,
    },

    /// A generation lifecycle hook (provision/start/stop/cleanup) failed.
    ///
    /// The message is located: it names the generation, the phase, and the resource that failed,
    /// so a failed reload can be diagnosed without attaching a debugger. Any additional failures
    /// from the same phase (a cleanup that continues after one resource errors, for example) are
    /// appended to `message`.
    #[error("generation {generation} {phase} failed at resource `{resource}`: {message}")]
    Lifecycle {
        /// Generation id whose lifecycle failed.
        generation: u64,
        /// Phase: `provision`, `start`, `stop`, or `cleanup`.
        phase: &'static str,
        /// Stable resource name reported by the resource's `name()`.
        resource: String,
        /// Failure diagnosis (plus any secondary failures).
        message: String,
    },

    /// A generation lifecycle operation was cancelled before it completed.
    ///
    /// Cancellation is cooperative via [`crate::CancellationToken`]; resources already attached to
    /// the generation are cleaned up exactly once before this error is returned.
    #[error("generation {generation} {phase} was cancelled")]
    LifecycleCancelled {
        /// Generation id whose lifecycle was cancelled.
        generation: u64,
        /// Phase the operation was executing: `provision`, `start`, `stop`, or `cleanup`.
        phase: &'static str,
    },

    /// A lifecycle phase was entered out of order (framework misuse, never user configuration).
    #[error("generation {generation} lifecycle state error: {message}")]
    LifecycleState {
        /// Generation id whose lifecycle state was invalid.
        generation: u64,
        /// What was wrong.
        message: String,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Convenience constructor for a located invalid-configuration error.
    pub fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Convenience constructor for a located "unknown module" error with a "did you mean" hint.
    ///
    /// `candidates` are the JSON keys (or ids) that *are* registered for this module category; the
    /// closest one is suggested when it is within a small edit distance of `name`. Callers with a
    /// [`crate::ModuleRegistry`] should use [`crate::ModuleRegistry::unknown_module`], which
    /// supplies the candidates automatically.
    pub fn unknown_module<'a>(
        kind: &'static str,
        name: impl Into<String>,
        path: impl Into<String>,
        candidates: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let name = name.into();
        let hint = match closest_match(&name, candidates) {
            Some(suggestion) => format!(" (did you mean `{suggestion}`?)"),
            None => String::new(),
        };
        Self::UnknownModule {
            kind,
            name,
            path: path.into(),
            hint,
        }
    }

    /// Stable, machine-readable error code for tooling.
    ///
    /// The codes are part of the diagnostics contract (they are what scripts and editors match on),
    /// so they must not change when a message is reworded. [`Self::Invalid`] is deliberately
    /// coarse: the located JSON path, not the code, identifies the offending value.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "config.invalid",
            Self::UnknownModule { .. } => "module.unknown",
            Self::InvalidListen { .. } => "listen.invalid",
            Self::ConfigIo { .. } => "config.io",
            Self::Json { .. } => "config.json",
            Self::Unsupported { .. } => "config.unsupported",
            Self::DuplicateModule(_) => "module.duplicate",
            Self::ModuleKeyConflict { .. } => "module.key_conflict",
            Self::InvalidModuleDefinition { .. } => "module.invalid_definition",
            Self::NotImplemented { .. } => "not_implemented",
            Self::Lifecycle { .. } => "lifecycle.failed",
            Self::LifecycleCancelled { .. } => "lifecycle.cancelled",
            Self::LifecycleState { .. } => "lifecycle.state",
        }
    }

    /// Convenience constructor for a located "recognised but unsupported" error with a tracking
    /// task.
    pub fn unsupported(
        path: impl Into<String>,
        feature: impl Into<String>,
        tracking_id: &'static str,
    ) -> Self {
        Self::Unsupported {
            path: path.into(),
            feature: feature.into(),
            tracking_suffix: format!(" (tracked as {tracking_id})"),
        }
    }

    /// Convenience constructor for a located "recognised but unsupported" error with no
    /// implementation task yet.
    ///
    /// This is for Caddy constructs that this build deliberately rejects but that are not yet
    /// scheduled; the message still says "not supported by this build" and never suggests a
    /// typo.
    pub fn unsupported_untracked(path: impl Into<String>, feature: impl Into<String>) -> Self {
        Self::Unsupported {
            path: path.into(),
            feature: feature.into(),
            tracking_suffix: String::new(),
        }
    }
}

/// The closest registered name to `name`, when it is close enough to be a useful suggestion.
///
/// "Close enough" is a small edit-distance budget that grows with the length of the name (one
/// edit for short names, up to three for long ones), so `revers_proxy` suggests `reverse_proxy`
/// while an unrelated name suggests nothing. Ties are broken lexicographically so the suggestion is
/// deterministic. A qualified id (`http.handlers.reverse_proxy`) is compared with its last segment
/// as well, matching how Caddy's JSON usually names modules.
fn closest_match<'a>(name: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    let tail = trimmed.rsplit('.').next().unwrap_or(trimmed);
    let budget = match trimmed.len().max(tail.len()) {
        0..=4 => 1,
        5..=9 => 2,
        _ => 3,
    };
    let mut best: Option<(usize, &'a str)> = None;
    for candidate in candidates {
        if candidate == trimmed {
            // The registry would have resolved an exact key; nothing to suggest.
            continue;
        }
        // A qualified reference (`http.handlers.reverse_proxy`) is compared by its last segment,
        // which is the short key Caddy's JSON actually uses.
        let distance = edit_distance_budgeted(tail, candidate, budget)
            .or_else(|| edit_distance_budgeted(trimmed, candidate, budget));
        let Some(distance) = distance else { continue };
        let better = match best {
            None => true,
            Some((best_distance, best_name)) => {
                distance < best_distance || (distance == best_distance && candidate < best_name)
            }
        };
        if better {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// Levenshtein distance, abandoned as soon as it exceeds `budget` (returns `None`).
///
/// The early exit keeps a suggestion over a large registry cheap: a candidate whose prefix already
/// drifts too far is rejected without filling the whole matrix.
fn edit_distance_budgeted(left: &str, right: &str, budget: usize) -> Option<usize> {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    if left.len().abs_diff(right.len()) > budget {
        return None;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0usize; right.len() + 1];
    for (i, left_char) in left.iter().enumerate() {
        current[0] = i + 1;
        let mut row_minimum = current[0];
        for (j, right_char) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_char != right_char);
            let insertion = current[j] + 1;
            let deletion = previous[j + 1] + 1;
            current[j + 1] = substitution.min(insertion).min(deletion);
            row_minimum = row_minimum.min(current[j + 1]);
        }
        if row_minimum > budget {
            return None;
        }
        std::mem::swap(&mut previous, &mut current);
    }
    let distance = previous[right.len()];
    (distance <= budget).then_some(distance)
}
