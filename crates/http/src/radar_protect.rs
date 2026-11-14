//! Default Radar protection handlers with lazy registration.
//!
//! # Rules and actions
//!
//! Every handler is a [`ProtectionRule`]: a [`RadarPredicate`] plus a [`ProtectionAction`]
//! (`block`, `tarpit`, `pow_challenge`, `rate_limit`) and a `handler_order`. The built-in defaults
//! are the ones the acceptance list names:
//!
//! | Rule id | Predicate | Action | Order |
//! | --- | --- | --- | --- |
//! | `hijacked_prefix` | `target_prefix_hijacked` | `block` | 100 |
//! | `tarpit_attacker` | `source_asn_attacking` + `min_magnitude` 5000 | `tarpit` | 200 |
//! | `pow_challenge_anomalous` | `source_asn_anomalous` + `scanning`/`botnet`/`credential_stuffing` | `pow_challenge` | 300 |
//! | `rate_limit_suspicious` | `source_asn_anomalous` | `rate_limit` rate 100 burst 20 | 400 |
//!
//! # Lazy registration
//!
//! [`RadarProtection::new`] registers **nothing**: the registry is inactive and empty. It becomes
//! active only when [`RadarProtection::refresh`] is told radar is enabled — i.e. when
//! [`RadarState`] transitions idle→enabled after the first successful auto-mode poll. Every later
//! `refresh(false)` (auto mode still idle, per-server `radar off`, `protect false`) empties the
//! registry again. [`RadarProtection::guard`] is the single gated hook the request pipeline calls;
//! it returns `None` while the registry is inactive, so no rule can run before radar is enabled.
//!
//! # Wiring
//!
//! [`RadarRuntime`] is the integration point handed to the runtime row: it owns the state, the
//! GeoIP/`trust_cdn` seams and the registry. The `caddy-rs-server` pipeline does not construct it
//! yet, so **nothing is wired into request dispatch in this task**. The two calls the pipeline has
//! to make are:
//!
//! * `runtime.sync(&radar_client).await` after each poll (and on the auto-mode enable), which
//!   publishes the snapshot and calls `protection.refresh(state.is_enabled())`;
//! * `runtime.guard(&request)` at the top of request dispatch, before route evaluation; a returned
//!   [`ProtectionDecision`] maps onto the existing handlers (`static_response` for `block`,
//!   `rate_limit`, and the tarpit/pow handlers the runtime row provides).
//!
//! Configuration comes from the `radar` global option's `protect` block (parsed by
//! [`ProtectionConfig::from_json`]): global `protect false`, per-rule disable and thresholds,
//! per-server radar off, and user-defined handlers that run before the defaults.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use serde_json::Value;

use crate::radar_client::RadarClient;
use crate::radar_matcher::{
    AsnSelector, GeoIpProvider, RadarContext, RadarPredicate, RadarState, RadarTransition,
    TrustCdnResolver,
};
use crate::radar_vars::RadarVars;
use crate::types::Request;

/// Rule id of the default hijacked-prefix block.
pub const RULE_HIJACKED_PREFIX: &str = "hijacked_prefix";
/// Rule id of the default active-attacker tarpit.
pub const RULE_TARPIT_ATTACKER: &str = "tarpit_attacker";
/// Rule id of the default anomalous-source proof-of-work challenge.
pub const RULE_POW_CHALLENGE_ANOMALOUS: &str = "pow_challenge_anomalous";
/// Rule id of the default suspicious-source rate limit.
pub const RULE_RATE_LIMIT_SUSPICIOUS: &str = "rate_limit_suspicious";
/// Magnitude threshold of the default tarpit rule.
pub const DEFAULT_TARPIT_MIN_MAGNITUDE: f64 = 5000.0;
/// Rate of the default suspicious-source rate limit.
pub const DEFAULT_RATE_LIMIT_RATE: u32 = 100;
/// Burst of the default suspicious-source rate limit.
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 20;
/// Handler order of the default hijacked-prefix rule.
pub const DEFAULT_ORDER_HIJACKED_PREFIX: u32 = 100;
/// Handler order of the default tarpit rule.
pub const DEFAULT_ORDER_TARPIT: u32 = 200;
/// Handler order of the default proof-of-work rule.
pub const DEFAULT_ORDER_POW_CHALLENGE: u32 = 300;
/// Handler order of the default rate-limit rule.
pub const DEFAULT_ORDER_RATE_LIMIT: u32 = 400;
/// Default handler order of a user-defined rule (runs before every default).
pub const DEFAULT_ORDER_USER: u32 = 10;

/// What a matched rule does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionAction {
    /// Reject the request.
    Block,
    /// Hold the connection (tarpit).
    Tarpit,
    /// Answer with a proof-of-work challenge.
    PowChallenge,
    /// Apply a token-bucket rate limit.
    RateLimit {
        /// Requests per second.
        rate: u32,
        /// Burst size.
        burst: u32,
    },
}

impl ProtectionAction {
    /// Stable name used in logs and JSON.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Tarpit => "tarpit",
            Self::PowChallenge => "pow_challenge",
            Self::RateLimit { .. } => "rate_limit",
        }
    }

    /// Parse an action name; `rate_limit` keeps the rule's `rate`/`burst` overrides.
    pub fn from_json(value: &Value, rate: Option<u32>, burst: Option<u32>) -> Result<Self, String> {
        let name = value
            .as_str()
            .ok_or_else(|| "`action` must be a string".to_string())?;
        match name {
            "block" => Ok(Self::Block),
            "tarpit" => Ok(Self::Tarpit),
            "pow_challenge" => Ok(Self::PowChallenge),
            "rate_limit" => Ok(Self::RateLimit {
                rate: rate.unwrap_or(DEFAULT_RATE_LIMIT_RATE),
                burst: burst.unwrap_or(DEFAULT_RATE_LIMIT_BURST),
            }),
            other => Err(format!(
                "unknown protect action `{other}` (expected block, tarpit, pow_challenge, rate_limit)"
            )),
        }
    }
}

/// Who defined a rule; user-defined rules win ties against defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleSource {
    /// A handler from the `protect` block.
    User,
    /// One of the built-in defaults.
    Default,
}

/// One protection handler: predicate + action + precedence.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionRule {
    /// Stable id (`hijacked_prefix`, `tarpit_attacker`, or a user-provided name).
    pub id: String,
    /// Precedence: lower runs first; user rules default below every default rule.
    pub handler_order: u32,
    /// When to fire.
    pub predicate: RadarPredicate,
    /// What to do.
    pub action: ProtectionAction,
    /// Whether this rule is a default or user-defined.
    pub source: RuleSource,
}

impl ProtectionRule {
    /// Parse a user-defined rule (`{"name": ..., "order": ..., "action": ..., "predicate": ...}`).
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "protect handler must be a JSON object".to_string())?;
        let mut id = None;
        let mut handler_order = None;
        let mut predicate = None;
        let mut action = None;
        let mut rate = None;
        let mut burst = None;
        for (key, value) in object {
            match key.as_str() {
                "name" | "id" => {
                    id = Some(
                        value
                            .as_str()
                            .ok_or_else(|| "`name` must be a string".to_string())?
                            .to_string(),
                    )
                }
                "order" | "handler_order" => handler_order = Some(u32_field(value, key)?),
                "predicate" => predicate = Some(RadarPredicate::from_json(value)?),
                "action" => action = Some(value.clone()),
                "rate" => rate = Some(u32_field(value, key)?),
                "burst" => burst = Some(u32_field(value, key)?),
                other => return Err(format!("unknown protect handler field `{other}`")),
            }
        }
        let id = id.ok_or_else(|| "protect handler needs a `name`".to_string())?;
        let predicate =
            predicate.ok_or_else(|| "protect handler needs a `predicate`".to_string())?;
        let action = match action {
            Some(value) => ProtectionAction::from_json(&value, rate, burst)?,
            None => ProtectionAction::Block,
        };
        Ok(Self {
            id,
            handler_order: handler_order.unwrap_or(DEFAULT_ORDER_USER),
            predicate,
            action,
            source: RuleSource::User,
        })
    }
}

/// The rule that fired.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionDecision {
    /// Id of the matched rule.
    pub rule_id: String,
    /// The rule's precedence.
    pub handler_order: u32,
    /// What the pipeline should apply.
    pub action: ProtectionAction,
}

impl ProtectionDecision {
    /// Short log line.
    pub fn describe(&self) -> String {
        format!(
            "radar protect: rule `{}` (order {}) -> {}",
            self.rule_id,
            self.handler_order,
            self.action.name()
        )
    }
}

/// Per-rule threshold overrides and the global/per-server opt-outs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleOverride {
    /// `false` removes the rule.
    pub enabled: Option<bool>,
    /// Replaces the rule's magnitude threshold.
    pub min_magnitude: Option<f64>,
    /// Replaces a `rate_limit` rule's rate.
    pub rate: Option<u32>,
    /// Replaces a `rate_limit` rule's burst.
    pub burst: Option<u32>,
    /// Replaces the rule's anomaly kinds.
    pub anomaly_types: Option<Vec<String>>,
}

/// The `protect` block.
///
/// JSON forms (`false` is the global `protect false` opt-out):
///
/// ```json
/// {
///   "enabled": true,
///   "server_radar_off": false,
///   "rule": {
///     "tarpit_attacker": { "min_magnitude": 8000 },
///     "rate_limit_suspicious": { "rate": 50, "burst": 10 },
///     "pow_challenge_anomalous": { "enabled": false }
///   },
///   "handler": [
///     {
///       "name": "deny_ddos_sources",
///       "order": 1,
///       "action": "block",
///       "predicate": { "source_asn_attacking": true, "min_magnitude": 1000 }
///     }
///   ]
/// }
/// ```
///
/// User-defined handlers run before the defaults because their default order
/// ([`DEFAULT_ORDER_USER`]) is below every built-in order, and an explicit `order` sorts a rule
/// wherever it belongs.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionConfig {
    /// Global `protect` switch (default true).
    pub enabled: bool,
    /// The per-server `radar off` opt-out (wins over everything else).
    pub server_radar_off: bool,
    /// Per-rule overrides, keyed by rule id.
    pub overrides: BTreeMap<String, RuleOverride>,
    /// User-defined handlers.
    pub user_rules: Vec<ProtectionRule>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_radar_off: false,
            overrides: BTreeMap::new(),
            user_rules: Vec::new(),
        }
    }
}

impl ProtectionConfig {
    /// Parse the `protect` block (`false`, or an object).
    pub fn from_json(value: &Value) -> Result<Self, String> {
        if let Some(enabled) = value.as_bool() {
            return Ok(Self {
                enabled,
                ..Self::default()
            });
        }
        let object = value
            .as_object()
            .ok_or_else(|| "`protect` must be false or a JSON object".to_string())?;
        let mut config = Self::default();
        for (key, value) in object {
            match key.as_str() {
                "enabled" => {
                    config.enabled = value
                        .as_bool()
                        .ok_or_else(|| "`protect.enabled` must be a boolean".to_string())?
                }
                "server_radar_off" => {
                    config.server_radar_off = value
                        .as_bool()
                        .ok_or_else(|| "`protect.server_radar_off` must be a boolean".to_string())?
                }
                "radar" => {
                    config.server_radar_off = !value
                        .as_bool()
                        .ok_or_else(|| "`protect.radar` must be a boolean".to_string())?
                }
                "rule" => {
                    let rules = value
                        .as_object()
                        .ok_or_else(|| "`protect.rule` must be an object".to_string())?;
                    for (id, override_value) in rules {
                        config
                            .overrides
                            .insert(id.clone(), override_from_json(override_value)?);
                    }
                }
                "handler" | "handlers" => {
                    let handlers = value
                        .as_array()
                        .ok_or_else(|| "`protect.handler` must be an array".to_string())?;
                    config.user_rules = handlers
                        .iter()
                        .map(ProtectionRule::from_json)
                        .collect::<Result<Vec<_>, _>>()?;
                }
                other => return Err(format!("unknown protect field `{other}`")),
            }
        }
        Ok(config)
    }

    /// Whether a rule id is disabled by an override.
    pub fn rule_disabled(&self, id: &str) -> bool {
        self.overrides
            .get(id)
            .and_then(|overridden| overridden.enabled)
            == Some(false)
    }
}

/// Parse one `rule` override object.
fn override_from_json(value: &Value) -> Result<RuleOverride, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "rule override must be a JSON object".to_string())?;
    let mut overridden = RuleOverride::default();
    for (key, value) in object {
        match key.as_str() {
            "enabled" => {
                overridden.enabled = Some(
                    value
                        .as_bool()
                        .ok_or_else(|| "`enabled` must be a boolean".to_string())?,
                )
            }
            "min_magnitude" => overridden.min_magnitude = Some(number(value, key)?),
            "rate" => overridden.rate = Some(u32_field(value, key)?),
            "burst" => overridden.burst = Some(u32_field(value, key)?),
            "anomaly_type" | "anomaly_types" => {
                overridden.anomaly_types = Some(string_list(value, key)?)
            }
            other => return Err(format!("unknown rule override field `{other}`")),
        }
    }
    Ok(overridden)
}

/// The built-in protection rules, before overrides.
pub fn default_rules() -> Vec<ProtectionRule> {
    vec![
        ProtectionRule {
            id: RULE_HIJACKED_PREFIX.to_string(),
            handler_order: DEFAULT_ORDER_HIJACKED_PREFIX,
            predicate: RadarPredicate {
                target_prefix_hijacked: Some(AsnSelector::Client),
                ..RadarPredicate::default()
            },
            action: ProtectionAction::Block,
            source: RuleSource::Default,
        },
        ProtectionRule {
            id: RULE_TARPIT_ATTACKER.to_string(),
            handler_order: DEFAULT_ORDER_TARPIT,
            predicate: RadarPredicate {
                source_asn_attacking: Some(AsnSelector::Client),
                min_magnitude: Some(DEFAULT_TARPIT_MIN_MAGNITUDE),
                ..RadarPredicate::default()
            },
            action: ProtectionAction::Tarpit,
            source: RuleSource::Default,
        },
        ProtectionRule {
            id: RULE_POW_CHALLENGE_ANOMALOUS.to_string(),
            handler_order: DEFAULT_ORDER_POW_CHALLENGE,
            predicate: RadarPredicate {
                source_asn_anomalous: Some(AsnSelector::Client),
                anomaly_type: vec![
                    "scanning".to_string(),
                    "botnet".to_string(),
                    "credential_stuffing".to_string(),
                ],
                ..RadarPredicate::default()
            },
            action: ProtectionAction::PowChallenge,
            source: RuleSource::Default,
        },
        ProtectionRule {
            id: RULE_RATE_LIMIT_SUSPICIOUS.to_string(),
            handler_order: DEFAULT_ORDER_RATE_LIMIT,
            predicate: RadarPredicate {
                source_asn_anomalous: Some(AsnSelector::Client),
                ..RadarPredicate::default()
            },
            action: ProtectionAction::RateLimit {
                rate: DEFAULT_RATE_LIMIT_RATE,
                burst: DEFAULT_RATE_LIMIT_BURST,
            },
            source: RuleSource::Default,
        },
    ]
}

/// The lazily-registered protection registry.
///
/// Starts inactive and empty; [`Self::refresh`] materialises the rules once radar is enabled.
#[derive(Debug)]
pub struct RadarProtection {
    config: ProtectionConfig,
    rules: RwLock<Vec<ProtectionRule>>,
    active: AtomicBool,
}

impl RadarProtection {
    /// Build a registry. Nothing is registered and nothing fires until [`Self::refresh`] sees
    /// radar enabled and the opt-outs allow it.
    pub fn new(config: ProtectionConfig) -> Self {
        Self {
            config,
            rules: RwLock::new(Vec::new()),
            active: AtomicBool::new(false),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &ProtectionConfig {
        &self.config
    }

    /// Whether handlers are currently registered (false before the first enable).
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// The registered rules, in precedence order.
    pub fn active_rules(&self) -> Vec<ProtectionRule> {
        self.rules
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// (Re)build the registry for the given radar state; returns whether it is active.
    ///
    /// This is the lazy-registration step: the first `refresh(true)` after the idle→enabled
    /// transition registers the rules, while `refresh(false)` (auto mode idle, per-server
    /// `radar off`) empties the registry again. `protect false` and per-rule disables are applied
    /// here so the request path never re-checks configuration.
    pub fn refresh(&self, radar_enabled: bool) -> bool {
        let active = radar_enabled && self.config.enabled && !self.config.server_radar_off;
        let mut rules = Vec::new();
        if active {
            for rule in &self.config.user_rules {
                if self.config.rule_disabled(&rule.id) {
                    continue;
                }
                rules.push(self.apply_override(rule.clone()));
            }
            for rule in default_rules() {
                if self.config.rule_disabled(&rule.id) {
                    continue;
                }
                rules.push(self.apply_override(rule));
            }
            rules.sort_by(|a, b| {
                a.handler_order
                    .cmp(&b.handler_order)
                    .then(a.source.cmp(&b.source))
                    .then(a.id.cmp(&b.id))
            });
        }
        *self
            .rules
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = rules;
        self.active.store(active, Ordering::Release);
        active
    }

    /// Apply the configured thresholds to `rule`.
    fn apply_override(&self, mut rule: ProtectionRule) -> ProtectionRule {
        let Some(overridden) = self.config.overrides.get(&rule.id) else {
            return rule;
        };
        if let Some(minimum) = overridden.min_magnitude {
            rule.predicate.min_magnitude = Some(minimum);
        }
        if let Some(anomaly_types) = &overridden.anomaly_types {
            rule.predicate.anomaly_type = anomaly_types.clone();
        }
        if let ProtectionAction::RateLimit { rate, burst } = &mut rule.action {
            if let Some(overridden) = overridden.rate {
                *rate = overridden;
            }
            if let Some(overridden) = overridden.burst {
                *burst = overridden;
            }
        }
        rule
    }

    /// The gated request hook: the first active rule whose predicate matches wins.
    ///
    /// Returns `None` while the registry is inactive (radar idle/off, `protect false`, per-server
    /// `radar off`), when the request has no peer address, or when no rule matches.
    pub fn guard(
        &self,
        context: RadarContext<'_>,
        request: &Request,
    ) -> Option<ProtectionDecision> {
        if !self.is_active() || !context.state.is_enabled() {
            return None;
        }
        let rules = self.active_rules();
        if rules.is_empty() {
            return None;
        }
        let identity = context.identify(request)?;
        let snapshot = context.state.snapshot();
        let now = SystemTime::now();
        rules
            .iter()
            .find(|rule| rule.predicate.matches_snapshot(&snapshot, &identity, now))
            .map(|rule| ProtectionDecision {
                rule_id: rule.id.clone(),
                handler_order: rule.handler_order,
                action: rule.action.clone(),
            })
    }
}

/// The handles the runtime row owns: snapshot, GeoIP, `trust_cdn`, protection registry.
///
/// This is the documented integration point for the server pipeline: call [`Self::sync`] after
/// each Radar poll and [`Self::guard`] before route evaluation.
pub struct RadarRuntime {
    /// The shared snapshot + enabled flag.
    pub state: Arc<RadarState>,
    /// IP → ASN/country lookup.
    pub geoip: Arc<dyn GeoIpProvider>,
    /// Which peers may forward the client IP.
    pub trust_cdn: Arc<dyn TrustCdnResolver>,
    /// The lazily-registered protection handlers.
    pub protection: Arc<RadarProtection>,
}

impl RadarRuntime {
    /// Build the runtime handles.
    pub fn new(
        state: Arc<RadarState>,
        geoip: Arc<dyn GeoIpProvider>,
        trust_cdn: Arc<dyn TrustCdnResolver>,
        protection: Arc<RadarProtection>,
    ) -> Self {
        Self {
            state,
            geoip,
            trust_cdn,
            protection,
        }
    }

    /// The request-path context.
    pub fn context(&self) -> RadarContext<'_> {
        RadarContext::new(
            self.state.as_ref(),
            self.geoip.as_ref(),
            self.trust_cdn.as_ref(),
        )
    }

    /// Publish the client's snapshot and re-evaluate lazy protection registration.
    pub async fn sync(&self, client: &RadarClient) -> RadarTransition {
        let transition = self.state.sync_from_client(client).await;
        self.protection.refresh(transition.enabled);
        transition
    }

    /// The gated protection hook (see [`RadarProtection::guard`]).
    pub fn guard(&self, request: &Request) -> Option<ProtectionDecision> {
        self.protection.guard(self.context(), request)
    }

    /// The Radar variables for `request`.
    pub fn variables(&self) -> RadarVars<'_> {
        RadarVars::from_context(self.context())
    }
}

/// Parse a number, accepting a numeric string.
fn number(value: &Value, field: &str) -> Result<f64, String> {
    match value {
        Value::Number(number) => number
            .as_f64()
            .ok_or_else(|| format!("`{field}` is not a number")),
        Value::String(text) => text
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("`{field}` is not a number")),
        _ => Err(format!("`{field}` must be a number")),
    }
}

/// Parse a non-negative integer.
fn u32_field(value: &Value, field: &str) -> Result<u32, String> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or_else(|| format!("`{field}` must be a non-negative integer")),
        Value::String(text) => text
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("`{field}` must be a non-negative integer")),
        _ => Err(format!("`{field}` must be a non-negative integer")),
    }
}

/// Parse a string or array of strings.
fn string_list(value: &Value, field: &str) -> Result<Vec<String>, String> {
    match value {
        Value::String(text) => Ok(vec![text.clone()]),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{field}` must be a string or an array of strings"))
            })
            .collect(),
        _ => Err(format!("`{field}` must be a string or an array of strings")),
    }
}
