//! Documentation registry for the proxy-manager security header options.
//!
//! The registry is the single source of truth for both surfaces:
//!
//! * `GET /api/v1/security-headers/docs` — JSON (`Json<&'static SecurityHeadersDocs>`),
//! * `GET /security-headers/docs` — the same data rendered as an HTML page in the PM UI.
//!
//! It documents every field of [`crate::security_headers::SecurityHeadersDto`]: purpose, default,
//! valid values, examples, security implications, common misconfigurations, the relationship to
//! Caddy's generic `headers` handler, and the behavior-divergence (DIV) entries that describe where
//! caddy-rs is stricter than stock Caddy. Nothing here is generated at request time, and the HTML
//! page is rendered from these same structs, so the page and the API can never disagree.
//!
//! DIV references cite `docs/compatibility/BEHAVIOR-DIVERGENCES.md`:
//! DIV-0120 (CSP parsing/validation), DIV-0121 (HSTS preload validation, HTTPS-only emission),
//! DIV-0122 (`security_headers` extension and its secure defaults), DIV-0131 (reverse-proxy
//! secure-by-default profile).

use axum::http::{header, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// One documented configuration field of the security-headers DTO.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HeaderOptionDoc {
    /// Stable slug used as an anchor in the rendered page.
    pub id: &'static str,
    /// JSON field name in `SecurityHeadersDto` / `SecurityHeadersConfig`.
    pub field: &'static str,
    /// HTTP header the field controls.
    pub header: &'static str,
    /// What the option does and why an operator would set it.
    pub description: &'static str,
    /// Effective default when the field is omitted.
    pub default: &'static str,
    /// Accepted values and their meaning.
    pub valid_values: &'static [&'static str],
    /// Copy-pasteable JSON bodies.
    pub examples: &'static [DocExample],
    /// Security consequences of setting (or not setting) the header.
    pub security_implications: &'static str,
    /// Mistakes seen in the wild and what they cost.
    pub common_misconfigurations: &'static [&'static str],
    /// How this field relates to Caddy's generic `headers` handler.
    pub caddy_headers_handler: &'static str,
    /// Behavior-divergence ids that justify the caddy-rs behavior.
    pub divergences: &'static [&'static str],
}

/// A JSON example for one option.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DocExample {
    /// Short label for the example.
    pub label: &'static str,
    /// JSON body fragment as sent to `PUT /api/v1/security-headers`.
    pub json: &'static str,
}

/// One CSP directive with browser-support caveats.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CspDirectiveDoc {
    /// Directive name, exactly as written in the policy.
    pub directive: &'static str,
    /// What the directive restricts.
    pub purpose: &'static str,
    /// Accepted source expressions.
    pub valid_values: &'static str,
    /// Browser-support notes and the caveat that matters in practice.
    pub browser_support: &'static str,
}

/// HSTS-specific guidance, including the preload irreversibility warning.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HstsDocs {
    /// Keys of the `strict_transport_security` object.
    pub fields: &'static [&'static str],
    /// Validation rules the PM enforces before storing a config.
    pub validation: &'static [&'static str],
    /// The preload warning. Preload is a one-way door; this text is intentionally blunt.
    pub preload_warning: &'static str,
    /// Why a short `max-age` is a rollout tool, not a production value.
    pub rollout_guidance: &'static str,
}

/// X-Frame-Options clickjacking tradeoff.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FrameOptionsDocs {
    /// `DENY` versus `SAMEORIGIN`: which to choose and what breaks.
    pub deny_vs_sameorigin: &'static str,
    /// The modern replacement for framing policy.
    pub csp_frame_ancestors: &'static str,
}

/// A behavior divergence cited by the docs.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DivergenceRef {
    /// Divergence id from `docs/compatibility/BEHAVIOR-DIVERGENCES.md`.
    pub id: &'static str,
    /// Its title.
    pub title: &'static str,
    /// Why it matters for this option set.
    pub relevance: &'static str,
}

/// The whole documentation payload, served as JSON and rendered as HTML.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SecurityHeadersDocs {
    /// Document title.
    pub title: &'static str,
    /// One-paragraph overview.
    pub summary: &'static str,
    /// Routes that expose the config and this documentation.
    pub routes: &'static [&'static str],
    /// Where the defaults come from (and where they differ from stock Caddy).
    pub defaults_note: &'static str,
    /// Whether the global config or a per-host override is in effect.
    pub inheritance_note: &'static str,
    /// Per-option documentation, one entry per DTO field.
    pub options: &'static [HeaderOptionDoc],
    /// CSP directive-by-directive notes.
    pub csp_directives: &'static [CspDirectiveDoc],
    /// CSP-wide notes (validation, nonces, reporting).
    pub csp_notes: &'static [&'static str],
    /// HSTS guidance.
    pub hsts: HstsDocs,
    /// Framing guidance.
    pub frame_options: FrameOptionsDocs,
    /// Cited divergences.
    pub divergences: &'static [DivergenceRef],
    /// Cross-cutting misconfigurations.
    pub common_misconfigurations: &'static [&'static str],
}

/// The JSON field names of the documented DTO, in documentation order.
pub const DOCUMENTED_FIELDS: &[&str] = &[
    "content_security_policy",
    "strict_transport_security",
    "permissions_policy",
    "x_frame_options",
    "x_content_type_options",
    "referrer_policy",
];

const HSTS_PRELOAD_WARNING: &str = "HSTS preload is effectively irreversible. Adding `preload` \
(and the `include_subdomains` it requires) is a request to have every major browser ship your \
domain in a built-in list that forces HTTPS for the domain and *all* of its subdomains. Removal \
takes months: you must first serve `max-age=0` on every host in scope, wait for every browser's \
cached policy to expire, and then wait for a chrome/Chromium list update to propagate. If any \
subdomain cannot serve HTTPS — an internal host, a partner's vanity host, a device with a pinned \
certificate — it becomes unreachable for those users in the meantime. Enable `preload` only when \
you control every subdomain, intend to keep HTTPS there permanently, and have served a stable \
HSTS policy for at least several months.";

const DEFAULTS_NOTE: &str = "caddy-rs is stricter than stock Caddy. When a `security_headers` \
handler is present, omitting `x_frame_options`, `x_content_type_options` and `referrer_policy` \
yields the secure baseline (DENY / nosniff / strict-origin-when-cross-origin); Caddy v2.11.9 \
emits no security headers at all unless the operator spells them out. Content-Security-Policy, \
Strict-Transport-Security and Permissions-Policy are opt-in in both implementations, because a \
wrong value for them breaks a site rather than merely weakening it. The proxy-manager stores the \
JSON form of the same schema the Caddy handler consumes: a PUT body that omits a field gets the \
baseline value for those three headers, while an explicit `null` suppresses the header (see \
`GET /api/v1/security-headers`, which returns the stored document). The reverse-proxy \
secure-by-default profile adds HSTS, nosniff, DENY, strict-origin-when-cross-origin and a \
Permissions-Policy deny list even with no `security_headers` handler (DIV-0131).";

const OPTIONS: &[HeaderOptionDoc] = &[
    HeaderOptionDoc {
        id: "content-security-policy",
        field: "content_security_policy",
        header: "Content-Security-Policy",
        description: "The policy that tells the browser which origins may supply scripts, styles, \
images, frames and connections for this host. It is the primary mitigation for cross-site \
scripting and injected-content attacks: a correctly scoped policy turns a successful HTML \
injection into a blocked request. Send it as a full header-value string. The proxy-manager API \
stores that string verbatim: a PUT body whose value is an object is rejected as a validation \
error. (The caddy-rs handler's JSON config additionally accepts a directive object mapped to \
source lists, DIV-0120, but that form is not part of this API.)",
        default: "none (opt-in): omitting the field (`null`) emits no Content-Security-Policy \
header, matching Caddy's behavior. caddy-rs never invents a CSP for you.",
        valid_values: &[
            "a header-value string: `default-src 'self'; script-src 'self' https://cdn.example.com`",
            "string form only through this API; the directive-object form belongs to the caddy-rs handler JSON config, not to the proxy-manager API (a PUT with an object is rejected with a located validation error)",
            "`{csp.nonce}` inside script-src/src-src to expand a per-response nonce (caddy-rs extension)",
            "directive names from CSP Level 3; `'none'` only as the sole source of a directive",
        ],
        examples: &[
            DocExample {
                label: "string form, strict default-deny with a CDN",
                json: "{\"content_security_policy\": \"default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'; base-uri 'self'\"}",
            },
            DocExample {
                label: "string form with a per-response nonce",
                json: "{\"content_security_policy\": \"default-src 'self'; script-src 'self' {csp.nonce}; frame-ancestors 'none'\"}",
            },
            DocExample {
                label: "explicitly disabled",
                json: "{\"content_security_policy\": null}",
            },
        ],
        security_implications: "A CSP is the cheapest durable defense against injected script. \
`'unsafe-inline'` and `'unsafe-eval'` undo most of that value, and a policy with only \
`default-src *` is decoration. Roll out in report-only mode first if you cannot test: a policy \
that omits a real dependency breaks the page for every user at once, while a policy that is too \
permissive merely fails to protect.",
        common_misconfigurations: &[
            "`default-src 'self'` plus `'unsafe-inline'` for scripts: reports as protected, behaves as unprotected",
            "forgetting `connect-src` for XHR/WebSocket/fetch, which then fails silently in the browser console",
            "setting `frame-ancestors` in a CSP delivered by a meta tag — browsers ignore it there",
            "pasting a policy copied from another site without auditing its CDN and font origins",
            "combining `'none'` with other sources, which caddy-rs rejects at config time (DIV-0120)",
            "sending the directive-object form to the proxy-manager API: it accepts a string header value only and answers a located 400 validation error",
        ],
        caddy_headers_handler: "Caddy stages the literal string and never parses it. caddy-rs \
parses, validates and can build the policy (DIV-0120); the raw string form stays available for \
byte-exact parity with Caddy's `headers` handler.",
        divergences: &["DIV-0120"],
    },
    HeaderOptionDoc {
        id: "strict-transport-security",
        field: "strict_transport_security",
        header: "Strict-Transport-Security",
        description: "Instructs browsers to reach this host (and optionally its subdomains) only \
over HTTPS for a given period, and lets the browser skip the plain-HTTP first request that a \
downgrade attack needs. Configurable as a structured object with `max_age` (seconds), \
`include_subdomains` and `preload`.",
        default: "none (opt-in): omitting the field emits no HSTS header. When set, caddy-rs only \
emits it on TLS responses, never over plain HTTP.",
        valid_values: &[
            "`max_age`: seconds, must be >= 15552000 (180 days); 0 is rejected",
            "`include_subdomains`: boolean; extends the policy to every subdomain",
            "`preload`: boolean; requires `include_subdomains: true` and is a long-term commitment",
            "computed value: `max-age=<seconds>[; includeSubDomains][; preload]` (RFC 6797)",
        ],
        examples: &[
            DocExample {
                label: "recommended production value (one year, subdomains, no preload)",
                json: "{\"strict_transport_security\": {\"max_age\": 31536000, \"include_subdomains\": true, \"preload\": false}}",
            },
            DocExample {
                label: "preload submission candidate",
                json: "{\"strict_transport_security\": {\"max_age\": 31536000, \"include_subdomains\": true, \"preload\": true}}",
            },
            DocExample {
                label: "invalid: preload without include_subdomains (rejected with 400)",
                json: "{\"strict_transport_security\": {\"max_age\": 31536000, \"include_subdomains\": false, \"preload\": true}}",
            },
        ],
        security_implications: "HSTS closes the SSL-stripping window and is the precondition for \
preload. A short `max_age` during rollout is safe and reversible; a long `max_age` with \
`include_subdomains` is what makes it effective, and is also what makes a broken subdomain \
unreachable. Never send HSTS from a host that still serves plain HTTP on purpose.",
        common_misconfigurations: &[
            "choosing `max_age` under 180 days: the PM rejects it (400) instead of storing a weak policy",
            "enabling `include_subdomains` while an internal or legacy subdomain is HTTP-only",
            "setting `preload` as a copy-paste “best practice” without intending a permanent commitment",
            "expecting HSTS to protect the very first visit — the first request is still plain or redirect-only",
            "setting a long `max_age` and later needing plain HTTP back: browsers keep the cached policy until it expires",
        ],
        caddy_headers_handler: "Caddy has no HSTS handler; the generic `headers` handler stages \
whatever string you write, on every matched response including cleartext ones, with no validation. \
caddy-rs validates the directives and only emits HSTS on TLS responses (DIV-0121).",
        divergences: &["DIV-0121", "DIV-0131"],
    },
    HeaderOptionDoc {
        id: "permissions-policy",
        field: "permissions_policy",
        header: "Permissions-Policy",
        description: "Restricts which powerful browser features (camera, microphone, geolocation, \
USB, and so on) the page and its frames may use. Every feature is allowed by default, so this is \
the header that removes capabilities the application never needs, shrinking the impact of \
third-party scripts.",
        default: "none (opt-in) from this field. The reverse-proxy secure-by-default profile ships a \
deny list (accelerometer, camera, geolocation, gyroscope, magnetometer, microphone, payment, usb) \
when no `security_headers` handler opts out (DIV-0131).",
        valid_values: &[
            "comma-separated `feature=(allowlist)` pairs, e.g. `camera=(), geolocation=(self)`",
            "empty parentheses `()` deny the feature for every origin including the page's own",
            "`(self)` allows the same origin; `(self \"https://partner.example\")` allows listed origins",
            "`*` allows all origins (rarely appropriate)",
        ],
        examples: &[
            DocExample {
                label: "deny the common sensor and payment features",
                json: "{\"permissions_policy\": \"accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()\"}",
            },
            DocExample {
                label: "allow geolocation only for this origin",
                json: "{\"permissions_policy\": \"geolocation=(self), camera=()\"}",
            },
        ],
        security_implications: "Least privilege for browser capabilities. It is low-risk to \
deploy and cheap to widen, but a deny list that includes a feature your app uses (geolocation for \
a store locator, payment for a wallet checkout) removes functionality with no visible config error.",
        common_misconfigurations: &[
            "using the obsolete `Feature-Policy` header instead of `Permissions-Policy`, which modern browsers ignore",
            "listing a feature with an allowlist for an origin that never gets framed, giving a false sense of control",
            "denying `fullscreen` or `payment` on a page whose checkout flow needs them",
            "assuming this replaces CSP: it constrains features, not script origins",
        ],
        caddy_headers_handler: "Identical to Caddy's generic `headers` handler: an opaque value \
with no validation in either implementation. Treat typos as silent no-ops.",
        divergences: &["DIV-0131"],
    },
    HeaderOptionDoc {
        id: "x-frame-options",
        field: "x_frame_options",
        header: "X-Frame-Options",
        description: "Controls whether another site may embed this host in a frame or iframe, \
which is the classic clickjacking defense: an attacker overlays invisible frames to trick a \
logged-in user into clicking a destructive control.",
        default: "DENY (secure baseline; caddy-rs is stricter than Caddy, which sends nothing)",
        valid_values: &[
            "`DENY` — no origin may frame this page, including the site itself",
            "`SAMEORIGIN` — only same-origin pages may frame it",
            "`null` — suppress the header entirely (rely on CSP `frame-ancestors` instead)",
        ],
        examples: &[
            DocExample {
                label: "default (strictest)",
                json: "{\"x_frame_options\": \"DENY\"}",
            },
            DocExample {
                label: "allow same-origin framing (dashboards, previews)",
                json: "{\"x_frame_options\": \"SAMEORIGIN\"}",
            },
            DocExample {
                label: "suppress; use CSP frame-ancestors instead",
                json: "{\"x_frame_options\": null, \"content_security_policy\": \"frame-ancestors 'self' https://portal.example.com\"}",
            },
        ],
        security_implications: "DENY is the strictest setting and is right for nearly every \
proxied app. SAMEORIGIN is the correct choice when your own UI frames a proxied page (an admin \
preview pane, a same-site dashboard composition). Both are ignored by browsers that honor CSP \
`frame-ancestors`, which takes precedence — so if you set both, keep them consistent. `ALLOW-FROM` \
is obsolete and unsupported by modern browsers.",
        common_misconfigurations: &[
            "reaching for `SAMEORIGIN` by reflex on an app that is never framed, silently accepting a weaker default",
            "`ALLOW-FROM https://partner.example` — dead syntax, treated as no protection by Chrome and Firefox",
            "setting `frame-ancestors` in CSP while leaving a contradictory `X-Frame-Options: DENY` (CSP wins, the confusion remains)",
            "suppressing the header for an app that genuinely needs it, with no CSP to replace it",
        ],
        caddy_headers_handler: "Caddy would only send this header if the operator wrote it. \
caddy-rs's `security_headers` handler defaults it to DENY and the reverse-proxy profile adds DENY \
to proxied responses (DIV-0122, DIV-0131).",
        divergences: &["DIV-0122", "DIV-0131"],
    },
    HeaderOptionDoc {
        id: "x-content-type-options",
        field: "x_content_type_options",
        header: "X-Content-Type-Options",
        description: "Disables MIME-type sniffing: the browser must trust the declared \
`Content-Type` instead of inspecting the bytes. It stops an uploaded image or text file that \
contains markup from being executed as HTML or JavaScript.",
        default: "nosniff (secure baseline; caddy-rs is stricter than Caddy, which sends nothing)",
        valid_values: &[
            "`nosniff` — the only defined value",
            "`null` — suppress the header entirely (not recommended)",
        ],
        examples: &[
            DocExample {
                label: "default",
                json: "{\"x_content_type_options\": \"nosniff\"}",
            },
            DocExample {
                label: "explicitly disabled (legacy upstream that relies on sniffing)",
                json: "{\"x_content_type_options\": null}",
            },
        ],
        security_implications: "`nosniff` removes a whole class of content-confusion attacks, at \
the cost of exposing misconfigured origins that serve a wrong or missing Content-Type — their \
stylesheets and scripts stop loading instead of being guessed. Keep it on and fix the \
Content-Type upstream.",
        common_misconfigurations: &[
            "typo such as `no-sniff` or `nosniff;` — browsers ignore the unknown value",
            "disabling it to “fix” a broken asset that actually has a wrong upstream Content-Type",
            "expecting it to protect against XSS: it does not, that is CSP's job",
        ],
        caddy_headers_handler: "Same header name and semantics as a Caddy `headers` directive; the \
difference is that caddy-rs sends it by default (DIV-0122, DIV-0131).",
        divergences: &["DIV-0122", "DIV-0131"],
    },
    HeaderOptionDoc {
        id: "referrer-policy",
        field: "referrer_policy",
        header: "Referrer-Policy",
        description: "Controls how much URL information the browser sends in the `Referer` header \
on outbound navigation and subresource requests, including to third parties. It limits leaking \
tokens, query strings and internal paths to analytics, CDNs and advertisers.",
        default: "strict-origin-when-cross-origin (secure baseline; caddy-rs is stricter than \
Caddy, which sends nothing — and this is the modern browser default only for some engines)",
        valid_values: &[
            "`no-referrer` — send nothing, ever",
            "`same-origin` — full URL for same-origin requests, nothing cross-origin",
            "`strict-origin-when-cross-origin` — full URL same-origin, origin only cross-origin, nothing on HTTPS->HTTP downgrade",
            "`strict-origin`, `origin-when-cross-origin`, `origin`, `no-referrer-when-downgrade`, `unsafe-url` (last is not recommended)",
        ],
        examples: &[
            DocExample {
                label: "default",
                json: "{\"referrer_policy\": \"strict-origin-when-cross-origin\"}",
            },
            DocExample {
                label: "maximum privacy",
                json: "{\"referrer_policy\": \"no-referrer\"}",
            },
        ],
        security_implications: "Cross-origin referrers leak path and query data; a reset-password \
URL with a token in the query is the worst case. `no-referrer` breaks analytics attribution and \
some OAuth/sign-in flows that compare the referring page, so \
`strict-origin-when-cross-origin` is the pragmatic default. Pair it with a per-request nonce-free \
token policy (short-lived, single-use tokens) rather than relying on referrer suppression alone.",
        common_misconfigurations: &[
            "`unsafe-url` copied from a legacy guide",
            "setting `no-referrer` and then wondering why OAuth or analytics attribution stopped",
            "relying on this header to keep tokens out of server logs — proxies still log the path",
        ],
        caddy_headers_handler: "The same header Caddy's `headers` handler could send; caddy-rs \
sends the strict form by default (DIV-0122, DIV-0131).",
        divergences: &["DIV-0122", "DIV-0131"],
    },
];

const CSP_DIRECTIVES: &[CspDirectiveDoc] = &[
    CspDirectiveDoc {
        directive: "default-src",
        purpose: "Fallback for every fetch directive that is not listed explicitly.",
        valid_values: "source list: `'self'`, `'none'`, origins, schemes, `'unsafe-inline'`, `'unsafe-eval'`, nonces, hashes",
        browser_support: "Universal in CSP Level 1 browsers. It is the only directive you truly need to get right: an unlisted directive inherits it, and an empty policy falls back to allow-all.",
    },
    CspDirectiveDoc {
        directive: "script-src",
        purpose: "Which scripts may execute: external origins, inline scripts and eval-like constructs.",
        valid_values: "source list; `'nonce-<base64>'` or `{csp.nonce}` (expanded per response); `'sha256-...'` hashes; `'strict-dynamic'`",
        browser_support: "`'strict-dynamic'` and nonce support are reliable only in CSP Level 2+ browsers (Chrome/Edge/Firefox/Safari since 2016-ish); older Safari and IE ignore `'strict-dynamic'` while still honoring host allowlists, so keep a host list alongside it. Nonce-based policies need every inline script to carry the nonce.",
    },
    CspDirectiveDoc {
        directive: "style-src",
        purpose: "Which stylesheets and inline styles may apply.",
        valid_values: "source list; nonces/hashes for inline `<style>`; `'unsafe-inline'` to allow all inline CSS",
        browser_support: "Universal. Inline-style nonces are CSP Level 2+; many apps still need `'unsafe-inline'` here, which is a much smaller risk than for scripts.",
    },
    CspDirectiveDoc {
        directive: "img-src",
        purpose: "Where images may be loaded from (including tracking pixels and data: URIs).",
        valid_values: "source list, `data:` for inline images, `blob:` for generated images",
        browser_support: "Universal. Forgetting `data:` breaks base64 icons; forgetting an image CDN makes images silently disappear.",
    },
    CspDirectiveDoc {
        directive: "connect-src",
        purpose: "Which endpoints `fetch`, XHR, WebSocket and EventSource may reach.",
        valid_values: "source list; include `wss://` origins explicitly for WebSockets",
        browser_support: "Universal, but WebSocket enforcement varies in older Safari. Missing entries fail only at runtime, so test the real user flows.",
    },
    CspDirectiveDoc {
        directive: "font-src",
        purpose: "Which origins may supply web fonts.",
        valid_values: "source list, `data:` for inlined fonts",
        browser_support: "Universal. A blocked font usually degrades silently to a fallback face, which is easy to miss in review.",
    },
    CspDirectiveDoc {
        directive: "style-src-elem / style-src-attr",
        purpose: "Split inline style elements from style attributes (CSP Level 3).",
        valid_values: "source list; `'unsafe-hashes'` for attribute handlers",
        browser_support: "CSP Level 3; Chrome/Edge/Firefox support them, Safari's support is incomplete — keep `style-src` as the fallback for those browsers.",
    },
    CspDirectiveDoc {
        directive: "object-src",
        purpose: "Plugins and `<object>`/`<embed>` content such as legacy Flash or PDF viewers.",
        valid_values: "source list; `'none'` is the recommended value",
        browser_support: "Universal. Setting `object-src 'none'` is nearly free and closes legacy plugin execution.",
    },
    CspDirectiveDoc {
        directive: "base-uri",
        purpose: "Restricts the URLs a `<base>` element may set, blocking base-tag injection attacks.",
        valid_values: "source list; `'self'` or `'none'`",
        browser_support: "CSP Level 2+; ignored by Internet Explorer. Harmless where unsupported.",
    },
    CspDirectiveDoc {
        directive: "form-action",
        purpose: "Which URLs a form may submit to, limiting credential exfiltration through injected forms.",
        valid_values: "source list of origins",
        browser_support: "CSP Level 2+; supported by all current browsers, not enforced on redirects that a submission follows in older engines.",
    },
    CspDirectiveDoc {
        directive: "frame-ancestors",
        purpose: "Which origins may frame this page; the modern replacement for X-Frame-Options.",
        valid_values: "source list; `'none'` denies all framing, `'self'` allows same-origin",
        browser_support: "CSP Level 2+; ignored in a `<meta>` tag and ignored by Internet Explorer, so pair it with X-Frame-Options for old clients.",
    },
    CspDirectiveDoc {
        directive: "upgrade-insecure-requests",
        purpose: "Rewrites http:// subresource requests to https:// before they are sent.",
        valid_values: "valueless directive (caddy-rs rejects values on valueless directives)",
        browser_support: "CSP Level 2+ (no IE). Helpful during migration; it can break a page that genuinely depends on a plain-HTTP subresource.",
    },
    CspDirectiveDoc {
        directive: "report-uri / report-to",
        purpose: "Sends violation reports to a collector so a policy can be tuned from real traffic.",
        valid_values: "exactly one URL (caddy-rs rejects multiple values); `report-to` names a Reporting API group",
        browser_support: "`report-uri` is broadly supported but deprecated; `report-to` is the replacement and is not supported by Safari. Accept either, and prefer report-only rollout (`Content-Security-Policy-Report-Only`) before enforcing.",
    },
];

const DIVERGENCES: &[DivergenceRef] = &[
    DivergenceRef {
        id: "DIV-0120",
        title: "caddy-rs parses, validates and builds Content-Security-Policy values where Caddy only stages an opaque header",
        relevance: "Explains why a malformed CSP is rejected at config time with a located error instead of silently weakening the policy in the browser.",
    },
    DivergenceRef {
        id: "DIV-0121",
        title: "`security_headers` adds HSTS preload validation and HTTPS-only emission",
        relevance: "Explains the 180-day `max_age` floor, the `preload` => `include_subdomains` rule, and why HSTS is never emitted over cleartext even when configured.",
    },
    DivergenceRef {
        id: "DIV-0122",
        title: "`security_headers` is a caddy-rs extension whose staged headers follow route-order precedence",
        relevance: "Explains the strict defaults (DENY / nosniff / strict-origin-when-cross-origin) that stock Caddy does not send, and how per-host, per-route and subroute values resolve.",
    },
    DivergenceRef {
        id: "DIV-0131",
        title: "Reverse-proxy responses get secure-by-default headers and lose fingerprint headers",
        relevance: "Explains why proxied responses carry HSTS plus four security headers and a Permissions-Policy deny list even when no `security_headers` handler is configured.",
    },
];

const CSP_NOTES: &[&str] = &[
    "caddy-rs validates directive names against the CSP Level 3 set and sources against the CSP grammar at config time; an unknown directive, a non-ASCII source or `'none'` mixed with other sources is a located error (DIV-0120).",
    "`{csp.nonce}` is expanded per response with a fresh 16-byte CSPRNG nonce, so a cached HTML response must not embed it.",
    "Directive order is normalized on serialization (lexicographic, single spaces), so the stored value and the emitted header can differ in whitespace only.",
    "Start with `Content-Security-Policy-Report-Only` and a `report-uri` when tightening a live site; switch to enforcement once the reports are quiet.",
];

const CROSS_CUTTING_MISCONFIGURATIONS: &[&str] = &[
    "setting a per-host override to `null` for every field, believing it inherits: an explicit per-host config replaces the global one for that host, so inheritance must be left unset",
    "treating `X-Frame-Options: SAMEORIGIN` plus `frame-ancestors *` as defense in depth — CSP wins and the framing policy is effectively open",
    "deploying HSTS `preload` and CSP enforcement in the same change, so a rollback cannot be tested independently",
    "assuming the PM's stored config is the whole story: the reverse-proxy secure-by-default profile (DIV-0131) also applies unless a `security_headers` handler opts the route out",
    "forgetting that headers only affect responses: misconfigured upstreams still serve the wrong Content-Type, and `nosniff` will then surface the breakage as blocked assets",
];

const HSTS_VALIDATION: &[&str] = &[
    "`max_age` must be greater than 0",
    "`max_age` must be at least 15552000 seconds (180 days)",
    "`preload: true` requires `include_subdomains: true`",
    "caddy-rs emits the header only on TLS responses (DIV-0121)",
];

static DOCS: SecurityHeadersDocs = SecurityHeadersDocs {
    title: "Proxy manager security headers",
    summary: "Every security header option the proxy manager exposes, with its default, accepted \
values, examples, security consequences and failure modes. caddy-rs is stricter than stock Caddy: \
the three low-risk headers default to their secure form, and the three that can break a site \
(CSP, HSTS, Permissions-Policy) are opt-in but validated when set. The same documentation is \
served as JSON at `/api/v1/security-headers/docs` and as this page at `/security-headers/docs`.",
    routes: &[
        "GET /api/v1/security-headers  — global config with defaults applied (JSON)",
        "PUT /api/v1/security-headers  — validate and store the global config (JSON)",
        "GET /api/v1/hosts/{id}/security-headers — effective per-host config (inherits the global one)",
        "PUT /api/v1/hosts/{id}/security-headers — validate and store a per-host override",
        "GET /api/v1/security-headers/docs — this documentation (JSON)",
        "GET /security-headers/docs — this documentation (HTML, PM UI)",
    ],
    defaults_note: DEFAULTS_NOTE,
    inheritance_note: "A host's `security_headers` field is optional. When it is unset the host \
inherits the global config; when it is set it replaces the global config for that host (it does \
not merge field by field). Set the global config once, then override only the hosts that need a \
different CSP or framing policy.",
    options: OPTIONS,
    csp_directives: CSP_DIRECTIVES,
    csp_notes: CSP_NOTES,
    hsts: HstsDocs {
        fields: &["max_age", "include_subdomains", "preload"],
        validation: HSTS_VALIDATION,
        preload_warning: HSTS_PRELOAD_WARNING,
        rollout_guidance: "Roll out in stages: a short `max_age` (for example 300 seconds) while \
you confirm every host serves HTTPS, then a month, then one year with `include_subdomains`, and \
only then consider `preload`. Each step is reversible by lowering `max_age`; preload is not.",
    },
    frame_options: FrameOptionsDocs {
        deny_vs_sameorigin: "`DENY` blocks framing by every origin, including your own site. Use it \
for any application that is not meant to be embedded — it is the default and the safest choice. \
`SAMEORIGIN` allows your own pages to frame the app, which you need for an admin preview pane, a \
same-site dashboard, or an app that frames itself after login; it still blocks third-party \
clickjacking. The cost of `SAMEORIGIN` is that a cross-site scripting or HTML-injection bug on any \
same-origin page can frame the protected app and clickjack its own users, so choose it only when \
same-origin framing is a real product requirement. Neither value does anything once a CSP \
`frame-ancestors` directive is present: browsers honor `frame-ancestors` and ignore \
`X-Frame-Options`, so keep the two consistent (`DENY` ≈ `frame-ancestors 'none'`, `SAMEORIGIN` ≈ \
`frame-ancestors 'self'`).",
        csp_frame_ancestors: "Prefer `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) \
for new deployments and keep `X-Frame-Options` for older browsers that ignore it.",
    },
    divergences: DIVERGENCES,
    common_misconfigurations: CROSS_CUTTING_MISCONFIGURATIONS,
};

/// The documentation payload. Both surfaces read from this one static.
pub fn docs() -> &'static SecurityHeadersDocs {
    &DOCS
}

/// `GET /api/v1/security-headers/docs` — the documentation as JSON.
pub async fn docs_handler() -> Json<&'static SecurityHeadersDocs> {
    Json(docs())
}

/// `GET /security-headers/docs` — the same documentation rendered for the PM UI.
pub async fn docs_page_handler() -> Response {
    let mut response = Html(render_page(docs())).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; \
             frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Escape text for HTML text nodes and attribute values.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn paragraph(text: &str) -> String {
    format!("<p>{}</p>", escape(text))
}

fn bullet_list(items: &[&str]) -> String {
    let mut out = String::from("<ul>");
    for item in items {
        out.push_str(&format!("<li>{}</li>", escape(item)));
    }
    out.push_str("</ul>");
    out
}

/// Render the documentation page from [`Docs`]. Pure string assembly, no template engine.
pub fn render_page(docs: &SecurityHeadersDocs) -> String {
    let mut body = String::new();
    body.push_str(&format!("<h1>{}</h1>", escape(docs.title)));
    body.push_str(&paragraph(docs.summary));
    body.push_str(&format!(
        "<p class=\"api-link\">Same content as JSON: \
         <a href=\"/api/v1/security-headers/docs\">/api/v1/security-headers/docs</a> · \
         <a href=\"/\">back to the proxy manager</a></p>"
    ));
    body.push_str("<h2>Defaults and stricter-than-Caddy behavior</h2>");
    body.push_str(&paragraph(docs.defaults_note));
    body.push_str("<h2>Routes</h2>");
    body.push_str(&bullet_list(docs.routes));
    body.push_str("<h2>Inheritance</h2>");
    body.push_str(&paragraph(docs.inheritance_note));

    body.push_str("<h2>Options</h2>");
    for option in docs.options {
        body.push_str(&format!(
            "<section class=\"option\" id=\"{}\"><h3>{} <code>{}</code></h3>",
            escape(option.id),
            escape(option.field),
            escape(option.header)
        ));
        body.push_str(&paragraph(option.description));
        body.push_str(&format!(
            "<p><strong>Default:</strong> {}</p><p><strong>Valid values:</strong></p>{}",
            escape(option.default),
            bullet_list(option.valid_values)
        ));
        body.push_str("<p><strong>Examples</strong></p><ul>");
        for example in option.examples {
            body.push_str(&format!(
                "<li>{}<pre><code>{}</code></pre></li>",
                escape(example.label),
                escape(example.json)
            ));
        }
        body.push_str("</ul>");
        body.push_str(&format!(
            "<p><strong>Security implications:</strong> {}</p>",
            escape(option.security_implications)
        ));
        body.push_str("<p><strong>Common misconfigurations</strong></p>");
        body.push_str(&bullet_list(option.common_misconfigurations));
        body.push_str(&format!(
            "<p><strong>Relation to Caddy's <code>headers</code> handler:</strong> {}</p>",
            escape(option.caddy_headers_handler)
        ));
        body.push_str(&format!(
            "<p><strong>Divergences:</strong> {}</p></section>",
            escape(&option.divergences.join(", "))
        ));
    }

    body.push_str("<h2>Content-Security-Policy directives</h2>");
    body.push_str(&bullet_list(docs.csp_notes));
    body.push_str(
        "<table><thead><tr><th>Directive</th><th>Purpose</th><th>Valid values</th>\
         <th>Browser support</th></tr></thead><tbody>",
    );
    for directive in docs.csp_directives {
        body.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(directive.directive),
            escape(directive.purpose),
            escape(directive.valid_values),
            escape(directive.browser_support)
        ));
    }
    body.push_str("</tbody></table>");

    body.push_str("<h2>Strict-Transport-Security</h2>");
    body.push_str("<p><strong>Validation rules:</strong></p>");
    body.push_str(&bullet_list(docs.hsts.validation));
    body.push_str(&format!(
        "<p class=\"warning\"><strong>Preload warning:</strong> {}</p>",
        escape(docs.hsts.preload_warning)
    ));
    body.push_str(&paragraph(docs.hsts.rollout_guidance));

    body.push_str("<h2>X-Frame-Options: DENY vs SAMEORIGIN</h2>");
    body.push_str(&paragraph(docs.frame_options.deny_vs_sameorigin));
    body.push_str(&paragraph(docs.frame_options.csp_frame_ancestors));

    body.push_str("<h2>Common misconfigurations</h2>");
    body.push_str(&bullet_list(docs.common_misconfigurations));

    body.push_str("<h2>Behavior divergences from Caddy</h2>");
    for divergence in docs.divergences {
        body.push_str(&format!(
            "<p><strong>{}</strong> — {}<br><em>{}</em></p>",
            escape(divergence.id),
            escape(divergence.title),
            escape(divergence.relevance)
        ));
    }

    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title>\
         <style>\
         body{{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;\
         line-height:1.5;color:#1b1b1b;background:#fff}}\
         h1{{font-size:1.8rem}}h2{{margin-top:2.5rem;border-bottom:1px solid #ddd;padding-bottom:.3rem}}\
         code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:.9em}}\
         pre{{background:#f4f4f4;padding:.6rem;overflow-x:auto;border-radius:4px}}\
         table{{border-collapse:collapse;width:100%;font-size:.92em}}\
         th,td{{border:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top}}\
         .warning{{border-left:4px solid #b00020;padding:.6rem;background:#fdf0f2}}\
         .api-link{{font-size:.95em;color:#444}}\
         </style></head><body>{body}</body></html>",
        title = escape(docs.title),
        body = body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_field_is_unique_and_non_empty() {
        for option in DOCS.options {
            assert!(
                !option.description.is_empty(),
                "{} has no description",
                option.id
            );
            assert!(!option.default.is_empty(), "{} has no default", option.id);
            assert!(
                !option.valid_values.is_empty(),
                "{} has no values",
                option.id
            );
            assert!(!option.examples.is_empty(), "{} has no example", option.id);
        }
        let mut fields: Vec<&str> = DOCS.options.iter().map(|o| o.field).collect();
        let count = fields.len();
        fields.sort_unstable();
        fields.dedup();
        assert_eq!(count, fields.len(), "duplicate documented field");
        assert_eq!(count, DOCUMENTED_FIELDS.len());
    }

    #[test]
    fn the_rendered_page_contains_every_option_and_warning() {
        let page = render_page(&docs());
        for option in DOCS.options {
            assert!(page.contains(option.field), "page misses {}", option.field);
            assert!(page.contains(&escape(&option.default[..20])));
        }
        assert!(page.contains("Preload warning"));
        assert!(page.contains("DENY vs SAMEORIGIN"));
        assert!(page.contains("/api/v1/security-headers/docs"));
        assert!(page.contains("DIV-0121"));
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(escape("a<b&c'd\"e"), "a&lt;b&amp;c&#39;d&quot;e");
        assert!(!render_page(&docs()).contains("<script"));
    }
}
