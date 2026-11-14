//! Application-layer access control for the mutual-TLS admin endpoint
//! (`admin.remote.access_control`).
//!
//! Port of Caddy v2.11.9 `RemoteAdmin.enforceAccessControls` and `adminPathAllowed`
//! (`external/caddy/admin.go:678-758`). The TLS listener has already verified the client
//! certificate chain against the pool built from every `public_keys` entry; this module decides
//! whether the verified identity is authorized for the request path and method, and reports the
//! same 401/403 outcomes and messages upstream uses.
//!
//! Identity binding is cryptographic (T-ADMIN-061). Each `public_keys` entry is a trust anchor,
//! so an entry matches only when the presented certificate chain verifies to that entry's anchor:
//!
//! - Upstream scans `r.TLS.VerifiedChains`, which includes the trust anchor; rustls
//!   `peer_certificates()` omits the root. [`public_key_matches`] therefore compares the
//!   configured certificate's SubjectPublicKeyInfo with the presented **leaf** only (the
//!   configured-leaf anchor case, which WebPKI cannot express because it rejects an anchor that is
//!   itself the end entity) *and* re-verifies the presented chain against the configured anchor
//!   with WebPKI path validation (`caddy_rs_tls::chain_anchored_by`), which covers configured
//!   roots and intermediates that the client does not present. Certificates the client appends
//!   after the leaf are never inspected by key: they are not proven path members, and scanning
//!   them would let any client borrow another entry's permissions by appending that entry's
//!   public certificate (the T-ADMIN-061 review finding). Distinguished names never authorize a
//!   client: a certificate from another configured CA that copies a configured subject DN stays
//!   bound to its own CA and does not inherit that identity's permissions.
//! - `subjects`/`serials` are caddy-rs extensions and are **advisory filters only**: CA-chosen
//!   values that can narrow, never widen, an entry's `public_keys` match. They are never the sole
//!   basis for authorizing a client; an entry without `public_keys` matches no one (upstream
//!   behaviour).

use caddy_rs_core::{AdminAccess, AdminPermissions, AdminRemote};
use http::{Method, StatusCode};

/// The authenticated client identity of a request on the secure admin listener.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminClientIdentity {
    /// DER-encoded certificates presented by the client, leaf first.
    pub certificates: Vec<Vec<u8>>,
    /// Subject distinguished name of the leaf certificate (Go `x509.Name.String()` form).
    ///
    /// CA-chosen metadata: usable as an advisory filter (`access_control[*].subjects`), never as
    /// proof of identity.
    pub subject: String,
    /// Issuer distinguished name of the leaf certificate. Advisory only, like [`Self::subject`].
    pub issuer: String,
    /// Serial number of the leaf certificate in decimal. Advisory only; compare with
    /// `access_control[*].serials` as a filter, never as authentication.
    pub serial: String,
}

impl AdminClientIdentity {
    /// DER of the leaf certificate presented by the client, if any.
    pub fn leaf_der(&self) -> Option<&[u8]> {
        self.certificates.first().map(Vec::as_slice)
    }
}

/// A denied request: the HTTP status and message Caddy returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDenial {
    /// HTTP status (`401` for an unrecognized identity, `403` for a recognized but unauthorized
    /// request, matching upstream).
    pub status: StatusCode,
    /// Response message, upstream wording.
    pub message: String,
}

impl AccessDenial {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "client identity not authorized".to_string(),
        }
    }

    fn path() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "not authorized to access this path".to_string(),
        }
    }

    fn method() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "not authorized to use this method".to_string(),
        }
    }

    /// Fail-closed denial for a request that arrived on the remote listener but whose verified
    /// client certificate could not be parsed into identity metadata.
    ///
    /// The handshake proved possession of a certificate anchored in the configured pool, but the
    /// application layer cannot bind it to an access-control entry, so it must not fall through to
    /// the plaintext origin policy (where a forged `Host`/`Origin` could pass).
    fn unparsable_client_certificate() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "client certificate could not be parsed".to_string(),
        }
    }
}

/// Decide a request from its transport state, for requests that did not arrive on the plaintext
/// listener.
///
/// [`ClientIdentity::NotPresented`] denies as well: the plaintext origin policy is applied by the
/// caller, never here, so an unexpected state fails closed with 401.
pub fn decide_client(
    remote: Option<&AdminRemote>,
    client: &crate::ClientIdentity,
    method: &Method,
    path: &str,
) -> Result<(), AccessDenial> {
    match client {
        crate::ClientIdentity::Verified(identity) => decide(remote, Some(identity), method, path),
        crate::ClientIdentity::Unparsable => Err(AccessDenial::unparsable_client_certificate()),
        crate::ClientIdentity::NotPresented => Err(AccessDenial::unauthorized()),
    }
}

/// Decide whether `identity` may perform `method` on `path` under `remote`.
///
/// An absent `remote` (remote administration not configured in the active generation) denies
/// every request: the decision is read from the live configuration so a reload cannot leave a
/// request running under stale permissions.
pub fn decide(
    remote: Option<&AdminRemote>,
    identity: Option<&AdminClientIdentity>,
    method: &Method,
    path: &str,
) -> Result<(), AccessDenial> {
    let (Some(remote), Some(identity)) = (remote, identity) else {
        return Err(AccessDenial::unauthorized());
    };

    // The same identity may appear in more than one entry; the request is allowed if any entry
    // containing it permits it (upstream `admin.go:686-688`).
    let mut identity_recognized = false;
    let mut path_allowed_somewhere = false;

    for access in &remote.access_control {
        if !access_matches_identity(access, identity) {
            continue;
        }
        identity_recognized = true;

        // No permissions configured grants everything (`len(adminAccess.Permissions) == 0`).
        if access.permissions.is_empty() {
            return Ok(());
        }
        for permission in &access.permissions {
            let path_found = match &permission.paths {
                None => true,
                Some(paths) => paths
                    .iter()
                    .any(|allowed| admin_path_allowed(path, allowed)),
            };
            if !path_found {
                continue;
            }
            path_allowed_somewhere = true;
            if permission_method_allowed(permission, method) {
                return Ok(());
            }
        }
    }

    if identity_recognized {
        if path_allowed_somewhere {
            return Err(AccessDenial::method());
        }
        return Err(AccessDenial::path());
    }
    Err(AccessDenial::unauthorized())
}

/// Whether an access-control entry names this identity.
///
/// The entry's `public_keys` are trust anchors, so a match requires the presented key material to
/// belong to one of them ([`public_key_matches`]). `subjects`/`serials` are advisory filters over
/// CA-chosen values: when present they can only narrow the entry, never widen it, and an entry
/// without `public_keys` matches no client.
fn access_matches_identity(access: &AdminAccess, identity: &AdminClientIdentity) -> bool {
    if !access
        .public_keys
        .iter()
        .any(|key| public_key_matches(key, identity))
    {
        return false;
    }
    let subject_ok = access.subjects.is_empty()
        || access
            .subjects
            .iter()
            .any(|subject| subject.trim() == identity.subject.trim());
    let serial_ok = access.serials.is_empty()
        || access
            .serials
            .iter()
            .any(|serial| serial.trim() == identity.serial);
    subject_ok && serial_ok
}

/// Whether one configured base64 DER certificate authorizes the presented client chain.
///
/// Cryptographic binding only; distinguished names are never consulted. Matches when:
/// - the presented **leaf** certificate's SubjectPublicKeyInfo equals the configured
///   certificate's (configured-leaf anchor), or
/// - the presented chain verifies to the configured certificate as its trust anchor (upstream's
///   scan over the root, which rustls does not expose via `peer_certificates()`).
///
/// Intermediate anchors are supported through the verified path: WebPKI tries the configured
/// trust anchor before any presented intermediate, so a configured intermediate that issued the
/// leaf verifies directly (whether or not the client presents that intermediate), and one above
/// the leaf verifies through the client-presented intermediates. Nothing else is accepted for
/// them, so an intermediate anchor never authorizes a leaf it did not issue.
fn public_key_matches(configured: &str, identity: &AdminClientIdentity) -> bool {
    use base64::Engine as _;

    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
        return false;
    };
    leaf_spki_matches(&der, identity)
        || caddy_rs_tls::chain_anchored_by(&der, &identity.certificates)
}

/// Whether the presented leaf certificate carries the same SubjectPublicKeyInfo as `configured_der`.
///
/// Only `certificates[0]` is compared: the TLS layer verified it as the end entity. Certificates
/// appended after it are unverified extras and must never be used to bind an identity.
fn leaf_spki_matches(configured_der: &[u8], identity: &AdminClientIdentity) -> bool {
    let Some(leaf) = identity.leaf_der() else {
        return false;
    };
    let Ok(configured) = caddy_rs_tls::ClientCertificateInfo::parse(configured_der, false) else {
        return false;
    };
    if configured.public_key_der.is_empty() {
        return false;
    }
    caddy_rs_tls::ClientCertificateInfo::parse(leaf, false)
        .map(|info| info.public_key_der == configured.public_key_der)
        .unwrap_or(false)
}

/// Upstream `adminPathAllowed` (`external/caddy/admin.go:742`).
///
/// An empty or `/` allowed path admits every request; otherwise the request path must equal the
/// allowed path (respecting an allowed trailing slash) or extend it at a path-segment boundary.
pub(crate) fn admin_path_allowed(request_path: &str, allowed_path: &str) -> bool {
    let request_had_trailing_slash = request_path.ends_with('/');
    let request_path = clean_path(request_path);
    if allowed_path.is_empty() {
        return true;
    }
    let allowed_had_trailing_slash = allowed_path != "/" && allowed_path.ends_with('/');
    let allowed_path = clean_path(allowed_path);
    if allowed_path == "/" {
        return true;
    }
    if request_path == allowed_path {
        return !allowed_had_trailing_slash || request_had_trailing_slash;
    }
    request_path.starts_with(&format!("{allowed_path}/"))
}

/// Whether the permission admits `method`: no `methods` list admits every method.
fn permission_method_allowed(permission: &AdminPermissions, method: &Method) -> bool {
    match &permission.methods {
        None => true,
        Some(methods) => methods.iter().any(|allowed| allowed == method.as_str()),
    }
}

/// Lexical path cleaning equivalent to Go's `path.Clean` for absolute paths.
fn clean_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    format!("/{}", segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientIdentity;

    // Test PKI (crates/admin/testdata/access-control): two CAs and two client certificates whose
    // subject DN is identical (`CN=admin-a,O=caddy-rs`) but whose keys/issuers differ. That is the
    // cross-CA spoofing setup: an attacker certificate copies the configured identity's subject DN.
    const CA_A_PEM: &str = include_str!("../testdata/access-control/ca-a.pem");
    const CA_B_PEM: &str = include_str!("../testdata/access-control/ca-b.pem");
    const CLIENT_A_PEM: &str = include_str!("../testdata/access-control/client-a.pem");
    const CLIENT_B_PEM: &str = include_str!("../testdata/access-control/client-b.pem");

    fn remote(json: serde_json::Value) -> AdminRemote {
        serde_json::from_value(json).expect("valid admin.remote configuration")
    }

    fn certificate_der(pem: &str) -> Vec<u8> {
        caddy_rs_tls::certificates_from_pem(pem)
            .expect("PEM certificate")
            .first()
            .expect("one certificate")
            .as_ref()
            .to_vec()
    }

    fn certificate_base64(pem: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(certificate_der(pem))
    }

    /// The identity the TLS layer builds from a client that presents exactly one certificate
    /// (rustls `peer_certificates()`; the root is not included).
    fn identity(pem: &str) -> AdminClientIdentity {
        let leaf = certificate_der(pem);
        let info =
            caddy_rs_tls::ClientCertificateInfo::parse(&leaf, true).expect("certificate info");
        AdminClientIdentity {
            certificates: vec![leaf],
            subject: info.subject,
            issuer: info.issuer,
            serial: info.serial,
        }
    }

    /// The legitimate client of CA-A.
    fn victim() -> AdminClientIdentity {
        identity(CLIENT_A_PEM)
    }

    /// A client of CA-B whose subject DN was copied from the CA-A client's certificate.
    fn attacker() -> AdminClientIdentity {
        identity(CLIENT_B_PEM)
    }

    fn method(value: &str) -> Method {
        value.parse().expect("valid method")
    }

    fn allowed(
        remote: &AdminRemote,
        identity: &AdminClientIdentity,
        verb: &str,
        path: &str,
    ) -> bool {
        decide(Some(remote), Some(identity), &method(verb), path).is_ok()
    }

    fn expect_denial(
        remote: &AdminRemote,
        identity: &AdminClientIdentity,
        verb: &str,
        path: &str,
    ) -> AccessDenial {
        decide(Some(remote), Some(identity), &method(verb), path).expect_err("denied")
    }

    #[test]
    fn configured_root_key_authorizes_the_clients_it_issued() {
        // The client presents only its leaf; the configured CA is the (unpresented) trust anchor,
        // which rustls `peer_certificates()` omits and upstream reads from `VerifiedChains`.
        let remote = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "permissions": [{ "paths": ["/config/"], "methods": ["GET"] }]
            }]
        }));
        assert!(allowed(&remote, &victim(), "GET", "/config/"));
        assert!(allowed(&remote, &victim(), "GET", "/config/apps/http"));
        // A path that merely shares a character prefix is not allowed.
        assert!(!allowed(&remote, &victim(), "GET", "/configuration"));
        assert!(!allowed(&remote, &victim(), "GET", "/config"));
        // A client of the other CA is not anchored by this entry.
        assert!(!allowed(&remote, &attacker(), "GET", "/config/"));
    }

    #[test]
    fn spoofed_subject_dn_from_another_ca_does_not_inherit_permissions() {
        let victim_identity = victim();
        let attacker_identity = attacker();
        assert_eq!(
            victim_identity.subject, attacker_identity.subject,
            "spoof precondition: the attacker certificate copies identity A's subject DN"
        );
        assert_ne!(victim_identity.issuer, attacker_identity.issuer);

        // Entry A names identity A's subject as an advisory filter; the CA-B client copies that
        // DN. A subject-only match would hand it identity A's `/config/` permission.
        let remote = remote(serde_json::json!({
            "access_control": [
                {
                    "public_keys": [certificate_base64(CA_A_PEM)],
                    "subjects": [victim_identity.subject.clone()],
                    "permissions": [{ "paths": ["/config/"] }]
                },
                {
                    "public_keys": [certificate_base64(CA_B_PEM)],
                    "permissions": [{ "paths": ["/id/"] }]
                }
            ]
        }));

        // The attacker is recognized as a CA-B client, so its own (narrower) permissions decide:
        // 403, not identity A's `/config/` permission.
        let denial = expect_denial(&remote, &attacker_identity, "GET", "/config/");
        assert_eq!(denial.status, StatusCode::FORBIDDEN);
        assert_eq!(denial.message, "not authorized to access this path");
        assert!(allowed(&remote, &attacker_identity, "GET", "/id/"));
        assert!(allowed(&remote, &victim_identity, "GET", "/config/"));
    }

    #[test]
    fn configured_leaf_certificate_binds_to_its_key_not_its_subject_dn() {
        // Upstream also accepts a client certificate itself as an anchor. Matching it by subject
        // DN would let the CA-B client (same DN) in; matching by key does not.
        let remote = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CLIENT_A_PEM)],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        assert!(allowed(&remote, &victim(), "GET", "/config/"));
        let denial = expect_denial(&remote, &attacker(), "GET", "/config/");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
        assert_eq!(denial.message, "client identity not authorized");
    }

    #[test]
    fn subject_selector_only_narrows_the_public_key_match() {
        // Same key material, subject filter excludes it: the entry no longer matches.
        let narrowed = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "subjects": ["CN=someone-else"],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        assert!(!allowed(&narrowed, &victim(), "GET", "/config/"));

        // A matching subject DN with the wrong key never authorizes on its own.
        let advisory_only = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_B_PEM)],
                "subjects": [victim().subject],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        assert!(!allowed(&advisory_only, &victim(), "GET", "/config/"));

        // An entry with subjects but no public_keys matches nobody (upstream behaviour).
        let no_key = remote(serde_json::json!({
            "access_control": [{
                "subjects": [victim().subject],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        assert!(!allowed(&no_key, &victim(), "GET", "/config/"));
    }

    #[test]
    fn serial_selector_only_narrows_the_public_key_match() {
        let victim_identity = victim();
        let matching = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "serials": [victim_identity.serial],
                "permissions": [{ "paths": ["/id/"] }]
            }]
        }));
        assert!(allowed(&matching, &victim_identity, "POST", "/id/anything"));

        let mismatched = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "serials": ["999"],
                "permissions": [{ "paths": ["/id/"] }]
            }]
        }));
        assert!(!allowed(
            &mismatched,
            &victim_identity,
            "POST",
            "/id/anything"
        ));

        let other_ca = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_B_PEM)],
                "serials": [victim_identity.serial],
                "permissions": [{ "paths": ["/id/"] }]
            }]
        }));
        assert!(!allowed(
            &other_ca,
            &victim_identity,
            "POST",
            "/id/anything"
        ));
    }

    #[test]
    fn denies_wrong_identity_with_401() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_B_PEM)],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        let denial = expect_denial(&remote, &victim(), "GET", "/config/");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
        assert_eq!(denial.message, "client identity not authorized");
    }

    #[test]
    fn denies_disallowed_method_with_403() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "permissions": [{ "paths": ["/config/"], "methods": ["GET"] }]
            }]
        }));
        let denial = expect_denial(&remote, &victim(), "POST", "/load");
        assert_eq!(denial.status, StatusCode::FORBIDDEN);
        assert_eq!(denial.message, "not authorized to access this path");

        let denial = expect_denial(&remote, &victim(), "DELETE", "/config/");
        assert_eq!(denial.status, StatusCode::FORBIDDEN);
        assert_eq!(denial.message, "not authorized to use this method");
    }

    #[test]
    fn empty_permissions_grant_everything() {
        let remote = remote(serde_json::json!({
            "access_control": [{ "public_keys": [certificate_base64(CA_A_PEM)] }]
        }));
        assert!(allowed(&remote, &victim(), "DELETE", "/stop"));
        assert!(allowed(&remote, &victim(), "POST", "/load"));
    }

    #[test]
    fn multiple_entries_union_their_permissions() {
        let remote = remote(serde_json::json!({
            "access_control": [
                {
                    "public_keys": [certificate_base64(CA_A_PEM)],
                    "permissions": [{ "paths": ["/config/"] }]
                },
                {
                    "public_keys": [certificate_base64(CA_A_PEM)],
                    "permissions": [{ "methods": ["POST"], "paths": ["/load"] }]
                }
            ]
        }));
        assert!(allowed(&remote, &victim(), "GET", "/config/"));
        assert!(allowed(&remote, &victim(), "POST", "/load"));
        assert!(!allowed(&remote, &victim(), "GET", "/metrics"));
    }

    #[test]
    fn explicit_empty_permission_lists_deny_everything() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "permissions": [{ "paths": [], "methods": [] }]
            }]
        }));
        assert!(!allowed(&remote, &victim(), "GET", "/config/"));
    }

    #[test]
    fn missing_methods_list_allows_every_method() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "public_keys": [certificate_base64(CA_A_PEM)],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        assert!(allowed(&remote, &victim(), "PUT", "/config/"));
        assert!(allowed(&remote, &victim(), "PATCH", "/config/apps"));
    }

    #[test]
    fn empty_access_control_denies_with_401() {
        let remote = remote(serde_json::json!({}));
        let denial = expect_denial(&remote, &victim(), "GET", "/config/");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn absent_remote_configuration_denies_with_401() {
        let denial = decide(None, Some(&victim()), &method("GET"), "/config/")
            .expect_err("no remote configuration");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn unparsable_client_identity_fails_closed_with_401() {
        // A verified handshake whose certificate metadata cannot be parsed must never reach the
        // plaintext origin policy: 401 regardless of the configured access control.
        let remote = remote(serde_json::json!({
            "access_control": [{ "public_keys": [certificate_base64(CA_A_PEM)] }]
        }));
        let denial = decide_client(
            Some(&remote),
            &ClientIdentity::Unparsable,
            &method("GET"),
            "/config/",
        )
        .expect_err("unparsable identity is denied");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
        assert_eq!(denial.message, "client certificate could not be parsed");

        let denial = decide_client(
            None,
            &ClientIdentity::Unparsable,
            &method("GET"),
            "/config/",
        )
        .expect_err("unparsable identity is denied without remote configuration");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);

        // Defensive: an unexpected "no certificate" state on the remote path is denied too.
        let denial = decide_client(
            Some(&remote),
            &ClientIdentity::NotPresented,
            &method("GET"),
            "/config/",
        )
        .expect_err("absent identity is denied on the remote path");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn path_root_and_empty_allow_everything() {
        assert!(admin_path_allowed("/stop", "/"));
        assert!(admin_path_allowed("/stop", ""));
        assert!(admin_path_allowed("/config/apps", "/config/"));
        assert!(!admin_path_allowed("/config", "/config/"));
        assert!(admin_path_allowed("/config/", "/config/"));
        assert!(admin_path_allowed("/config", "/config"));
        assert!(!admin_path_allowed("/config", "/config/"));
        assert!(admin_path_allowed("/config/apps", "/config"));
        assert!(!admin_path_allowed("/configurations", "/config"));
        assert!(admin_path_allowed("//config//apps/", "/config"));
    }
}
