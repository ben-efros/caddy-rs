//! Application-layer access control for the mutual-TLS admin endpoint
//! (`admin.remote.access_control`).
//!
//! Port of Caddy v2.11.9 `RemoteAdmin.enforceAccessControls` and `adminPathAllowed`
//! (`external/caddy/admin.go:678-758`). The TLS listener has already verified the client
//! certificate chain against the pool built from every `public_keys` entry; this module decides
//! whether the verified identity is authorized for the request path and method, and reports the
//! same 401/403 outcomes and messages upstream uses.
//!
//! Deviations (documented in the task report):
//! - Upstream scans `r.TLS.VerifiedChains` (which includes the trust anchor). rustls presents the
//!   peer chain without the root, so a configured certificate also matches the client leaf it
//!   directly issued (leaf issuer distinguished name equals the configured certificate's
//!   subject). The chain was verified against that same pool, so this cannot admit a client that
//!   the pool did not anchor.
//! - `subjects`/`serials` are caddy-rs extensions: upstream selects identities by public key
//!   only.

use caddy_rs_core::{AdminAccess, AdminPermissions, AdminRemote};
use http::{Method, StatusCode};

/// The authenticated client identity of a request on the secure admin listener.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminClientIdentity {
    /// DER-encoded certificates presented by the client, leaf first.
    pub certificates: Vec<Vec<u8>>,
    /// Subject distinguished name of the leaf certificate (Go `x509.Name.String()` form).
    pub subject: String,
    /// Issuer distinguished name of the leaf certificate.
    pub issuer: String,
    /// Serial number of the leaf certificate in decimal.
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
fn access_matches_identity(access: &AdminAccess, identity: &AdminClientIdentity) -> bool {
    if access
        .public_keys
        .iter()
        .any(|key| public_key_matches(key, identity))
    {
        return true;
    }
    if access
        .subjects
        .iter()
        .any(|subject| subject.trim() == identity.subject.trim())
    {
        return true;
    }
    access
        .serials
        .iter()
        .any(|serial| serial.trim() == identity.serial)
}

/// Whether one configured base64 DER certificate matches a presented certificate.
///
/// Matches when it is one of the presented certificates (DER equality), or when it issued the
/// presented leaf (issuer/subject equality; rustls does not expose the trust anchor itself).
fn public_key_matches(configured: &str, identity: &AdminClientIdentity) -> bool {
    use base64::Engine as _;

    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
        return false;
    };
    if identity
        .certificates
        .iter()
        .any(|presented| *presented == der)
    {
        return true;
    }
    let Ok(info) = caddy_rs_tls::ClientCertificateInfo::parse(&der, false) else {
        return false;
    };
    !info.subject.is_empty()
        && (info.subject == identity.subject || info.subject == identity.issuer)
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

    fn remote(json: serde_json::Value) -> AdminRemote {
        serde_json::from_value(json).expect("valid admin.remote configuration")
    }

    fn identity() -> AdminClientIdentity {
        AdminClientIdentity {
            certificates: vec![vec![1, 2, 3]],
            subject: "CN=client,O=ops".to_string(),
            issuer: "CN=test-ca".to_string(),
            serial: "42".to_string(),
        }
    }

    fn method(value: &str) -> Method {
        value.parse().expect("valid method")
    }

    fn allowed(remote: &AdminRemote, verb: &str, path: &str) -> bool {
        decide(Some(remote), Some(&identity()), &method(verb), path).is_ok()
    }

    #[test]
    fn allows_matching_subject_and_path_and_method() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "subjects": ["CN=client,O=ops"],
                "permissions": [{ "paths": ["/config/"], "methods": ["GET"] }]
            }]
        }));
        assert!(allowed(&remote, "GET", "/config/"));
        assert!(allowed(&remote, "GET", "/config/"));
        // A subpath at a segment boundary is allowed.
        assert!(allowed(&remote, "GET", "/config/apps/http"));
        // A path that merely shares a character prefix is not.
        assert!(!allowed(&remote, "GET", "/configuration"));
        assert!(!allowed(&remote, "GET", "/config"));
    }

    #[test]
    fn allows_matching_serial_selector() {
        let remote = remote(serde_json::json!({
            "access_control": [{ "serials": ["42"], "permissions": [{ "paths": ["/id/"] }] }]
        }));
        assert!(allowed(&remote, "POST", "/id/anything"));
        let other = AdminClientIdentity {
            serial: "43".to_string(),
            ..identity()
        };
        let denial = decide(Some(&remote), Some(&other), &method("GET"), "/id/x")
            .expect_err("unknown serial");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn denies_wrong_identity_with_401() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "subjects": ["CN=other"],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        let denial = decide(Some(&remote), Some(&identity()), &method("GET"), "/config/")
            .expect_err("wrong identity");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
        assert_eq!(denial.message, "client identity not authorized");
    }

    #[test]
    fn denies_disallowed_method_with_403() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "subjects": ["CN=client,O=ops"],
                "permissions": [{ "paths": ["/config/"], "methods": ["GET"] }]
            }]
        }));
        let denial = decide(Some(&remote), Some(&identity()), &method("POST"), "/load")
            .expect_err("path denied");
        assert_eq!(denial.status, StatusCode::FORBIDDEN);
        assert_eq!(denial.message, "not authorized to access this path");

        let denial = decide(
            Some(&remote),
            Some(&identity()),
            &method("DELETE"),
            "/config/",
        )
        .expect_err("method denied");
        assert_eq!(denial.status, StatusCode::FORBIDDEN);
        assert_eq!(denial.message, "not authorized to use this method");
    }

    #[test]
    fn empty_permissions_grant_everything() {
        let remote = remote(serde_json::json!({
            "access_control": [{ "subjects": ["CN=client,O=ops"] }]
        }));
        assert!(allowed(&remote, "DELETE", "/stop"));
        assert!(allowed(&remote, "POST", "/load"));
    }

    #[test]
    fn multiple_entries_union_their_permissions() {
        let remote = remote(serde_json::json!({
            "access_control": [
                { "subjects": ["CN=client,O=ops"], "permissions": [{ "paths": ["/config/"] }] },
                { "subjects": ["CN=client,O=ops"], "permissions": [{ "methods": ["POST"], "paths": ["/load"] }] }
            ]
        }));
        assert!(allowed(&remote, "GET", "/config/"));
        assert!(allowed(&remote, "POST", "/load"));
        assert!(!allowed(&remote, "GET", "/metrics"));
    }

    #[test]
    fn explicit_empty_permission_lists_deny_everything() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "subjects": ["CN=client,O=ops"],
                "permissions": [{ "paths": [], "methods": [] }]
            }]
        }));
        assert!(!allowed(&remote, "GET", "/config/"));
    }

    #[test]
    fn missing_methods_list_allows_every_method() {
        let remote = remote(serde_json::json!({
            "access_control": [{
                "subjects": ["CN=client,O=ops"],
                "permissions": [{ "paths": ["/config/"] }]
            }]
        }));
        assert!(allowed(&remote, "PUT", "/config/"));
        assert!(allowed(&remote, "PATCH", "/config/apps"));
    }

    #[test]
    fn empty_access_control_denies_with_401() {
        let remote = remote(serde_json::json!({}));
        let denial = decide(Some(&remote), Some(&identity()), &method("GET"), "/config/")
            .expect_err("no access control");
        assert_eq!(denial.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn absent_remote_configuration_denies_with_401() {
        let denial = decide(None, Some(&identity()), &method("GET"), "/config/")
            .expect_err("no remote configuration");
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
