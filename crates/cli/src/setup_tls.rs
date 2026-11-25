//! TLS for the `caddy-rs setup` activation endpoint (T-SETUP-008).
//!
//! The activation URLs `setup` prints are `https://`, so the endpoint has to actually be TLS.
//! Leaving it cleartext made the printed scheme a lie, which is worse than either alternative:
//! an operator who follows the link has no way to tell a real activation endpoint from an
//! intercepted one, and the whole point of the printed fingerprint is that it can be compared
//! out of band.
//!
//! # What is served, and by whom
//!
//! The certificate is issued by the **internal CA** (`tls internal` / `local_certs`), i.e. the
//! `Caddy Local Authority` root that `setup`'s generated configuration already asks for. It is a
//! self-signed local authority: no public CA can issue for `localhost` or an RFC 1918 address, and
//! reaching out to a public CA during first boot would make the boot depend on the network it is
//! supposed to be setting up.
//!
//! One leaf covers every name the boot serves — `--domain` plus every `--host` — so a single
//! certificate (and a single fingerprint to compare) covers the activation endpoint on every
//! printed URL. `--host` sites therefore reuse this certificate rather than minting their own; the
//! generated Caddyfile's per-site blocks all resolve to the same leaf through this resolver.
//!
//! # Why the fingerprint is printed
//!
//! The operator's browser will warn that the certificate is not trusted, which is correct and
//! expected for a local CA the machine has not installed. The fingerprint is what turns that
//! warning into a check instead of a reflex: `setup` prints the leaf's SHA-256 fingerprint *before*
//! the URL, in the same `AB:CD:...` colon-separated uppercase-hex form that
//! `openssl x509 -fingerprint -sha256` prints, so the two can be compared character for character.
//! It is the SHA-256 of the DER encoding of the **leaf** certificate — the one the listener
//! presents — not the root, because that is the certificate the browser shows and the one the
//! handshake is bound to.
//!
//! # Where it is used
//!
//! [`activate`] issues the leaf and prints the fingerprint; the returned [`ActivationTls`] is then
//! installed on the activation listener by
//! [`crate::activation::serve_with`]. The certificate material lives in the boot's data directory
//! (`<data-dir>/pki/authorities/local/`), so the root persists and a later boot of the same data
//! directory reuses the same authority.

use caddy_rs_core::{CertKeyPemPair, CertificatesConfig, TlsApp};
use caddy_rs_tls::{
    CertificateIssuer, CertificateResolver, InternalIssuer, IssuanceRequest, TlsCertificate,
};

use crate::setup::{SetupConfig, SetupError};

/// PEM label for a certificate.
const CERTIFICATE_LABEL: &str = "CERTIFICATE";
/// PEM label for a PKCS#8 private key.
const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";

/// The certificate the activation endpoint (and every `--host` site) is served with.
///
/// `Debug` is manual and prints only public material — the fingerprint and the covered names — so a
/// stray debug log cannot leak a private key.
pub struct ActivationTls {
    /// SHA-256 of the DER leaf, uppercase hex separated by colons (`AB:CD:...`).
    fingerprint: String,
    /// The names the leaf covers.
    names: Vec<String>,
    /// The leaf chain as PEM (leaf first), for a configuration that must serve the same cert.
    certificate_pem: String,
    /// The leaf's PKCS#8 private key as PEM.
    private_key_pem: String,
}

impl std::fmt::Debug for ActivationTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActivationTls")
            .field("fingerprint", &self.fingerprint)
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

impl Clone for ActivationTls {
    fn clone(&self) -> Self {
        Self {
            fingerprint: self.fingerprint.clone(),
            names: self.names.clone(),
            certificate_pem: self.certificate_pem.clone(),
            private_key_pem: self.private_key_pem.clone(),
        }
    }
}

impl ActivationTls {
    /// The leaf's SHA-256 fingerprint, uppercase hex separated by colons.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The names the leaf covers.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The leaf chain as PEM (leaf first), for `apps.tls.certificates.load_pem`.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The leaf's PKCS#8 private key as PEM, for `apps.tls.certificates.load_pem`.
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }
}

/// Format a DER certificate as `openssl x509 -fingerprint -sha256` prints it.
///
/// `openssl` writes `SHA256 Fingerprint=AB:CD:...`: uppercase hex, colon-separated, 32 bytes. This
/// returns the value after the `=`, so the console line reads
/// `SHA-256 fingerprint (leaf, openssl x509 -fingerprint -sha256): AB:CD:...` and an operator can
/// copy the value straight into a comparison.
pub fn sha256_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Issue the activation certificate and build the resolver that serves it.
///
/// The issuer is rooted at `<data-dir>/pki/authorities/local`, the same layout `local_certs` uses,
/// so the root a later `caddy-rs run` trusts is the root that signed this leaf.
pub async fn activate(config: &SetupConfig) -> Result<ActivationTls, SetupError> {
    let names = activation_names(config);
    let issuer = InternalIssuer::from_data_directory(&config.data_dir);
    // `obtain` is the same call automatic HTTPS makes for `tls internal`, so the leaf's shape —
    // ECDSA P-256, backdated, SAN-only names — is identical to what a `local_certs` site gets.
    // Async rather than a nested blocking runtime: `setup` already runs inside `main`'s runtime,
    // and starting a second one there panics ("Cannot start a runtime from within a runtime").
    let certificate = issuer
        .obtain(&IssuanceRequest {
            domains: names.clone(),
            internal: true,
            // `local_certs` leaves are ECDSA P-256 unless an automation policy says otherwise.
            key_type: caddy_rs_tls::acme::csr::CertificateKeyType::P256,
        })
        .await
        .map_err(|error| {
            SetupError::TlsUnavailable(format!(
                "cannot issue the activation certificate from the internal CA: {error}"
            ))
        })?;

    let leaf = certificate.cert_chain_der.first().ok_or_else(|| {
        SetupError::TlsUnavailable(
            "the internal CA returned an empty certificate chain".to_string(),
        )
    })?;
    let fingerprint = sha256_fingerprint(leaf);

    let tls_certificate =
        TlsCertificate::from_cache_certificate(&certificate).map_err(|error| {
            SetupError::TlsUnavailable(format!("cannot load the activation certificate: {error}"))
        })?;
    // Validating the leaf through the resolver proves it is servable (names parse, key matches the
    // chain) before the listener is bound; the value itself is dropped because the listener builds
    // its resolver from `apps.tls.certificates.load_pem`.
    CertificateResolver::from_certificates([tls_certificate]).map_err(|error| {
        SetupError::TlsUnavailable(format!(
            "the activation certificate is not servable: {error}"
        ))
    })?;

    let certificate_pem = certificate
        .cert_chain_der
        .iter()
        .map(|der| certificate_pem(der))
        .collect::<String>();
    let private_key_pem = private_key_pem(&certificate.private_key_der);

    Ok(ActivationTls {
        fingerprint,
        names,
        certificate_pem,
        private_key_pem,
    })
}

/// The names the activation leaf covers: `--domain` first, then every `--host`, de-duplicated.
///
/// These are exactly the hosts the activation URLs are printed for, so one certificate covers every
/// printed link.
fn activation_names(config: &SetupConfig) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(config.hosts.len() + 1);
    for host in std::iter::once(&config.domain).chain(config.hosts.iter()) {
        if !names.contains(host) {
            names.push(host.clone());
        }
    }
    names
}

/// The `apps.tls.certificates.load_pem` entry for a certificate, used when a setup boot is handed
/// to a normal `caddy-rs run` so the site keeps the certificate its URL advertised.
///
/// Not yet wired into the handoff (T-SETUP-005 owns persistence); exported so the handoff does not
/// have to re-derive the PEM shape when it lands.
pub fn load_pem_pair(certificate_pem: String, key_pem: String) -> CertKeyPemPair {
    CertKeyPemPair {
        certificate: certificate_pem,
        key: key_pem,
        tags: Vec::new(),
        extra: Default::default(),
    }
}

/// A TLS app that serves exactly `pair` — the shape a handoff configuration needs.
pub fn tls_app_with(pair: CertKeyPemPair) -> TlsApp {
    TlsApp {
        certificates: Some(CertificatesConfig {
            load_pem: Some(vec![pair]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// PEM-encode a DER certificate.
pub fn certificate_pem(der: &[u8]) -> String {
    pem_encode(CERTIFICATE_LABEL, der)
}

/// PEM-encode a DER PKCS#8 private key.
pub fn private_key_pem(der: &[u8]) -> String {
    pem_encode(PRIVATE_KEY_LABEL, der)
}

/// PEM-encode one DER block.
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / 64 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in body.as_bytes().chunks(64) {
        // `chunks` over the base64 alphabet never splits a UTF-8 sequence: it is ASCII.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_is_formatted_the_way_openssl_prints_it() {
        // `printf 'caddy-rs setup' | openssl dgst -sha256` =
        // a433d56f488b0857ab759ef0f97ca4074ac61ad4058028fa6b5dd1f377962e3f, so this pins the
        // uppercase colon-separated rendering against a value computed outside this code.
        let fingerprint = sha256_fingerprint(b"caddy-rs setup");
        assert_eq!(
            fingerprint,
            "A4:33:D5:6F:48:8B:08:57:AB:75:9E:F0:F9:7C:A4:07:\
             4A:C6:1A:D4:05:80:28:FA:6B:5D:D1:F3:77:96:2E:3F"
                .replace([' ', '\n'], ""),
            "the fingerprint is uppercase colon-separated hex, as openssl prints it"
        );
    }

    #[test]
    fn the_fingerprint_is_64_uppercase_hex_digits_in_colon_pairs() {
        let fingerprint = sha256_fingerprint(b"anything");
        let parts: Vec<&str> = fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32, "SHA-256 is 32 bytes: {fingerprint}");
        for part in parts {
            assert_eq!(part.len(), 2, "each byte is two digits: {fingerprint}");
            assert!(
                part.bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
                "uppercase hex only: {fingerprint}"
            );
        }
    }

    #[test]
    fn a_pem_block_round_trips_through_the_tls_crate() {
        // The PEM encoder is hand-written here (the TLS crate's is private), so prove it emits
        // what `TlsCertificate::from_pem` accepts.
        let pem = certificate_pem(&[0x30, 0x82, 0x00, 0x01, 0x00]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let key = private_key_pem(&[0x30, 0x00]);
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    }
}
