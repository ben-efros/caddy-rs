//! Production IP → ASN/country lookup backed by a MaxMind/DB-IP `.mmdb` file.
//!
//! [`GeoIpProvider`] is the seam `@radar` ASN and country predicates read through
//! ([`crate::radar_matcher`]). The crate ships [`NoopGeoIp`] as the default and
//! [`StaticGeoIp`] for tests; this module adds the provider that actually reads a database, so
//! those predicates can match in production (ADR-0020, DIV-0151).
//!
//! [`NoopGeoIp`]: crate::radar_matcher::NoopGeoIp
//! [`StaticGeoIp`]: crate::radar_matcher::StaticGeoIp
//!
//! # Two databases, not one
//!
//! ASN and country live in **different** `.mmdb` files: `dbip-asn.mmdb` and
//! `dbip-country.mmdb` (likewise MaxMind's `GeoLite2-ASN.mmdb` and `GeoLite2-Country.mmdb`).
//! [`MmdbGeoIp`] therefore holds up to two readers and consults only the ones that are present.
//! A deployment that supplies just the ASN database resolves ASN and reports `country: None`
//! rather than failing: a partially configured lookup is useful, and refusing it would push
//! operators toward the no-database case where *nothing* matches.
//!
//! # Fail open, warn once, never panic
//!
//! `GeoIpProvider::lookup` returns `Option` and is called on the request path, so a database
//! problem must never turn into a 5xx. Two distinct failures are handled differently:
//!
//! * **A missing or unreadable database at startup** is a configuration problem, not a request
//!   problem. [`MmdbGeoIp::open`] returns `Ok(None)` with a warning when the file does not exist,
//!   so the server starts with a [`NoopGeoIp`]-equivalent provider and continues serving. It
//!   returns `Err` only when a file exists but cannot be opened or is not a valid database —
//!   that is a real mistake and silently degrading would hide it.
//! * **A per-request lookup error** (an address outside the database's coverage, a corrupt
//!   record) is logged once per provider and then reported as `None`. The warning is emitted
//!   through [`MmdbGeoIp::set_warn`] rather than `eprintln!` so tests can capture it and the
//!   server can route it through its own logging.
//!
//! # Why not `crates/route`
//!
//! ADR-0020's module table names `crates/route/src/geoip.rs`, but no `route` crate was ever
//! created: the `GeoIpProvider` trait lives in `crates/http` (see `radar_matcher.rs`), and a
//! provider has to be in the same crate as the trait it implements unless the trait is moved.
//! This module is therefore `crates/http/src/geoip.rs`, and the ADR table is corrected alongside
//! this change rather than left pointing at a directory that does not exist.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use maxminddb::Reader;

use crate::radar_matcher::{GeoIpProvider, GeoLocation};

/// Which database product a path refers to. Recorded for diagnostics only; the reader does not
/// depend on it, because both products share the MaxMind DB format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoIpProduct {
    /// DB-IP's free tier (`dbip-asn-lite.mmdb`, `dbip-country-lite.mmdb`). The default, per
    /// ADR-0020's resolution of open question 1: no license key, so no credential to manage.
    DbIp,
    /// MaxMind's `GeoLite2`/`GeoIP2` databases. Opt-in, because MaxMind requires a license key for
    /// downloads even though the format is identical.
    MaxMind,
}

impl GeoIpProduct {
    /// Parse the Caddyfile `geoip <provider> <path>` provider word.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dbip" => Some(Self::DbIp),
            "maxmind" => Some(Self::MaxMind),
            _ => None,
        }
    }

    /// The provider word as written in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DbIp => "dbip",
            Self::MaxMind => "maxmind",
        }
    }
}

impl fmt::Display for GeoIpProduct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lookup counters. Cheap atomics, so the request path never takes a lock.
#[derive(Debug, Default)]
struct Counters {
    lookups: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// A snapshot of [`MmdbGeoIp`]'s counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GeoIpStats {
    /// Total addresses looked up.
    pub lookups: u64,
    /// Lookups that produced an ASN or a country.
    pub hits: u64,
    /// Lookups that produced neither.
    pub misses: u64,
}

/// The two databases a deployment may supply.
#[derive(Debug, Clone, Default)]
pub struct GeoIpPaths {
    /// Database carrying ASN records.
    pub asn: Option<PathBuf>,
    /// Database carrying country records.
    pub country: Option<PathBuf>,
}

impl GeoIpPaths {
    /// Both paths in one directory, named as DB-IP ships them.
    pub fn dbip(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            asn: Some(dir.join("dbip-asn-lite.mmdb")),
            country: Some(dir.join("dbip-country-lite.mmdb")),
        }
    }

    /// Both paths in one directory, named as MaxMind ships them.
    pub fn maxmind(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            asn: Some(dir.join("GeoLite2-ASN.mmdb")),
            country: Some(dir.join("GeoLite2-Country.mmdb")),
        }
    }
}

/// A [`GeoIpProvider`] backed by one or both `.mmdb` databases.
///
/// Construct with [`MmdbGeoIp::open`]; see the module docs for the fail-open policy.
pub struct MmdbGeoIp {
    asn: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
    counters: Counters,
    /// Emitted at most once, on the first per-request lookup failure.
    warn: Arc<dyn Fn(&str) + Send + Sync>,
}

impl fmt::Debug for MmdbGeoIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Reader` is not `Debug` and dumping a database handle would be useless anyway.
        f.debug_struct("MmdbGeoIp")
            .field("asn", &self.asn.is_some())
            .field("country", &self.country.is_some())
            .field("stats", &self.stats())
            .finish()
    }
}

/// Why a configured database could not be used.
#[derive(Debug)]
pub enum GeoIpError {
    /// The file exists but could not be opened or is not a valid MaxMind DB.
    Open { path: PathBuf, message: String },
}

impl fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, message } => write!(
                f,
                "cannot open GeoIP database {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for GeoIpError {}

impl MmdbGeoIp {
    /// Open the databases named by `paths`.
    ///
    /// A path that does not exist is skipped with a warning and yields `Ok(None)` when *no*
    /// database could be opened at all — the caller then installs [`NoopGeoIp`] and the server
    /// keeps serving (ADR-0020: fail open). A path that exists but is unreadable is an `Err`,
    /// because that is a genuine misconfiguration rather than an absent optional file.
    ///
    /// [`NoopGeoIp`]: crate::radar_matcher::NoopGeoIp
    pub fn open(
        paths: &GeoIpPaths,
        warn: impl Fn(&str) + Send + Sync + 'static,
    ) -> Result<Option<Self>, GeoIpError> {
        let warn: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(warn);
        let asn = Self::open_one(paths.asn.as_deref(), "ASN", &warn)?;
        let country = Self::open_one(paths.country.as_deref(), "country", &warn)?;
        if asn.is_none() && country.is_none() {
            warn(
                "geoip: no usable database configured; ASN and country predicates will never match",
            );
            return Ok(None);
        }
        Ok(Some(Self {
            asn,
            country,
            counters: Counters::default(),
            warn,
        }))
    }

    fn open_one(
        path: Option<&Path>,
        kind: &str,
        warn: &Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Option<Reader<Vec<u8>>>, GeoIpError> {
        let Some(path) = path else {
            return Ok(None);
        };
        if !path.exists() {
            // Absent optional database: warn and continue. A typo'd path lands here too, which is
            // why the warning names the full path.
            warn(&format!(
                "geoip: {kind} database {} does not exist; {kind} lookups will report unknown",
                path.display()
            ));
            return Ok(None);
        }
        match Reader::open_readfile(path) {
            Ok(reader) => Ok(Some(reader)),
            Err(error) => Err(GeoIpError::Open {
                path: path.to_path_buf(),
                message: error.to_string(),
            }),
        }
    }

    /// The counters so far.
    pub fn stats(&self) -> GeoIpStats {
        GeoIpStats {
            lookups: self.counters.lookups.load(Ordering::Relaxed),
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
        }
    }

    fn lookup_asn(&self, ip: IpAddr) -> Option<u64> {
        let reader = self.asn.as_ref()?;
        // A lookup failure here means "not in this database", which is not worth a warning:
        // ordinary uncovered addresses take this path constantly.
        // `decode` returns Ok(None) when the address has no record, which is the ordinary
        // "not covered by this database" case.
        let record: maxminddb::geoip2::Asn = reader.lookup(ip).ok()?.decode().ok()??;
        record.autonomous_system_number.map(u64::from)
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.country.as_ref()?;
        let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()?.decode().ok()??;
        record
            .country
            .iso_code
            .map(|code| code.to_ascii_uppercase())
    }
}

impl GeoIpProvider for MmdbGeoIp {
    fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        self.counters.lookups.fetch_add(1, Ordering::Relaxed);
        let asn = self.lookup_asn(ip);
        let country = self.lookup_country(ip);
        if asn.is_none() && country.is_none() {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.counters.hits.fetch_add(1, Ordering::Relaxed);
        Some(GeoLocation { asn, country })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink() -> impl Fn(&str) + Send + Sync + 'static {
        |_message: &str| {}
    }

    #[test]
    fn absent_databases_yield_none_so_the_caller_can_fall_back_to_noop() {
        let paths = GeoIpPaths {
            asn: Some(PathBuf::from("/nonexistent/dbip-asn.mmdb")),
            country: Some(PathBuf::from("/nonexistent/dbip-country.mmdb")),
        };
        let provider = MmdbGeoIp::open(&paths, sink()).unwrap();
        assert!(
            provider.is_none(),
            "no usable database must yield None so the caller installs NoopGeoIp"
        );
    }

    #[test]
    fn an_unreadable_file_is_an_error_not_a_silent_degrade() {
        // A path that EXISTS but is not a MaxMind DB: a real mistake, so it must not be swallowed.
        let dir = std::env::temp_dir().join(format!("geoip-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not-a-db.mmdb");
        std::fs::write(&path, b"this is not a maxmind database").unwrap();

        let paths = GeoIpPaths {
            asn: Some(path.clone()),
            country: None,
        };
        let result = MmdbGeoIp::open(&paths, sink());
        assert!(
            matches!(result, Err(GeoIpError::Open { .. })),
            "an existing but invalid database must be a located error"
        );
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("not-a-db.mmdb"),
            "the error must name the path: {message}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn absent_database_warns_with_the_full_path() {
        // The warning is the operator's only clue that a typo'd path silently disabled lookups.
        use std::sync::Mutex;
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let paths = GeoIpPaths {
            asn: Some(PathBuf::from("/nonexistent/dbip-asn.mmdb")),
            country: None,
        };
        let _ = MmdbGeoIp::open(&paths, move |message: &str| {
            recorder.lock().unwrap().push(message.to_string());
        })
        .unwrap();
        let messages = seen.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|m| m.contains("/nonexistent/dbip-asn.mmdb")),
            "the warning must name the missing path: {messages:?}"
        );
    }

    #[test]
    fn products_parse_and_round_trip() {
        assert_eq!(GeoIpProduct::parse("dbip"), Some(GeoIpProduct::DbIp));
        assert_eq!(GeoIpProduct::parse("maxmind"), Some(GeoIpProduct::MaxMind));
        assert_eq!(GeoIpProduct::parse("DBIP"), None, "case-sensitive");
        assert_eq!(GeoIpProduct::parse("geoip2"), None);
        for product in [GeoIpProduct::DbIp, GeoIpProduct::MaxMind] {
            assert_eq!(GeoIpProduct::parse(product.as_str()), Some(product));
        }
    }

    #[test]
    fn paths_use_the_names_each_product_ships() {
        let dbip = GeoIpPaths::dbip("/data");
        assert_eq!(
            dbip.asn.unwrap().to_str().unwrap(),
            "/data/dbip-asn-lite.mmdb"
        );
        assert_eq!(
            dbip.country.unwrap().to_str().unwrap(),
            "/data/dbip-country-lite.mmdb"
        );
        let maxmind = GeoIpPaths::maxmind("/data");
        assert_eq!(
            maxmind.asn.unwrap().to_str().unwrap(),
            "/data/GeoLite2-ASN.mmdb"
        );
        assert_eq!(
            maxmind.country.unwrap().to_str().unwrap(),
            "/data/GeoLite2-Country.mmdb"
        );
    }
}
