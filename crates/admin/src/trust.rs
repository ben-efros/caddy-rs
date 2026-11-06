//! CA root certificate trust-store planning and installation (T-ADMIN-033).
//!
//! Caddy's PKI app installs each generated root certificate into the platform trust store, plus
//! Mozilla/Firefox NSS databases and Java keystores, through `smallstep/truststore`
//! (`modules/caddypki/ca.go` `installRoot`, `cmd/caddypki/command.go` `caddy trust`). caddy-rs has
//! no dependency on that Go library, so this module reproduces the *observable* installation
//! targets with the tools available on the host:
//!
//! * **platform store** — Linux: copy the root into
//!   `<prefix>/usr/local/share/ca-certificates/caddy-rs-<ca-id>.crt` and run
//!   `update-ca-certificates`; macOS: `security add-trusted-cert`; Windows and other operating
//!   systems are explicitly unsupported with a located limitation (no silent success).
//! * **NSS/Firefox** — every discovered NSS database (`$HOME/.pki/nssdb` and Firefox profiles
//!   containing `cert9.db`, plus legacy `cert8.db` databases) is updated with
//!   `certutil -d sql:<db> -A -t C,, -n <alias> -i <root.crt>`. Requires `certutil` (nss-tools).
//! * **Java** — the JVM `cacerts` keystore (`$JAVA_HOME/lib/security/cacerts`, the `java` binary's
//!   home, or conventional system locations) is updated with
//!   `keytool -importcert -noprompt -trustcacerts -alias <alias> -file <root.crt>`. Requires
//!   `keytool`.
//!
//! Every target is planned up-front with its concrete command lines (used by `--dry-run` and
//! manual fallback) and a [`TrustStatus`]. A target whose tool or store is missing is **not**
//! silently skipped: [`TrustPlan::execute`] returns it in [`TrustReport::skipped`] with the exact
//! missing tool / store and the documented limitation, and the CLI prints a loud warning naming
//! it. Executing a plan is idempotent: NSS and Java targets first run a cheap "already installed"
//! probe (`certutil -L` / `keytool -list`) and report [`TrustStatus::AlreadyInstalled`] without
//! re-importing.
//!
//! The environment is injectable ([`TrustEnvironment`]) so tests can exercise tool discovery,
//! installation commands and idempotency with temporary directories and stub executables instead
//! of touching the real OS store. `platform_prefix` exists only for tests/containers: the CLI
//! always uses `/`.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Alias/nickname prefix used when importing the root into NSS databases and Java keystores.
///
/// Caddy's `smallstep/truststore` derives its nickname from the certificate subject; caddy-rs uses
/// a stable `caddy-rs-<ca-id>` alias so an idempotency check is independent of localized subject
/// formatting. This is a documented difference in DIV-0073 (the trust decision is the same).
pub const TRUST_ALIAS_PREFIX: &str = "caddy-rs";

/// Java's well-known default keystore password (`changeit`), used by `keytool` invocations.
pub const JAVA_KEYSTORE_PASSWORD: &str = "changeit";
/// Environment override for the platform-store path prefix (default `/`).
///
/// The CLI always uses `/` in normal operation; this override exists for tests and containers that
/// must not modify the real system store (for example `CADDY_RS_TRUST_PREFIX=/tmp/rootfs`). It only
/// affects the platform target, never NSS/Java discovery.
pub const PLATFORM_PREFIX_ENV: &str = "CADDY_RS_TRUST_PREFIX";

/// Operating system whose trust-store conventions are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPlatform {
    /// Linux: `/usr/local/share/ca-certificates` + `update-ca-certificates`.
    Linux,
    /// macOS: `security add-trusted-cert` on the system keychain.
    MacOs,
    /// Windows: no automatic installation in this build (documented limitation).
    Windows,
    /// Any other target: no automatic installation.
    Unsupported,
}

impl TrustPlatform {
    /// The platform of the current build.
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self::Unsupported
        }
    }

    /// Human-readable platform label for messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
            Self::Windows => "Windows",
            Self::Unsupported => "this operating system",
        }
    }
}

/// A trust store that a root certificate can be installed into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStoreKind {
    /// The platform/OS trust store.
    Platform,
    /// One NSS database (Firefox/Chrome), with the database type prefix (`sql`/`dbm`).
    Nss {
        /// Database directory.
        database: PathBuf,
        /// `certutil -d` prefix, `sql` or `dbm`.
        format: &'static str,
    },
    /// One Java `cacerts` keystore.
    Java {
        /// Keystore file.
        keystore: PathBuf,
    },
}

impl TrustStoreKind {
    /// Label used in the report and dry-run output.
    pub fn label(&self) -> String {
        match self {
            Self::Platform => "platform trust store".to_string(),
            Self::Nss { database, .. } => format!("NSS/Firefox database `{}`", database.display()),
            Self::Java { keystore } => format!("Java keystore `{}`", keystore.display()),
        }
    }

    /// Whether failure to install into this store must fail the whole installation.
    ///
    /// The platform store is the store Caddy treats as primary; NSS/Java are best-effort additions
    /// in `smallstep/truststore` and are reported loudly but do not hide an otherwise successful
    /// platform install.
    pub fn required(&self) -> bool {
        matches!(self, Self::Platform)
    }
}

/// Outcome planned for one target before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStatus {
    /// The target can be installed when execution is requested.
    Ready,
    /// The target cannot be installed because a required tool is missing.
    MissingTool {
        /// Tool name (`certutil`, `keytool`, `update-ca-certificates`, `security`).
        tool: &'static str,
        /// Documented limitation shown to the user.
        limitation: String,
    },
    /// The target itself is unavailable on this host (for example no NSS database or keystore).
    Unavailable {
        /// Documented limitation shown to the user.
        limitation: String,
    },
    /// Automatic installation is not supported for this target/platform.
    Unsupported {
        /// Documented limitation shown to the user.
        limitation: String,
    },
}

impl TrustStatus {
    /// Whether execution can install this target.
    pub fn is_ready(&self) -> bool {
        matches!(self, TrustStatus::Ready)
    }

    /// The loud documented limitation, when the target cannot be installed.
    pub fn limitation(&self) -> Option<&str> {
        match self {
            TrustStatus::Ready => None,
            TrustStatus::MissingTool { limitation, .. }
            | TrustStatus::Unavailable { limitation }
            | TrustStatus::Unsupported { limitation } => Some(limitation),
        }
    }
}

/// One concrete installation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStep {
    /// Copy the root certificate from `from` to `to` (parent directories are created).
    Copy {
        /// Source root certificate.
        from: PathBuf,
        /// Destination path.
        to: PathBuf,
    },
    /// Run a program with arguments.
    Run {
        /// Resolved executable path.
        program: PathBuf,
        /// Arguments.
        args: Vec<String>,
    },
}

impl TrustStep {
    /// Human-readable command line for dry-run/manual instructions.
    pub fn command_line(&self) -> String {
        match self {
            TrustStep::Copy { from, to } => {
                format!("install -m 0644 '{}' '{}'", from.display(), to.display())
            }
            TrustStep::Run { program, args } => {
                let args = args
                    .iter()
                    .map(|arg| {
                        if arg.contains(' ') || arg.contains('\'') {
                            format!("'{arg}'")
                        } else {
                            arg.clone()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                if args.is_empty() {
                    program.display().to_string()
                } else {
                    format!("{} {args}", program.display())
                }
            }
        }
    }
}

/// One planned trust-store target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustTarget {
    /// Which store this target updates.
    pub kind: TrustStoreKind,
    /// Planned status (ready or the documented reason it is skipped).
    pub status: TrustStatus,
    /// Steps executed when ready (the first may be a probe for idempotency).
    pub probe: Option<TrustStep>,
    /// Commands that install the certificate.
    pub steps: Vec<TrustStep>,
    /// Human-readable commands for `--dry-run`.
    pub commands: Vec<String>,
}

impl TrustTarget {
    fn limitation(&self) -> Option<String> {
        self.status
            .limitation()
            .map(|limitation| format!("{} not updated: {limitation}", self.kind.label()))
    }
}

/// A host environment for trust-target discovery, injectable for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEnvironment {
    /// Target operating system.
    pub platform: TrustPlatform,
    /// Value of `$HOME` (used for NSS/Firefox discovery).
    pub home: Option<PathBuf>,
    /// Value of `$PATH`, split into directories.
    pub path: Vec<PathBuf>,
    /// Root prefix for platform-store paths (the CLI uses `/`).
    pub platform_prefix: PathBuf,
    /// Value of `$JAVA_HOME`, when set.
    pub java_home: Option<PathBuf>,
    /// Explicit Java keystore override (tests, or a future `--java-keystore` option).
    pub java_keystores: Vec<PathBuf>,
}

impl TrustEnvironment {
    /// Discover the current process environment.
    pub fn detect() -> Self {
        let path = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        let platform_prefix = std::env::var_os(PLATFORM_PREFIX_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self {
            platform: TrustPlatform::current(),
            home: std::env::var_os("HOME").map(PathBuf::from),
            path,
            platform_prefix,
            java_home: std::env::var_os("JAVA_HOME").map(PathBuf::from),
            java_keystores: Vec::new(),
        }
    }

    /// Test-friendly constructor with explicit directories.
    pub fn new(platform: TrustPlatform, home: Option<PathBuf>, path: Vec<PathBuf>) -> Self {
        Self {
            platform,
            home,
            path,
            platform_prefix: PathBuf::from("/"),
            java_home: None,
            java_keystores: Vec::new(),
        }
    }

    /// Use a non-`/` platform-store root (tests/containers only; the CLI always uses `/`).
    pub fn with_platform_prefix(mut self, prefix: impl Into<PathBuf>) -> Self {
        self.platform_prefix = prefix.into();
        self
    }

    /// Set the Java home used to locate `lib/security/cacerts`.
    pub fn with_java_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.java_home = Some(home.into());
        self
    }

    /// Add an explicit Java keystore path.
    pub fn with_java_keystore(mut self, keystore: impl Into<PathBuf>) -> Self {
        self.java_keystores.push(keystore.into());
        self
    }

    fn find_program(&self, name: &str) -> Option<PathBuf> {
        for directory in &self.path {
            let candidate = directory.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
            #[cfg(target_os = "windows")]
            {
                let candidate = directory.join(format!("{name}.exe"));
                if is_executable(&candidate) {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

/// A complete trust installation plan for one CA root certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPlan {
    /// CA identifier.
    pub ca_id: String,
    /// NSS/Java alias/nickname.
    pub alias: String,
    /// Root certificate to install.
    pub root_path: PathBuf,
    /// Targets in installation order (platform first, then NSS, then Java).
    pub targets: Vec<TrustTarget>,
}

impl TrustPlan {
    /// Plan installation of `root_path` for CA `ca_id` on `environment`.
    pub fn detect(
        ca_id: impl Into<String>,
        root_path: impl Into<PathBuf>,
        environment: &TrustEnvironment,
    ) -> Self {
        let ca_id = ca_id.into();
        let root_path = root_path.into();
        let alias = format!("{TRUST_ALIAS_PREFIX}-{ca_id}");
        let mut targets = vec![platform_target(
            environment.platform,
            &ca_id,
            &root_path,
            &environment.platform_prefix,
            environment,
        )];
        for (database, format) in discover_nss_databases(environment.home.as_deref()) {
            targets.push(nss_target(
                &database,
                format,
                &alias,
                &root_path,
                environment,
            ));
        }
        for keystore in discover_java_keystores(environment) {
            targets.push(java_target(&keystore, &alias, &root_path, environment));
        }
        Self {
            ca_id,
            alias,
            root_path,
            targets,
        }
    }
}

/// Result of executing a plan.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TrustReport {
    /// Targets that were installed by this run.
    pub installed: Vec<TrustStoreKind>,
    /// Targets that were already trusted before this run.
    pub already_installed: Vec<TrustStoreKind>,
    /// Targets that were skipped, with the loud documented limitation.
    pub skipped: Vec<(TrustStoreKind, String)>,
    /// Targets whose installation failed (store/tool/permission errors).
    pub failures: Vec<(TrustStoreKind, String)>,
}

impl TrustReport {
    /// Whether at least one target is trusted (installed now or previously).
    pub fn any_trusted(&self) -> bool {
        !self.installed.is_empty() || !self.already_installed.is_empty()
    }
}

/// Trust installation failure (execution-level).
#[derive(Debug)]
pub struct TrustError {
    path: Option<PathBuf>,
    message: String,
}

impl TrustError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            path: None,
            message: message.into(),
        }
    }

    fn io(path: &Path, error: io::Error) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            message: error.to_string(),
        }
    }

    /// Path involved in the failure, when any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(formatter, "{}: {}", path.display(), self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

impl std::error::Error for TrustError {}

impl TrustPlan {
    /// Execute every ready target.
    ///
    /// Missing tools/stores and unsupported platforms are reported in
    /// [`TrustReport::skipped`] with their documented limitation instead of being silently
    /// discarded. Probe commands implement idempotency. Required-target failures are returned as an
    /// error; optional-target failures are collected in [`TrustReport::failures`].
    pub fn execute(&self) -> Result<TrustReport, TrustError> {
        let mut report = TrustReport::default();
        for target in &self.targets {
            if let Some(limitation) = target.limitation() {
                report.skipped.push((target.kind.clone(), limitation));
                continue;
            }
            match self.execute_target(target) {
                Ok(TargetOutcome::Installed) => report.installed.push(target.kind.clone()),
                Ok(TargetOutcome::AlreadyInstalled) => {
                    report.already_installed.push(target.kind.clone())
                }
                Err(error) => {
                    let message = format!("{} not updated: {error}", target.kind.label());
                    if target.kind.required() {
                        return Err(TrustError::new(message));
                    }
                    report.failures.push((target.kind.clone(), message));
                }
            }
        }
        Ok(report)
    }

    fn execute_target(&self, target: &TrustTarget) -> Result<TargetOutcome, TrustError> {
        if let Some(probe) = &target.probe {
            if run_step(probe).is_ok() {
                return Ok(TargetOutcome::AlreadyInstalled);
            }
        }
        for step in &target.steps {
            run_step(step)?;
        }
        Ok(TargetOutcome::Installed)
    }
}

enum TargetOutcome {
    Installed,
    AlreadyInstalled,
}

fn run_step(step: &TrustStep) -> Result<(), TrustError> {
    match step {
        TrustStep::Copy { from, to } => {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).map_err(|error| TrustError::io(parent, error))?;
            }
            std::fs::copy(from, to).map_err(|error| TrustError::io(to, error))?;
            Ok(())
        }
        TrustStep::Run { program, args } => {
            let output = std::process::Command::new(program)
                .args(args)
                .output()
                .map_err(|error| TrustError::io(program, error))?;
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                Err(TrustError::new(format!(
                    "{} failed with {}: {}{}",
                    program.display(),
                    output.status,
                    stdout.trim(),
                    stderr.trim()
                )))
            }
        }
    }
}

fn platform_target(
    platform: TrustPlatform,
    ca_id: &str,
    root_path: &Path,
    prefix: &Path,
    environment: &TrustEnvironment,
) -> TrustTarget {
    let platform_store = TrustStoreKind::Platform;
    match platform {
        TrustPlatform::Linux => {
            let destination = prefix
                .join("usr/local/share/ca-certificates")
                .join(format!("caddy-rs-{ca_id}.crt"));
            let Some(update) = environment.find_program("update-ca-certificates") else {
                return TrustTarget {
                    kind: platform_store,
                    status: TrustStatus::MissingTool {
                        tool: "update-ca-certificates",
                        limitation: "the Linux system trust store was not updated because \
                                      `update-ca-certificates` was not found on PATH (install the \
                                      `ca-certificates` package); the root certificate is not \
                                      trusted by system clients"
                            .to_string(),
                    },
                    probe: None,
                    steps: Vec::new(),
                    commands: vec![
                        format!(
                            "install -m 0644 '{}' '{}'",
                            root_path.display(),
                            destination.display()
                        ),
                        "update-ca-certificates".to_string(),
                    ],
                };
            };
            let steps = vec![
                TrustStep::Copy {
                    from: root_path.to_path_buf(),
                    to: destination.clone(),
                },
                TrustStep::Run {
                    program: update,
                    args: Vec::new(),
                },
            ];
            TrustTarget {
                kind: platform_store,
                status: TrustStatus::Ready,
                probe: None,
                commands: steps.iter().map(TrustStep::command_line).collect(),
                steps,
            }
        }
        TrustPlatform::MacOs => {
            let Some(security) = environment.find_program("security") else {
                return TrustTarget {
                    kind: platform_store,
                    status: TrustStatus::MissingTool {
                        tool: "security",
                        limitation: "the macOS system keychain was not updated because the \
                                      `security` tool was not found on PATH; the root certificate \
                                      is not trusted by system clients"
                            .to_string(),
                    },
                    probe: None,
                    steps: Vec::new(),
                    commands: vec![format!(
                        "sudo security add-trusted-cert -d -r trustRoot -k \
                         /Library/Keychains/System.keychain '{}'",
                        root_path.display()
                    )],
                };
            };
            let steps = vec![TrustStep::Run {
                program: security,
                args: vec![
                    "add-trusted-cert".to_string(),
                    "-d".to_string(),
                    "-r".to_string(),
                    "trustRoot".to_string(),
                    "-k".to_string(),
                    "/Library/Keychains/System.keychain".to_string(),
                    root_path.display().to_string(),
                ],
            }];
            TrustTarget {
                kind: platform_store,
                status: TrustStatus::Ready,
                probe: None,
                commands: steps.iter().map(TrustStep::command_line).collect(),
                steps,
            }
        }
        TrustPlatform::Windows => TrustTarget {
            kind: platform_store,
            status: TrustStatus::Unsupported {
                limitation: "automatic trust-store installation on Windows is not implemented; \
                             run `certutil -addstore -user Root <root.crt>` manually (this build \
                             never modifies the Windows certificate store silently)"
                    .to_string(),
            },
            probe: None,
            steps: Vec::new(),
            commands: vec![format!(
                "certutil -addstore -user Root \"{}\"",
                root_path.display()
            )],
        },
        TrustPlatform::Unsupported => TrustTarget {
            kind: platform_store,
            status: TrustStatus::Unsupported {
                limitation: format!(
                    "automatic trust-store installation is not implemented for {}; install the \
                     root PEM manually with the platform's certificate tool",
                    platform.label()
                ),
            },
            probe: None,
            steps: Vec::new(),
            commands: Vec::new(),
        },
    }
}

fn nss_target(
    database: &Path,
    format: &'static str,
    alias: &str,
    root_path: &Path,
    environment: &TrustEnvironment,
) -> TrustTarget {
    let kind = TrustStoreKind::Nss {
        database: database.to_path_buf(),
        format,
    };
    let Some(certutil) = environment.find_program("certutil") else {
        return TrustTarget {
            kind,
            status: TrustStatus::MissingTool {
                tool: "certutil",
                limitation: format!(
                    "the NSS/Firefox database `{}` was not updated because `certutil` was not \
                     found on PATH (install the `nss-tools`/`libnss3-tools` package); Firefox and \
                     Chrome will not trust the CA",
                    database.display()
                ),
            },
            probe: None,
            steps: Vec::new(),
            commands: vec![format!(
                "certutil -d {format}:{} -A -t 'C,,' -n '{alias}' -i '{}'",
                database.display(),
                root_path.display()
            )],
        };
    };
    let probe = TrustStep::Run {
        program: certutil.clone(),
        args: vec![
            "-d".to_string(),
            format!("{format}:{}", database.display()),
            "-L".to_string(),
            "-n".to_string(),
            alias.to_string(),
        ],
    };
    let steps = vec![TrustStep::Run {
        program: certutil,
        args: vec![
            "-d".to_string(),
            format!("{format}:{}", database.display()),
            "-A".to_string(),
            "-t".to_string(),
            "C,,".to_string(),
            "-n".to_string(),
            alias.to_string(),
            "-i".to_string(),
            root_path.display().to_string(),
        ],
    }];
    TrustTarget {
        kind,
        status: TrustStatus::Ready,
        probe: Some(probe),
        commands: steps.iter().map(TrustStep::command_line).collect(),
        steps,
    }
}

fn java_target(
    keystore: &Path,
    alias: &str,
    root_path: &Path,
    environment: &TrustEnvironment,
) -> TrustTarget {
    let kind = TrustStoreKind::Java {
        keystore: keystore.to_path_buf(),
    };
    let Some(keytool) = environment.find_program("keytool") else {
        return TrustTarget {
            kind,
            status: TrustStatus::MissingTool {
                tool: "keytool",
                limitation: format!(
                    "the Java keystore `{}` was not updated because `keytool` was not found on \
                     PATH (install a JDK/JRE); Java applications will not trust the CA",
                    keystore.display()
                ),
            },
            probe: None,
            steps: Vec::new(),
            commands: vec![format!(
                "keytool -importcert -noprompt -trustcacerts -alias '{alias}' -file '{}' \
                 -keystore '{}' -storepass {JAVA_KEYSTORE_PASSWORD}",
                root_path.display(),
                keystore.display()
            )],
        };
    };
    let probe = TrustStep::Run {
        program: keytool.clone(),
        args: vec![
            "-list".to_string(),
            "-keystore".to_string(),
            keystore.display().to_string(),
            "-storepass".to_string(),
            JAVA_KEYSTORE_PASSWORD.to_string(),
            "-alias".to_string(),
            alias.to_string(),
        ],
    };
    let steps = vec![TrustStep::Run {
        program: keytool,
        args: vec![
            "-importcert".to_string(),
            "-noprompt".to_string(),
            "-trustcacerts".to_string(),
            "-alias".to_string(),
            alias.to_string(),
            "-file".to_string(),
            root_path.display().to_string(),
            "-keystore".to_string(),
            keystore.display().to_string(),
            "-storepass".to_string(),
            JAVA_KEYSTORE_PASSWORD.to_string(),
        ],
    }];
    TrustTarget {
        kind,
        status: TrustStatus::Ready,
        probe: Some(probe),
        commands: steps.iter().map(TrustStep::command_line).collect(),
        steps,
    }
}

/// Discover NSS databases under `home`: the per-user `~/.pki/nssdb` store (Chrome/system NSS) and
/// Firefox profiles containing `cert9.db` (SQL) or `cert8.db` (legacy DBM).
pub fn discover_nss_databases(home: Option<&Path>) -> Vec<(PathBuf, &'static str)> {
    let Some(home) = home else {
        return Vec::new();
    };
    let mut databases: Vec<(PathBuf, &'static str)> = Vec::new();
    let global = home.join(".pki/nssdb");
    if global.is_dir() {
        if global.join("cert9.db").is_file() {
            databases.push((global.clone(), "sql"));
        } else if global.join("cert8.db").is_file() {
            databases.push((global, "dbm"));
        }
    }
    let firefox = home.join(".mozilla/firefox");
    if let Ok(entries) = std::fs::read_dir(&firefox) {
        let mut profiles: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        profiles.sort();
        for profile in profiles {
            if profile.join("cert9.db").is_file() {
                databases.push((profile, "sql"));
            } else if profile.join("cert8.db").is_file() {
                databases.push((profile, "dbm"));
            }
        }
    }
    databases
}

/// Discover Java `cacerts` keystores: explicit overrides, `$JAVA_HOME`, the `java` executable's
/// home, then conventional system locations.
pub fn discover_java_keystores(environment: &TrustEnvironment) -> Vec<PathBuf> {
    let mut keystores = environment.java_keystores.clone();
    if let Some(java_home) = &environment.java_home {
        keystores.push(java_home.join("lib/security/cacerts"));
    }
    if let Some(java) = environment.find_program("java") {
        // <jdk>/bin/java -> <jdk>/lib/security/cacerts
        if let Some(bin) = java.parent() {
            if let Some(home) = bin.parent() {
                keystores.push(home.join("lib/security/cacerts"));
            }
        }
    }
    keystores.push(PathBuf::from("/etc/ssl/certs/java/cacerts"));
    keystores.push(PathBuf::from(
        "/usr/lib/jvm/default-java/lib/security/cacerts",
    ));
    let mut seen = std::collections::BTreeSet::new();
    keystores
        .into_iter()
        .filter(|keystore| keystore.is_file())
        .filter(|keystore| seen.insert(keystore.clone()))
        .collect()
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "caddy-rs-trust-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn write_executable(path: &Path, script: &str) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(script.as_bytes()).unwrap();
        drop(file);
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn root_certificate(directory: &Path) -> PathBuf {
        let path = directory.join("root.crt");
        std::fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        path
    }

    #[test]
    fn linux_platform_target_installs_with_update_ca_certificates() {
        let directory = temp_dir("linux");
        let root = root_certificate(&directory);
        let bin = directory.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_executable(&bin.join("update-ca-certificates"), "#!/bin/sh\nexit 0\n");
        let environment = TrustEnvironment::new(TrustPlatform::Linux, None, vec![bin])
            .with_platform_prefix(&directory);
        let plan = TrustPlan::detect("local", &root, &environment);
        assert_eq!(plan.targets.len(), 1);
        let target = &plan.targets[0];
        assert!(target.status.is_ready());
        let report = plan.execute().unwrap();
        assert_eq!(report.installed, vec![TrustStoreKind::Platform]);
        let installed = directory.join("usr/local/share/ca-certificates/caddy-rs-local.crt");
        assert!(installed.is_file(), "{}", installed.display());
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            std::fs::read(&root).unwrap()
        );
    }

    #[test]
    fn missing_platform_tool_is_a_loud_limitation_not_silent_success() {
        let directory = temp_dir("missing-platform-tool");
        let root = root_certificate(&directory);
        let empty_bin = directory.join("empty-bin");
        std::fs::create_dir_all(&empty_bin).unwrap();
        let environment = TrustEnvironment::new(TrustPlatform::Linux, None, vec![empty_bin])
            .with_platform_prefix(&directory);
        let plan = TrustPlan::detect("local", &root, &environment);
        let limitation = plan.targets[0].status.limitation().unwrap();
        assert!(
            limitation.contains("update-ca-certificates"),
            "{limitation}"
        );
        let report = plan.execute().unwrap();
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].1.contains("update-ca-certificates"));
        assert!(!report.any_trusted());
    }

    #[test]
    fn nss_and_java_targets_are_discovered_and_installed_with_stub_tools() {
        let directory = temp_dir("nss-java");
        let root = root_certificate(&directory);
        // NSS databases: global Chrome NSS DB and one Firefox profile.
        let global_db = directory.join("home/.pki/nssdb");
        std::fs::create_dir_all(&global_db).unwrap();
        std::fs::write(global_db.join("cert9.db"), b"").unwrap();
        let firefox_profile = directory.join("home/.mozilla/firefox/abc.default-release");
        std::fs::create_dir_all(&firefox_profile).unwrap();
        std::fs::write(firefox_profile.join("cert9.db"), b"").unwrap();
        // Java keystore.
        let java_home = directory.join("jdk");
        std::fs::create_dir_all(java_home.join("lib/security")).unwrap();
        let keystore = java_home.join("lib/security/cacerts");
        std::fs::write(&keystore, b"fake-keystore").unwrap();

        let bin = directory.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let calls = directory.join("calls.log");
        let script = format!(
            "#!/bin/sh\necho \"$0 $@\" >> '{}'\ncase \" $* \" in\n  *\" -L \"*) exit 1 ;;\n  *\" -list \"*) exit 1 ;;\nesac\nexit 0\n",
            calls.display()
        );
        write_executable(&bin.join("certutil"), &script);
        write_executable(&bin.join("keytool"), &script);
        write_executable(&bin.join("update-ca-certificates"), "#!/bin/sh\nexit 0\n");

        let environment = TrustEnvironment::new(
            TrustPlatform::Linux,
            Some(directory.join("home")),
            vec![bin],
        )
        .with_platform_prefix(&directory)
        .with_java_home(java_home);
        let plan = TrustPlan::detect("local", &root, &environment);
        let kinds: Vec<String> = plan
            .targets
            .iter()
            .map(|target| target.kind.label())
            .collect();
        assert_eq!(plan.targets.len(), 4, "{kinds:?}"); // platform + 2 NSS + Java
        assert!(plan.targets.iter().all(|target| target.status.is_ready()));
        let report = plan.execute().unwrap();
        assert_eq!(report.installed.len(), 4, "{report:?}");
        let log = std::fs::read_to_string(&calls).unwrap();
        assert!(log.contains("certutil -d sql:"), "{log}");
        assert!(log.contains("-A"), "{log}");
        assert!(
            log.contains("keytool") || log.contains("keytool -importcert"),
            "{log}"
        );
        assert!(log.contains("-importcert"), "{log}");
    }

    #[test]
    fn second_execution_is_idempotent_via_probe_commands() {
        let directory = temp_dir("idempotent");
        let root = root_certificate(&directory);
        let database = directory.join("home/.pki/nssdb");
        std::fs::create_dir_all(&database).unwrap();
        std::fs::write(database.join("cert9.db"), b"").unwrap();
        let bin = directory.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let marker = directory.join("installed.marker");
        let certutil = format!(
            "#!/bin/sh\ncase \" $* \" in\n  *\" -L \"*) test -f '{marker}' && exit 0 || exit 1 ;;\n  *\" -A \"*) touch '{marker}'; exit 0 ;;\nesac\nexit 0\n",
            marker = marker.display()
        );
        write_executable(&bin.join("certutil"), &certutil);
        write_executable(&bin.join("update-ca-certificates"), "#!/bin/sh\nexit 0\n");
        let environment = TrustEnvironment::new(
            TrustPlatform::Linux,
            Some(directory.join("home")),
            vec![bin],
        )
        .with_platform_prefix(&directory);
        let plan = TrustPlan::detect("local", &root, &environment);
        let first = plan.execute().unwrap();
        assert!(first
            .installed
            .iter()
            .any(|kind| matches!(kind, TrustStoreKind::Nss { .. })));
        let second = plan.execute().unwrap();
        assert!(
            second
                .already_installed
                .iter()
                .any(|kind| matches!(kind, TrustStoreKind::Nss { .. })),
            "{second:?}"
        );
    }

    #[test]
    fn missing_certutil_and_keytool_are_reported_loudly_with_the_tool_name() {
        let directory = temp_dir("missing-optional-tools");
        let root = root_certificate(&directory);
        let database = directory.join("home/.pki/nssdb");
        std::fs::create_dir_all(&database).unwrap();
        std::fs::write(database.join("cert9.db"), b"").unwrap();
        let java_home = directory.join("jdk");
        std::fs::create_dir_all(java_home.join("lib/security")).unwrap();
        std::fs::write(java_home.join("lib/security/cacerts"), b"fake").unwrap();
        let bin = directory.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_executable(&bin.join("update-ca-certificates"), "#!/bin/sh\nexit 0\n");
        let environment = TrustEnvironment::new(
            TrustPlatform::Linux,
            Some(directory.join("home")),
            vec![bin],
        )
        .with_platform_prefix(&directory)
        .with_java_home(java_home);
        let plan = TrustPlan::detect("local", &root, &environment);
        let limitations: Vec<String> = plan
            .targets
            .iter()
            .filter_map(|target| target.status.limitation().map(str::to_string))
            .collect();
        assert!(
            limitations
                .iter()
                .any(|limitation| limitation.contains("certutil")),
            "{limitations:?}"
        );
        assert!(
            limitations
                .iter()
                .any(|limitation| limitation.contains("keytool")),
            "{limitations:?}"
        );
        let report = plan.execute().unwrap();
        assert!(report.installed.contains(&TrustStoreKind::Platform));
        assert_eq!(report.skipped.len(), 2, "{report:?}");
    }

    #[test]
    fn windows_and_unsupported_platforms_are_loudly_unsupported() {
        for platform in [TrustPlatform::Windows, TrustPlatform::Unsupported] {
            let directory = temp_dir("unsupported");
            let root = root_certificate(&directory);
            let environment = TrustEnvironment::new(platform, None, Vec::new());
            let plan = TrustPlan::detect("local", &root, &environment);
            let limitation = plan.targets[0].status.limitation().unwrap();
            assert!(!limitation.is_empty(), "{platform:?}");
            let report = plan.execute().unwrap();
            assert_eq!(report.skipped.len(), 1);
            assert!(!report.any_trusted());
        }
    }
}
