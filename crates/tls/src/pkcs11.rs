//! PKCS#11 token runtime: token-held TLS signing keys.
//!
//! This module owns the whole token side of `apps.tls.certificates.pkcs11[...]`:
//!
//! * opening a PKCS#11 module and selecting/logging into one token ([`open_token`]),
//! * a fixed set of OS threads, one per read-only session, that serialise `C_Sign` on
//!   the token ([`TokenPool`]),
//! * a bounded per-token sign queue with two independent budgets (`queue_wait` before
//!   dispatch, `sign_timeout` after dispatch) and a process-global quarantine latch
//!   ([`quarantine`], [`is_quarantined`]),
//! * private-key selection and verification, including SPKI construction from the
//!   token's public components ([`TokenPool::signing_key`]),
//! * the `rustls::sign::SigningKey` / `rustls::sign::Signer` bridge, including the
//!   `r || s` to DER `ECDSA-Sig-Value` conversion required by `CKM_ECDSA`.
//!
//! Design: `docs/design/T-TLS-096-pkcs11-implementation-brief.md` §§3-5 and
//! `docs/adr/0009-external-key-providers.md`. The private key never leaves the token;
//! only public components and signatures enter process memory.
//!
//! The PIN is held in a [`cryptoki::types::AuthPin`] (`secrecy::SecretString`); it is
//! never formatted, logged, or copied into an error value. Every error carries the
//! module path, token label, and — where one exists — the failed `CKR_*` code.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::acme::csr::CsrSigner;

// ---------------------------------------------------------------------------
// Budget, selector, errors
// ---------------------------------------------------------------------------

/// Resource budget for one token. Construct directly from configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11Budget {
    /// Maximum number of concurrent read-only sessions (= OS threads) per token.
    pub max_sessions: usize,
    /// Handshakes allowed to be inside a token-backed signature at once.
    pub max_inflight_handshakes: usize,
    /// How long a handshake waits for a permit (zero means "no wait").
    pub handshake_wait: Duration,
    /// Bound on queued (not in-flight) sign jobs per token.
    pub queue_depth: usize,
    /// Budget from enqueue until dispatch; expiry fails without quarantine.
    pub queue_wait: Duration,
    /// Budget from dispatch until the signature reply; expiry quarantines.
    pub sign_timeout: Duration,
    /// Default handshake budget used by [`TokenPool::acquire_handshake_with_budget`].
    pub handshake_timeout: Duration,
}

impl Default for Pkcs11Budget {
    fn default() -> Self {
        Pkcs11Budget {
            // ADR-0009 published defaults; `Pkcs11CertConfig::budget()` resolves the same
            // values from configuration, and T-TLS-097 measured them (docs/operations/PKCS11.md).
            max_sessions: 1,
            max_inflight_handshakes: 1,
            handshake_wait: Duration::from_secs(1),
            queue_depth: 64,
            queue_wait: Duration::from_secs(1),
            sign_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl Pkcs11Budget {
    fn normalized(mut self) -> Self {
        self.max_sessions = self.max_sessions.max(1);
        self.max_inflight_handshakes = self.max_inflight_handshakes.max(1);
        self.queue_depth = self.queue_depth.max(1);
        self
    }
}

/// How a token private key is selected: by `CKA_LABEL`, by `CKA_ID`, or both.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct KeySelector {
    /// `CKA_LABEL`, compared after trimming standard blank padding.
    pub label: Option<String>,
    /// `CKA_ID`, compared byte-for-byte.
    pub id: Option<Vec<u8>>,
}

impl KeySelector {
    /// The selector as it may appear in a located error (never contains secret data).
    fn describe(&self) -> String {
        match (&self.label, &self.id) {
            (Some(label), Some(id)) => format!("label={label:?} id={}", hex_bytes(id)),
            (Some(label), None) => format!("label={label:?}"),
            (None, Some(id)) => format!("id={}", hex_bytes(id)),
            (None, None) => "label=<none> id=<none>".to_string(),
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// A located PKCS#11 failure. Every variant names the token (and the module path for
/// module-level failures); none can carry PIN material.
#[derive(Debug, thiserror::Error)]
pub enum Pkcs11Error {
    /// The module path is not an absolute path to an existing regular file.
    #[error("PKCS#11 module path {path}: {detail}")]
    ModulePath { path: PathBuf, detail: String },
    /// Loading the shared library failed or panicked (not a PKCS#11 module).
    #[error("PKCS#11 module {path} could not be loaded: {detail}")]
    ModuleLoad { path: PathBuf, detail: String },
    /// `C_Initialize` failed.
    #[error("PKCS#11 module {path} failed C_Initialize: {rv}")]
    ModuleInitialize { path: PathBuf, rv: String },
    /// Token selection failed (no slot, no matching label, ambiguous).
    #[error("PKCS#11 token {token}: {detail}")]
    TokenSelect { token: String, detail: String },
    /// A cryptoki call failed; `rv` is the `CKR_*` text.
    #[error("PKCS#11 token {token}: {operation} failed: {rv}")]
    Cryptoki {
        token: String,
        operation: &'static str,
        rv: String,
    },
    /// The selector did not match exactly one private key.
    #[error("PKCS#11 token {token}: key selector ({selector}) matched {found} private keys, expected exactly 1")]
    KeySelection {
        token: String,
        selector: String,
        found: usize,
    },
    /// A private key failed the fail-closed attribute/algorithm checks.
    #[error("PKCS#11 token {token}: key ({selector}) rejected: {detail}")]
    KeyRejected {
        token: String,
        selector: String,
        detail: String,
    },
    /// No candidate signature mechanism is supported by the token.
    #[error("PKCS#11 token {token}: none of the required mechanisms ({mechanisms}) are supported")]
    MechanismUnsupported { token: String, mechanisms: String },
    /// A token signature had the wrong length for its algorithm.
    #[error("PKCS#11 token {token}: signature format: got {got} bytes, want {want}")]
    SignatureFormat {
        token: String,
        got: usize,
        want: usize,
    },
    /// A queued job was not dispatched within `queue_wait` (no quarantine).
    #[error("PKCS#11 token {token}: sign queue not dispatched within {waited_ms}ms (queue_wait); request dropped")]
    QueueWait { token: String, waited_ms: u128 },
    /// A dispatched job produced no reply within `sign_timeout` (token quarantined).
    #[error("PKCS#11 token {token}: dispatched sign produced no reply within {timeout_ms}ms; token quarantined")]
    SignTimeout { token: String, timeout_ms: u128 },
    /// The token is quarantined; every further sign fails fast.
    #[error("PKCS#11 token {token}: quarantined, refusing new sign requests")]
    Quarantined { token: String },
    /// The owning session thread is gone.
    #[error("PKCS#11 token {token}: session thread is gone")]
    SessionGone { token: String },
    /// The handshake concurrency budget could not be acquired.
    #[error("PKCS#11 token {token}: handshake budget: {detail}")]
    HandshakeBudget { token: String, detail: String },
    /// Anything that has no better classification (still located).
    #[error("PKCS#11 token {token}: {detail}")]
    Internal { token: String, detail: String },
}

impl Pkcs11Error {
    fn cryptoki(token: &str, operation: &'static str, error: CryptokiError) -> Self {
        Pkcs11Error::Cryptoki {
            token: token.to_string(),
            operation,
            rv: error.to_string(),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// DER helpers (hand-rolled: no DER crate is needed for three fixed shapes)
// ---------------------------------------------------------------------------

fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8);
    out.push(tag);
    der_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// DER `INTEGER` for a non-negative big-endian value: strip redundant leading zeros,
/// re-pad one `0x00` when the high bit of the first kept byte is set.
fn der_positive_integer(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let kept = &bytes[first.min(bytes.len())..];
    let mut body = Vec::with_capacity(kept.len() + 1);
    if kept.is_empty() || kept[0] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(kept);
    der_tlv(0x02, &body)
}

const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0); // zero unused bits
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

/// Build the RFC 5280 SPKI of an RSA public key from `CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`.
pub(crate) fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut rsa_key = Vec::with_capacity(modulus.len() + exponent.len() + 8);
    rsa_key.extend_from_slice(&der_positive_integer(modulus));
    rsa_key.extend_from_slice(&der_positive_integer(exponent));
    let rsa_key = der_tlv(0x30, &rsa_key);

    let mut algorithm = Vec::with_capacity(OID_RSA_ENCRYPTION.len() + 2);
    algorithm.extend_from_slice(OID_RSA_ENCRYPTION);
    algorithm.extend_from_slice(&[0x05, 0x00]); // NULL parameters
    let algorithm = der_tlv(0x30, &algorithm);

    let mut body = Vec::with_capacity(algorithm.len() + rsa_key.len() + 8);
    body.extend_from_slice(&algorithm);
    body.extend_from_slice(&bit_string(&rsa_key));
    der_tlv(0x30, &body)
}

/// Build the RFC 5280 SPKI of a P-256 public key from the uncompressed point.
pub(crate) fn ec_p256_spki(point: &[u8]) -> Vec<u8> {
    let mut algorithm = Vec::with_capacity(OID_EC_PUBLIC_KEY.len() + OID_PRIME256V1.len());
    algorithm.extend_from_slice(OID_EC_PUBLIC_KEY);
    algorithm.extend_from_slice(OID_PRIME256V1);
    let algorithm = der_tlv(0x30, &algorithm);

    let mut body = Vec::with_capacity(algorithm.len() + point.len() + 8);
    body.extend_from_slice(&algorithm);
    body.extend_from_slice(&bit_string(point));
    der_tlv(0x30, &body)
}

/// `CKA_EC_POINT` is a DER `OCTET STRING` on conforming tokens; some return the bare
/// point. Accept both and return the 65-byte uncompressed P-256 point.
fn unwrap_ec_point(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() == 65 && raw[0] == 0x04 {
        return Some(raw);
    }
    if raw.len() == 67 && raw[0] == 0x04 && raw[1] == 65 && raw[2] == 0x04 {
        return Some(&raw[2..]); // short-form OCTET STRING
    }
    if raw.len() == 68 && raw[0] == 0x04 && raw[1] == 0x81 && raw[2] == 65 && raw[3] == 0x04 {
        return Some(&raw[3..]); // long-form OCTET STRING
    }
    None
}

/// Convert a raw `r || s` PKCS#11 ECDSA signature into DER `ECDSA-Sig-Value`.
///
/// `field_len` is the curve field size in bytes (32 for P-256, the only supported
/// curve). Lengths are short-form: the result is always < 128 bytes.
pub(crate) fn raw_ecdsa_to_der(
    token: &str,
    raw: &[u8],
    field_len: usize,
) -> Result<Vec<u8>, Pkcs11Error> {
    if field_len == 0 || raw.len() != 2 * field_len {
        return Err(Pkcs11Error::SignatureFormat {
            token: token.to_string(),
            got: raw.len(),
            want: 2 * field_len,
        });
    }
    let (r, s) = raw.split_at(field_len);
    let mut body = Vec::with_capacity(2 * field_len + 8);
    body.extend_from_slice(&der_positive_integer(r));
    body.extend_from_slice(&der_positive_integer(s));
    debug_assert!(body.len() < 0x80, "ECDSA-Sig-Value stays in short-form DER");
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    der_length(body.len(), &mut out);
    out.extend_from_slice(&body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Mechanism plans
// ---------------------------------------------------------------------------

/// The signature schemes this runtime can drive on a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlanKind {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaP256Sha256,
}

impl PlanKind {
    fn scheme(self) -> SignatureScheme {
        match self {
            PlanKind::RsaPkcs1Sha256 => SignatureScheme::RSA_PKCS1_SHA256,
            PlanKind::RsaPkcs1Sha384 => SignatureScheme::RSA_PKCS1_SHA384,
            PlanKind::RsaPkcs1Sha512 => SignatureScheme::RSA_PKCS1_SHA512,
            PlanKind::RsaPssSha256 => SignatureScheme::RSA_PSS_SHA256,
            PlanKind::RsaPssSha384 => SignatureScheme::RSA_PSS_SHA384,
            PlanKind::RsaPssSha512 => SignatureScheme::RSA_PSS_SHA512,
            PlanKind::EcdsaP256Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        }
    }

    fn mechanism_type(self) -> MechanismType {
        match self {
            PlanKind::RsaPkcs1Sha256 => MechanismType::SHA256_RSA_PKCS,
            PlanKind::RsaPkcs1Sha384 => MechanismType::SHA384_RSA_PKCS,
            PlanKind::RsaPkcs1Sha512 => MechanismType::SHA512_RSA_PKCS,
            PlanKind::RsaPssSha256 | PlanKind::RsaPssSha384 | PlanKind::RsaPssSha512 => {
                MechanismType::RSA_PKCS_PSS
            }
            PlanKind::EcdsaP256Sha256 => MechanismType::ECDSA,
        }
    }

    fn mechanism_label(self) -> &'static str {
        match self {
            PlanKind::RsaPkcs1Sha256 => "CKM_SHA256_RSA_PKCS",
            PlanKind::RsaPkcs1Sha384 => "CKM_SHA384_RSA_PKCS",
            PlanKind::RsaPkcs1Sha512 => "CKM_SHA512_RSA_PKCS",
            PlanKind::RsaPssSha256 => "CKM_RSA_PKCS_PSS(SHA256)",
            PlanKind::RsaPssSha384 => "CKM_RSA_PKCS_PSS(SHA384)",
            PlanKind::RsaPssSha512 => "CKM_RSA_PKCS_PSS(SHA512)",
            PlanKind::EcdsaP256Sha256 => "CKM_ECDSA",
        }
    }

    fn is_ecdsa(self) -> bool {
        matches!(self, PlanKind::EcdsaP256Sha256)
    }

    /// Candidate plans for an RSA key, most-preferred first.
    fn rsa_candidates() -> &'static [PlanKind] {
        &[
            PlanKind::RsaPssSha256,
            PlanKind::RsaPssSha384,
            PlanKind::RsaPssSha512,
            PlanKind::RsaPkcs1Sha256,
            PlanKind::RsaPkcs1Sha384,
            PlanKind::RsaPkcs1Sha512,
        ]
    }

    fn ec_candidates() -> &'static [PlanKind] {
        &[PlanKind::EcdsaP256Sha256]
    }

    /// The token input for this plan: raw message for combined RSA PKCS#1 mechanisms,
    /// the pre-computed digest for RSA-PSS and ECDSA.
    fn payload(self, message: &[u8]) -> Vec<u8> {
        match self {
            PlanKind::RsaPkcs1Sha256 | PlanKind::RsaPkcs1Sha384 | PlanKind::RsaPkcs1Sha512 => {
                message.to_vec()
            }
            PlanKind::RsaPssSha256 | PlanKind::EcdsaP256Sha256 => Sha256::digest(message).to_vec(),
            PlanKind::RsaPssSha384 => Sha384::digest(message).to_vec(),
            PlanKind::RsaPssSha512 => Sha512::digest(message).to_vec(),
        }
    }

    fn mechanism(self) -> Mechanism<'static> {
        match self {
            PlanKind::RsaPkcs1Sha256 => Mechanism::Sha256RsaPkcs,
            PlanKind::RsaPkcs1Sha384 => Mechanism::Sha384RsaPkcs,
            PlanKind::RsaPkcs1Sha512 => Mechanism::Sha512RsaPkcs,
            PlanKind::RsaPssSha256 => Mechanism::RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32.into(),
            }),
            PlanKind::RsaPssSha384 => Mechanism::RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA384,
                mgf: PkcsMgfType::MGF1_SHA384,
                s_len: 48.into(),
            }),
            PlanKind::RsaPssSha512 => Mechanism::RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA512,
                mgf: PkcsMgfType::MGF1_SHA512,
                s_len: 64.into(),
            }),
            PlanKind::EcdsaP256Sha256 => Mechanism::Ecdsa,
        }
    }

    /// Pick the first offered scheme that this token key can actually drive.
    fn choose(plans: &[PlanKind], offered: &[SignatureScheme]) -> Option<PlanKind> {
        plans
            .iter()
            .copied()
            .find(|plan| offered.contains(&plan.scheme()))
    }
}

// ---------------------------------------------------------------------------
// Quarantine (process-global latch plus per-token latch)
// ---------------------------------------------------------------------------

static GLOBAL_QUARANTINE: AtomicBool = AtomicBool::new(false);

/// Latch the process-global quarantine. Any post-dispatch sign timeout calls this;
/// see [`is_quarantined`]. Idempotent.
pub fn quarantine() {
    GLOBAL_QUARANTINE.store(true, Ordering::SeqCst);
}

/// Whether a post-dispatch sign timeout has been observed in this process.
pub fn is_quarantined() -> bool {
    GLOBAL_QUARANTINE.load(Ordering::SeqCst)
}

/// Test/teardown hook: clearing the latch never happens in production, but tests that
/// deliberately provoke a timeout need a deterministic reset.
#[doc(hidden)]
pub fn clear_quarantine_for_test() {
    GLOBAL_QUARANTINE.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Sign queue
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JobState {
    Queued,
    Dispatched,
    Completed,
    Abandoned,
}

struct Job {
    plan: PlanKind,
    selector: Arc<KeySelector>,
    payload: Vec<u8>,
    state: Mutex<JobState>,
    dispatched: SyncSender<()>,
    reply: SyncSender<Result<Vec<u8>, Pkcs11Error>>,
}

impl Job {
    fn transition(&self, from: JobState, to: JobState) -> bool {
        let mut state = lock(&self.state);
        if *state == from {
            *state = to;
            true
        } else {
            false
        }
    }
}

struct QueueState {
    jobs: VecDeque<Arc<Job>>,
    closed: bool,
}

/// Bounded FIFO of sign jobs for one token, plus the token-local quarantine latch.
struct SignQueue {
    token: String,
    depth: usize,
    state: Mutex<QueueState>,
    work: Condvar,
    quarantined: AtomicBool,
    /// High-water mark of the queue depth, for the T-TLS-097 saturation evidence.
    max_observed: AtomicUsize,
}

impl SignQueue {
    fn new(token: String, depth: usize) -> Arc<SignQueue> {
        Arc::new(SignQueue {
            token,
            depth,
            state: Mutex::new(QueueState {
                jobs: VecDeque::new(),
                closed: false,
            }),
            work: Condvar::new(),
            quarantined: AtomicBool::new(false),
            max_observed: AtomicUsize::new(0),
        })
    }

    fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::SeqCst)
    }

    fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }

    fn set_quarantined(&self) {
        self.quarantined.store(true, Ordering::SeqCst);
        quarantine();
        self.close();
    }

    fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        state.jobs.clear();
        drop(state);
        self.work.notify_all();
    }

    /// Admit `job` unless the token is closed/quarantined or the deque stays full past
    /// `deadline`. A timeout here is a `QueueWait` failure and never quarantines.
    fn enqueue(&self, job: Arc<Job>, deadline: Instant) -> Result<(), Pkcs11Error> {
        let mut state = lock(&self.state);
        loop {
            if self.is_quarantined() {
                return Err(Pkcs11Error::Quarantined {
                    token: self.token.clone(),
                });
            }
            if state.closed {
                return Err(Pkcs11Error::SessionGone {
                    token: self.token.clone(),
                });
            }
            if state.jobs.len() < self.depth {
                state.jobs.push_back(job);
                let depth = state.jobs.len();
                drop(state);
                self.max_observed.fetch_max(depth, Ordering::Relaxed);
                self.work.notify_all();
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Pkcs11Error::QueueWait {
                    token: self.token.clone(),
                    waited_ms: 0,
                });
            }
            let (guard, timed_out) = self
                .work
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
            if timed_out.timed_out() && state.jobs.len() >= self.depth {
                return Err(Pkcs11Error::QueueWait {
                    token: self.token.clone(),
                    waited_ms: 0,
                });
            }
        }
    }

    /// Consumer side: block up to `grace` for a job, mark it `Dispatched`, return it.
    /// Abandoned jobs are discarded. `None` means the queue is closed.
    fn pop_dispatched(&self, grace: Duration) -> Option<Arc<Job>> {
        let mut state = lock(&self.state);
        loop {
            if state.closed {
                return None;
            }
            while let Some(job) = state.jobs.pop_front() {
                if job.transition(JobState::Queued, JobState::Dispatched) {
                    // Wake producers waiting for a free slot: popping frees one.
                    drop(state);
                    self.work.notify_all();
                    return Some(job);
                }
                // Abandoned in `queue_wait`: never reach the token.
            }
            if state.closed {
                return None;
            }
            let (guard, _) = self
                .work
                .wait_timeout(state, grace)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
        }
    }
}

/// Producer side of one sign: enqueue, wait for the dispatch mark under `queue_wait`,
/// then wait for the reply under `sign_timeout`. Only a post-dispatch timeout
/// quarantines; a `queue_wait` expiry drops the job without quarantine.
fn submit(
    queue: &SignQueue,
    plan: PlanKind,
    selector: &KeySelector,
    payload: Vec<u8>,
    budget: &Pkcs11Budget,
    token: &str,
) -> Result<Vec<u8>, Pkcs11Error> {
    if queue.is_quarantined() {
        return Err(Pkcs11Error::Quarantined {
            token: token.to_string(),
        });
    }
    let (dispatched_tx, dispatched_rx) = sync_channel(1);
    let (reply_tx, reply_rx) = sync_channel(1);
    let job = Arc::new(Job {
        plan,
        selector: Arc::new(selector.clone()),
        payload,
        state: Mutex::new(JobState::Queued),
        dispatched: dispatched_tx,
        reply: reply_tx,
    });
    let started = Instant::now();
    queue.enqueue(Arc::clone(&job), started + budget.queue_wait)?;

    let dispatched = match dispatched_rx.recv_timeout(budget.queue_wait) {
        Ok(()) => true,
        Err(RecvTimeoutError::Timeout) => {
            // Race with the consumer: winning the CAS (transition returns true) means the job
            // never reaches the token, so this is a pure queue wait. Losing it means the token
            // already dispatched the job and the reply must be awaited under `sign_timeout`.
            !job.transition(JobState::Queued, JobState::Abandoned)
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err(Pkcs11Error::SessionGone {
                token: token.to_string(),
            })
        }
    };
    if !dispatched {
        return Err(Pkcs11Error::QueueWait {
            token: token.to_string(),
            waited_ms: budget.queue_wait.as_millis(),
        });
    }

    match reply_rx.recv_timeout(budget.sign_timeout) {
        Ok(Ok(signature)) => Ok(signature),
        Ok(Err(error)) => Err(error),
        Err(RecvTimeoutError::Timeout) => {
            queue.set_quarantined();
            Err(Pkcs11Error::SignTimeout {
                token: token.to_string(),
                timeout_ms: budget.sign_timeout.as_millis(),
            })
        }
        Err(RecvTimeoutError::Disconnected) => {
            queue.set_quarantined();
            Err(Pkcs11Error::SessionGone {
                token: token.to_string(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake budget
// ---------------------------------------------------------------------------

struct HandshakeLimiter {
    token: String,
    max: usize,
    in_flight: Mutex<usize>,
    released: Condvar,
}

impl HandshakeLimiter {
    fn new(token: String, max: usize) -> Arc<HandshakeLimiter> {
        Arc::new(HandshakeLimiter {
            token,
            max,
            in_flight: Mutex::new(0),
            released: Condvar::new(),
        })
    }

    fn acquire(self: &Arc<Self>, wait: Duration) -> Result<HandshakePermit, Pkcs11Error> {
        let deadline = Instant::now() + wait;
        let mut in_flight = lock(&self.in_flight);
        loop {
            if *in_flight < self.max {
                *in_flight += 1;
                return Ok(HandshakePermit {
                    limiter: Arc::clone(self),
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Pkcs11Error::HandshakeBudget {
                    token: self.token.clone(),
                    detail: format!(
                        "{} in-flight handshakes, none released within {}ms",
                        *in_flight,
                        wait.as_millis()
                    ),
                });
            }
            let (guard, _) = self
                .released
                .wait_timeout(in_flight, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            in_flight = guard;
        }
    }
}

/// Owned handshake permit; releasing it (on drop) admits the next handshake.
pub struct HandshakePermit {
    limiter: Arc<HandshakeLimiter>,
}

impl HandshakePermit {
    /// The token this permit belongs to.
    pub fn token(&self) -> &str {
        &self.limiter.token
    }
}

impl fmt::Debug for HandshakePermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakePermit")
            .field("token", &self.limiter.token)
            .finish()
    }
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        let mut in_flight = lock(&self.limiter.in_flight);
        *in_flight = in_flight.saturating_sub(1);
        drop(in_flight);
        self.limiter.released.notify_one();
    }
}

// ---------------------------------------------------------------------------
// Token session runtime
// ---------------------------------------------------------------------------

/// Immutable state shared by every session thread of one token.
struct SessionRuntime {
    token: String,
    pkcs11: Pkcs11,
    slot: Slot,
    pin: AuthPin,
    queue: Arc<SignQueue>,
}

fn find_private_keys(
    session: &Session,
    selector: &KeySelector,
    token: &str,
) -> Result<Vec<ObjectHandle>, Pkcs11Error> {
    let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
    if let Some(id) = &selector.id {
        template.push(Attribute::Id(id.clone()));
    }
    let candidates = session
        .find_objects(&template)
        .map_err(|error| Pkcs11Error::cryptoki(token, "C_FindObjects", error))?;

    // Labels are blank-padded to 32 bytes by tokens; compare trimmed.
    if let Some(wanted) = &selector.label {
        let wanted = wanted.trim();
        let mut matched = Vec::new();
        for handle in candidates {
            let label = match session.get_attributes(handle, &[AttributeType::Label]) {
                Ok(attributes) => attributes.iter().find_map(|attribute| match attribute {
                    Attribute::Label(bytes) => Some(
                        String::from_utf8_lossy(bytes)
                            .trim_end_matches([' ', '\0'])
                            .to_string(),
                    ),
                    _ => None,
                }),
                Err(error) => {
                    return Err(Pkcs11Error::cryptoki(token, "C_GetAttributeValue", error))
                }
            };
            if label.as_deref() == Some(wanted) {
                matched.push(handle);
            }
        }
        Ok(matched)
    } else {
        Ok(candidates)
    }
}

fn find_single_private_key(
    session: &Session,
    selector: &KeySelector,
    token: &str,
) -> Result<ObjectHandle, Pkcs11Error> {
    let mut keys = find_private_keys(session, selector, token)?;
    if keys.len() == 1 {
        return Ok(keys.remove(0));
    }
    Err(Pkcs11Error::KeySelection {
        token: token.to_string(),
        selector: selector.describe(),
        found: keys.len(),
    })
}

fn attribute_bytes(
    session: &Session,
    handle: ObjectHandle,
    attribute_type: AttributeType,
    token: &str,
    selector: &KeySelector,
) -> Result<Vec<u8>, Pkcs11Error> {
    let attributes = session
        .get_attributes(handle, &[attribute_type])
        .map_err(|error| Pkcs11Error::cryptoki(token, "C_GetAttributeValue", error))?;
    for attribute in attributes {
        match attribute {
            Attribute::Label(bytes)
            | Attribute::Id(bytes)
            | Attribute::Modulus(bytes)
            | Attribute::PublicExponent(bytes)
            | Attribute::EcParams(bytes)
            | Attribute::EcPoint(bytes) => return Ok(bytes),
            Attribute::Sensitive(value)
            | Attribute::Extractable(value)
            | Attribute::NeverExtractable(value)
            | Attribute::AlwaysAuthenticate(value) => return Ok(vec![u8::from(value)]),
            _ => {}
        }
    }
    Err(Pkcs11Error::KeyRejected {
        token: token.to_string(),
        selector: selector.describe(),
        detail: format!("required attribute {attribute_type} is absent"),
    })
}

fn attribute_bool(
    session: &Session,
    handle: ObjectHandle,
    attribute_type: AttributeType,
    token: &str,
    selector: &KeySelector,
) -> Result<bool, Pkcs11Error> {
    let bytes = attribute_bytes(session, handle, attribute_type, token, selector)?;
    match bytes.as_slice() {
        [value] => Ok(*value != 0),
        _ => Err(Pkcs11Error::KeyRejected {
            token: token.to_string(),
            selector: selector.describe(),
            detail: format!("attribute {attribute_type} is not a single byte"),
        }),
    }
}

fn attribute_key_type(
    session: &Session,
    handle: ObjectHandle,
    token: &str,
    selector: &KeySelector,
) -> Result<KeyType, Pkcs11Error> {
    let attributes = session
        .get_attributes(handle, &[AttributeType::KeyType])
        .map_err(|error| Pkcs11Error::cryptoki(token, "C_GetAttributeValue", error))?;
    for attribute in attributes {
        if let Attribute::KeyType(key_type) = attribute {
            return Ok(key_type);
        }
    }
    Err(Pkcs11Error::KeyRejected {
        token: token.to_string(),
        selector: selector.describe(),
        detail: "required attribute CKA_KEY_TYPE is absent".to_string(),
    })
}

fn optional_attribute_bool(
    session: &Session,
    handle: ObjectHandle,
    attribute_type: AttributeType,
) -> Option<bool> {
    let attributes = session.get_attributes(handle, &[attribute_type]).ok()?;
    attributes.iter().find_map(|attribute| match attribute {
        Attribute::NeverExtractable(value) | Attribute::AlwaysAuthenticate(value) => Some(*value),
        _ => None,
    })
}

fn optional_attribute_bytes(
    session: &Session,
    handle: ObjectHandle,
    attribute_type: AttributeType,
) -> Option<Vec<u8>> {
    let attributes = session.get_attributes(handle, &[attribute_type]).ok()?;
    attributes.iter().find_map(|attribute| match attribute {
        Attribute::Modulus(bytes)
        | Attribute::PublicExponent(bytes)
        | Attribute::EcParams(bytes)
        | Attribute::EcPoint(bytes) => Some(bytes.clone()),
        _ => None,
    })
}

/// Find the public-key object that belongs to the selected private key and read its
/// `CKA_EC_POINT`.
///
/// PKCS#11 v2.40 defines `CKA_EC_POINT` on public keys, and SoftHSM2 (like most tokens that
/// import a private key without a matching public object) does not expose it on the private key.
/// The point is still needed to build the SPKI rustls compares against the certificate, so read
/// it from the public object with the same `CKA_ID`/`CKA_LABEL`. Returning `None` lets the caller
/// fail with an actionable error instead of a bare "attribute absent".
fn find_public_key_ec_point(
    session: &Session,
    selector: &KeySelector,
    token: &str,
) -> Result<Option<Vec<u8>>, Pkcs11Error> {
    let mut attributes = vec![Attribute::Class(ObjectClass::PUBLIC_KEY)];
    if let Some(id) = &selector.id {
        attributes.push(Attribute::Id(id.clone()));
    }
    if let Some(label) = &selector.label {
        attributes.push(Attribute::Label(label.as_bytes().to_vec()));
    }
    if attributes.len() == 1 {
        // Without a label or ID there is no way to prove which public object belongs to the key.
        return Ok(None);
    }
    let objects = session
        .find_objects(&attributes)
        .map_err(|error| Pkcs11Error::cryptoki(token, "C_FindObjects", error))?;
    match objects.as_slice() {
        [] => Ok(None),
        [public] => Ok(optional_attribute_bytes(
            session,
            *public,
            AttributeType::EcPoint,
        )),
        many => Err(Pkcs11Error::KeyRejected {
            token: token.to_string(),
            selector: selector.describe(),
            detail: format!(
                "{} public key objects match the selector; narrow `key_id`/`key_label`",
                many.len()
            ),
        }),
    }
}

struct VerifiedKey {
    kind: KeyKind,
    spki: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    Rsa,
    EcP256,
}

impl KeyKind {
    fn algorithm(self) -> SignatureAlgorithm {
        match self {
            KeyKind::Rsa => SignatureAlgorithm::RSA,
            KeyKind::EcP256 => SignatureAlgorithm::ECDSA,
        }
    }

    fn candidates(self) -> &'static [PlanKind] {
        match self {
            KeyKind::Rsa => PlanKind::rsa_candidates(),
            KeyKind::EcP256 => PlanKind::ec_candidates(),
        }
    }
}

fn verify_key(
    pkcs11: &Pkcs11,
    slot: Slot,
    session: &Session,
    handle: ObjectHandle,
    selector: &KeySelector,
    token: &str,
) -> Result<VerifiedKey, Pkcs11Error> {
    let sensitive = attribute_bool(session, handle, AttributeType::Sensitive, token, selector)?;
    if !sensitive {
        return Err(Pkcs11Error::KeyRejected {
            token: token.to_string(),
            selector: selector.describe(),
            detail: "CKA_SENSITIVE is false; the key material would be readable".to_string(),
        });
    }
    let extractable = attribute_bool(session, handle, AttributeType::Extractable, token, selector)?;
    if extractable {
        return Err(Pkcs11Error::KeyRejected {
            token: token.to_string(),
            selector: selector.describe(),
            detail: "CKA_EXTRACTABLE is true; the key material would be readable".to_string(),
        });
    }
    if optional_attribute_bool(session, handle, AttributeType::AlwaysAuthenticate) == Some(true) {
        return Err(Pkcs11Error::KeyRejected {
            token: token.to_string(),
            selector: selector.describe(),
            detail: "CKA_ALWAYS_AUTHENTICATE requires a per-sign PIN and is not supported"
                .to_string(),
        });
    }

    let key_type = attribute_key_type(session, handle, token, selector)?;
    let kind = if key_type == KeyType::RSA {
        KeyKind::Rsa
    } else if key_type == KeyType::EC {
        KeyKind::EcP256
    } else {
        return Err(Pkcs11Error::KeyRejected {
            token: token.to_string(),
            selector: selector.describe(),
            detail: format!("CKA_KEY_TYPE {key_type:?} is neither RSA nor EC"),
        });
    };

    let spki = match kind {
        KeyKind::Rsa => {
            let modulus =
                attribute_bytes(session, handle, AttributeType::Modulus, token, selector)?;
            let exponent = attribute_bytes(
                session,
                handle,
                AttributeType::PublicExponent,
                token,
                selector,
            )?;
            if !matches!(modulus.len(), 256 | 384 | 512) {
                return Err(Pkcs11Error::KeyRejected {
                    token: token.to_string(),
                    selector: selector.describe(),
                    detail: format!(
                        "RSA modulus is {} bytes; only 2048/3072/4096-bit keys are supported",
                        modulus.len()
                    ),
                });
            }
            if modulus.first() == Some(&0) || exponent.is_empty() {
                return Err(Pkcs11Error::KeyRejected {
                    token: token.to_string(),
                    selector: selector.describe(),
                    detail: "RSA modulus or public exponent is not minimally encoded".to_string(),
                });
            }
            rsa_spki(&modulus, &exponent)
        }
        KeyKind::EcP256 => {
            let params =
                attribute_bytes(session, handle, AttributeType::EcParams, token, selector)?;
            if params != OID_PRIME256V1 {
                return Err(Pkcs11Error::KeyRejected {
                    token: token.to_string(),
                    selector: selector.describe(),
                    detail: format!(
                        "CKA_EC_PARAMS {} is not prime256v1; only P-256 is supported",
                        hex_bytes(&params)
                    ),
                });
            }
            let point = match optional_attribute_bytes(session, handle, AttributeType::EcPoint) {
                Some(point) => point,
                None => find_public_key_ec_point(session, selector, token)?.ok_or_else(|| {
                    Pkcs11Error::KeyRejected {
                        token: token.to_string(),
                        selector: selector.describe(),
                        detail: "CKA_EC_POINT is absent from the private key and no matching \
                                 public key object (same CKA_ID or CKA_LABEL) provides it; import \
                                 the matching public key object or use a token that exposes \
                                 CKA_EC_POINT on private keys"
                            .to_string(),
                    }
                })?,
            };
            let point = unwrap_ec_point(&point).ok_or_else(|| Pkcs11Error::KeyRejected {
                token: token.to_string(),
                selector: selector.describe(),
                detail: format!(
                    "CKA_EC_POINT is not an uncompressed P-256 point ({} bytes)",
                    point.len()
                ),
            })?;
            ec_p256_spki(point)
        }
    };

    let supported: Vec<PlanKind> = kind
        .candidates()
        .iter()
        .copied()
        .filter(|plan| {
            pkcs11
                .get_mechanism_info(slot, plan.mechanism_type())
                .is_ok()
        })
        .collect();
    if supported.is_empty() {
        return Err(Pkcs11Error::MechanismUnsupported {
            token: token.to_string(),
            mechanisms: kind
                .candidates()
                .iter()
                .map(|plan| plan.mechanism_label())
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    Ok(VerifiedKey { kind, spki })
}

fn sign_with_session(
    session: &Session,
    key: ObjectHandle,
    plan: PlanKind,
    payload: &[u8],
    token: &str,
) -> Result<Vec<u8>, Pkcs11Error> {
    session
        .sign(&plan.mechanism(), key, payload)
        .map_err(|error| Pkcs11Error::cryptoki(token, "C_SignInit/C_Sign", error))
}

/// Log a user in on `session`, treating `CKR_USER_ALREADY_LOGGED_IN` as success.
///
/// PKCS#11 login is token-wide, not session-wide: once any session of this process has logged
/// into the token, a login attempt on another session of the same token returns
/// `CKR_USER_ALREADY_LOGGED_IN`. The pool opens one session per `max_sessions` (and the loader
/// opens a short-lived session to resolve the public key), so every login after the first must
/// tolerate that return code instead of failing a correctly configured token.
fn login_user(session: &Session, pin: &AuthPin, token: &str) -> Result<(), Pkcs11Error> {
    match session.login(UserType::User, Some(pin)) {
        Ok(()) => Ok(()),
        Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
        Err(error) => Err(Pkcs11Error::cryptoki(token, "C_Login", error)),
    }
}

fn run_session(runtime: Arc<SessionRuntime>) {
    let token = runtime.token.clone();
    let session = match runtime.pkcs11.open_ro_session(runtime.slot) {
        Ok(session) => session,
        Err(error) => {
            let _ = Pkcs11Error::cryptoki(&token, "C_OpenSession", error);
            runtime.queue.close();
            return;
        }
    };
    if login_user(&session, &runtime.pin, &token).is_err() {
        // Fail closed: no session can sign, so reject queued and future work instead of
        // waiting for a reply that can never arrive.
        runtime.queue.close();
        return;
    }

    let mut keys: HashMap<KeySelector, ObjectHandle> = HashMap::new();
    loop {
        if runtime.queue.is_quarantined() || is_quarantined() {
            break;
        }
        let Some(job) = runtime.queue.pop_dispatched(Duration::from_millis(50)) else {
            if runtime.queue.is_closed() {
                break;
            }
            continue;
        };
        let _ = job.dispatched.send(());
        let outcome = match keys.get(job.selector.as_ref()).copied() {
            Some(handle) => sign_with_session(&session, handle, job.plan, &job.payload, &token),
            None => match find_single_private_key(&session, &job.selector, &token) {
                Ok(handle) => {
                    keys.insert(job.selector.as_ref().clone(), handle);
                    sign_with_session(&session, handle, job.plan, &job.payload, &token)
                }
                Err(error) => Err(error),
            },
        };
        *lock(&job.state) = JobState::Completed;
        let _ = job.reply.send(outcome);
    }
    let _ = session.logout();
}

// ---------------------------------------------------------------------------
// TokenPool
// ---------------------------------------------------------------------------

struct PoolInner {
    token: String,
    module_path: PathBuf,
    pkcs11: Pkcs11,
    slot: Slot,
    pin: AuthPin,
    budget: Pkcs11Budget,
    queue: Arc<SignQueue>,
    handshakes: Arc<HandshakeLimiter>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    /// Token-sign counters for the T-TLS-097 measurement harness.
    signs: AtomicU64,
    queue_wait_failures: AtomicU64,
    sign_timeout_failures: AtomicU64,
}

impl PoolInner {
    fn sign(
        &self,
        plan: PlanKind,
        selector: &KeySelector,
        message: &[u8],
    ) -> Result<Vec<u8>, Pkcs11Error> {
        let outcome = submit(
            &self.queue,
            plan,
            selector,
            plan.payload(message),
            &self.budget,
            &self.token,
        );
        match &outcome {
            Ok(_) => {
                self.signs.fetch_add(1, Ordering::Relaxed);
            }
            Err(Pkcs11Error::QueueWait { .. }) => {
                self.queue_wait_failures.fetch_add(1, Ordering::Relaxed);
            }
            Err(Pkcs11Error::SignTimeout { .. }) => {
                self.sign_timeout_failures.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        outcome
    }
}

impl Drop for PoolInner {
    fn drop(&mut self) {
        self.queue.close();
    }
}

/// Point-in-time counters for one token pool (T-TLS-097 measurement evidence).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Successful token signatures (one per full TLS 1.3 handshake on this token).
    pub signs: u64,
    /// Signs that were never dispatched within `queue_wait` (no quarantine).
    pub queue_wait_failures: u64,
    /// Dispatched signs that missed `sign_timeout` (token quarantined).
    pub sign_timeout_failures: u64,
    /// Queue high-water mark observed so far (<= `budget.queue_depth`).
    pub max_queue_depth: usize,
}

/// One open token: a bounded session pool, the sign queue, and the handshake budget.
///
/// `Send + Sync`; cheap to clone via `Arc` (see [`open_token`]).
pub struct TokenPool {
    inner: Arc<PoolInner>,
}

impl fmt::Debug for TokenPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenPool")
            .field("token", &self.inner.token)
            .field("module", &self.inner.module_path)
            .field("slot", &self.inner.slot.id())
            .field("budget", &self.inner.budget)
            .finish()
    }
}

impl TokenPool {
    /// The token label this pool is bound to.
    pub fn token_label(&self) -> &str {
        &self.inner.token
    }

    /// The module path this pool was opened from.
    pub fn module_path(&self) -> &Path {
        &self.inner.module_path
    }

    /// The budget this pool was opened with.
    pub fn budget(&self) -> &Pkcs11Budget {
        &self.inner.budget
    }

    /// Counters for the T-TLS-097 measurement harness: successful token signs, the
    /// `queue_wait` and post-dispatch `sign_timeout` failures, and the observed queue
    /// high-water mark (always <= `budget.queue_depth`).
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            signs: self.inner.signs.load(Ordering::Relaxed),
            queue_wait_failures: self.inner.queue_wait_failures.load(Ordering::Relaxed),
            sign_timeout_failures: self.inner.sign_timeout_failures.load(Ordering::Relaxed),
            max_queue_depth: self.inner.queue.max_observed.load(Ordering::Relaxed),
        }
    }

    /// Quarantine this token: every further sign fails fast with
    /// [`Pkcs11Error::Quarantined`]. Also latches the process-global flag.
    pub fn quarantine(&self) {
        self.inner.queue.set_quarantined();
    }

    /// Whether this token is quarantined.
    pub fn is_quarantined(&self) -> bool {
        self.inner.queue.is_quarantined()
    }

    /// Acquire a handshake permit, waiting at most `wait`.
    ///
    /// This is a blocking call; from async code use [`TokenPool::acquire_handshake`].
    pub fn handshake_permit(&self, wait: Duration) -> Result<HandshakePermit, Pkcs11Error> {
        self.inner.handshakes.acquire(wait)
    }

    /// Acquire a handshake permit from async code without blocking the reactor.
    pub async fn acquire_handshake(&self, wait: Duration) -> Result<HandshakePermit, Pkcs11Error> {
        let limiter = Arc::clone(&self.inner.handshakes);
        tokio::task::spawn_blocking(move || limiter.acquire(wait))
            .await
            .map_err(|error| Pkcs11Error::HandshakeBudget {
                token: self.inner.token.clone(),
                detail: format!("handshake permit task failed: {error}"),
            })?
    }

    /// Acquire a handshake permit using `budget.handshake_timeout`.
    pub async fn acquire_handshake_with_budget(&self) -> Result<HandshakePermit, Pkcs11Error> {
        let wait = self.inner.budget.handshake_timeout;
        self.acquire_handshake(wait).await
    }

    /// Stop the session threads and wait for them. A token wedged inside `C_Sign`
    /// cannot be interrupted, so this may block; production drop does not join.
    pub fn shutdown(&self) {
        self.inner.queue.close();
        let handles: Vec<JoinHandle<()>> = {
            let mut threads = lock(&self.inner.threads);
            std::mem::take(&mut *threads)
        };
        for handle in handles {
            let _ = handle.join();
        }
    }

    /// Select and verify exactly one private key, and return its rustls signing key.
    ///
    /// Fails closed on: no/multiple matches, `CKA_SENSITIVE` false, `CKA_EXTRACTABLE`
    /// true, `CKA_ALWAYS_AUTHENTICATE`, unsupported key type/curve/size, missing
    /// public components, or a token that supports none of the needed mechanisms.
    pub fn signing_key(
        &self,
        selector: &KeySelector,
    ) -> Result<Arc<Pkcs11SigningKey>, Pkcs11Error> {
        let token = self.inner.token.clone();
        let session = self
            .inner
            .pkcs11
            .open_ro_session(self.inner.slot)
            .map_err(|error| Pkcs11Error::cryptoki(&token, "C_OpenSession", error))?;
        let result = (|| {
            login_user(&session, &self.inner.pin, &token)?;
            let handle = find_single_private_key(&session, selector, &token)?;
            verify_key(
                &self.inner.pkcs11,
                self.inner.slot,
                &session,
                handle,
                selector,
                &token,
            )
        })();
        // Closing this short-lived session is enough: never call `C_Logout` here, because
        // PKCS#11 logout is token-wide and would log out the pool's live session threads.
        let verified = result?;
        let plans: Vec<PlanKind> = verified
            .kind
            .candidates()
            .iter()
            .copied()
            .filter(|plan| {
                self.inner
                    .pkcs11
                    .get_mechanism_info(self.inner.slot, plan.mechanism_type())
                    .is_ok()
            })
            .collect();
        Ok(Arc::new(Pkcs11SigningKey {
            pool: Arc::clone(&self.inner),
            kind: verified.kind,
            spki: verified.spki,
            selector: selector.clone(),
            plans,
        }))
    }
}

// ---------------------------------------------------------------------------
// Opening a token
// ---------------------------------------------------------------------------

fn load_module(module: &Path) -> Result<Pkcs11, Pkcs11Error> {
    if !module.is_absolute() {
        return Err(Pkcs11Error::ModulePath {
            path: module.to_path_buf(),
            detail: "module path must be absolute".to_string(),
        });
    }
    match std::fs::metadata(module) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(Pkcs11Error::ModulePath {
                path: module.to_path_buf(),
                detail: "not a regular file".to_string(),
            })
        }
        Err(error) => {
            return Err(Pkcs11Error::ModulePath {
                path: module.to_path_buf(),
                detail: error.to_string(),
            })
        }
    }
    // cryptoki calls `libloading`'s `DlSym` on a symbol and panics if the library is
    // not a PKCS#11 module; a bad path must be a located error, never a panic.
    let loaded = catch_unwind(AssertUnwindSafe(|| Pkcs11::new(module))).map_err(|_| {
        Pkcs11Error::ModuleLoad {
            path: module.to_path_buf(),
            detail: "module load panicked (not a PKCS#11 shared library)".to_string(),
        }
    })?;
    loaded.map_err(|error| Pkcs11Error::ModuleLoad {
        path: module.to_path_buf(),
        detail: error.to_string(),
    })
}

/// One `Pkcs11` context per module path, shared process-wide.
///
/// `C_Initialize`/`C_Finalize` are process-global for a PKCS#11 module, while
/// `cryptoki::Pkcs11` calls `C_Finalize` from `Drop` when its last handle drops. Creating a
/// second context for the same module therefore either fails `C_Initialize` with
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` or — worse — lets the old context's `Drop` finalize the
/// module underneath live sessions, which was observed as SIGSEGV inside SoftHSM2 during the
/// T-TLS-097 measurements. Share one context per module for the process lifetime: a
/// configuration reload reuses it, and `C_Finalize` runs when the process exits.
static MODULE_CONTEXTS: LazyLock<Mutex<HashMap<PathBuf, Pkcs11>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn open_module(module: &Path) -> Result<Pkcs11, Pkcs11Error> {
    let key = std::fs::canonicalize(module).unwrap_or_else(|_| module.to_path_buf());
    // Serialize creation under the registry lock so two threads can never both call
    // `C_Initialize`/`C_Finalize` on the same module.
    let mut contexts = lock(&MODULE_CONTEXTS);
    if let Some(pkcs11) = contexts.get(&key) {
        return Ok(pkcs11.clone());
    }
    let pkcs11 = load_module(module)?;
    match pkcs11.initialize(CInitializeArgs::OsThreads) {
        Ok(()) => {}
        // This handle initialized the module.
        Err(CryptokiError::AlreadyInitialized) => {}
        // Some other code path in this process initialized the module first; the module is
        // initialized and this handle is usable.
        Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(error) => {
            return Err(Pkcs11Error::ModuleInitialize {
                path: module.to_path_buf(),
                rv: error.to_string(),
            })
        }
    }
    contexts.insert(key, pkcs11.clone());
    Ok(pkcs11)
}

fn select_slot(
    pkcs11: &Pkcs11,
    module: &Path,
    token_label: Option<&str>,
    slot_id: Option<u64>,
) -> Result<(Slot, String), Pkcs11Error> {
    let token_name = token_label.unwrap_or("<any>").to_string();
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|error| Pkcs11Error::Cryptoki {
            token: token_name.clone(),
            operation: "C_GetSlotList",
            rv: error.to_string(),
        })?;
    if slots.is_empty() {
        return Err(Pkcs11Error::TokenSelect {
            token: token_name,
            detail: format!("module {} reports no token present", module.display()),
        });
    }
    let mut matches = Vec::new();
    for slot in slots {
        if let Some(wanted) = slot_id {
            if slot.id() != wanted {
                continue;
            }
        }
        let label = pkcs11
            .get_token_info(slot)
            .map(|info| info.label().trim_end_matches([' ', '\0']).to_string())
            .map_err(|error| Pkcs11Error::Cryptoki {
                token: token_name.clone(),
                operation: "C_GetTokenInfo",
                rv: error.to_string(),
            })?;
        if let Some(wanted) = token_label {
            if label != wanted.trim() {
                continue;
            }
        }
        matches.push((slot, label));
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Pkcs11Error::TokenSelect {
            token: token_name,
            detail: format!(
                "no slot matches token_label={:?} slot={:?}",
                token_label, slot_id
            ),
        }),
        found => Err(Pkcs11Error::TokenSelect {
            token: token_name,
            detail: format!("{found} slots match; narrow token_label or slot"),
        }),
    }
}

/// Open `module`, select one token (by `token_label` and/or `slot`), log in with `pin`,
/// and start `budget.max_sessions` session threads.
///
/// Fails closed with a located error naming the module path, token, and `CKR_*` text.
pub fn open_token(
    module: &Path,
    token_label: Option<&str>,
    slot: Option<u64>,
    pin: AuthPin,
    budget: Pkcs11Budget,
) -> Result<Arc<TokenPool>, Pkcs11Error> {
    let budget = budget.normalized();
    let pkcs11 = open_module(module)?;
    let (slot, token) = select_slot(&pkcs11, module, token_label, slot)?;

    // Probe: open a session and log in on this thread so a wrong PIN fails here,
    // with a located error, before any session thread exists.
    {
        let session = pkcs11
            .open_ro_session(slot)
            .map_err(|error| Pkcs11Error::cryptoki(&token, "C_OpenSession", error))?;
        login_user(&session, &pin, &token)?;
        // Do not `C_Logout` here: logout is token-wide and would sign out sessions of an older
        // pool for the same token (configuration reload). Dropping the session closes it only.
    }

    let queue = SignQueue::new(token.clone(), budget.queue_depth);
    let handshakes = HandshakeLimiter::new(token.clone(), budget.max_inflight_handshakes);
    let mut threads = Vec::with_capacity(budget.max_sessions);
    for index in 0..budget.max_sessions {
        let runtime = Arc::new(SessionRuntime {
            token: token.clone(),
            pkcs11: pkcs11.clone(),
            slot,
            pin: pin.clone(),
            queue: Arc::clone(&queue),
        });
        let handle = thread::Builder::new()
            .name(format!("pkcs11-{token}-{index}"))
            .spawn(move || run_session(runtime))
            .map_err(|error| Pkcs11Error::Internal {
                token: token.clone(),
                detail: format!("spawning session thread failed: {error}"),
            })?;
        threads.push(handle);
    }

    Ok(Arc::new(TokenPool {
        inner: Arc::new(PoolInner {
            token,
            module_path: module.to_path_buf(),
            pkcs11,
            slot,
            pin,
            budget,
            queue,
            handshakes,
            threads: Mutex::new(threads),
            signs: AtomicU64::new(0),
            queue_wait_failures: AtomicU64::new(0),
            sign_timeout_failures: AtomicU64::new(0),
        }),
    }))
}

// ---------------------------------------------------------------------------
// rustls bridge
// ---------------------------------------------------------------------------

/// A token-backed key implementing [`rustls::sign::SigningKey`].
pub struct Pkcs11SigningKey {
    pool: Arc<PoolInner>,
    kind: KeyKind,
    spki: Vec<u8>,
    selector: KeySelector,
    plans: Vec<PlanKind>,
}

impl fmt::Debug for Pkcs11SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11SigningKey")
            .field("token", &self.pool.token)
            .field("selector", &self.selector)
            .field("kind", &self.kind)
            .finish()
    }
}

impl Pkcs11SigningKey {
    /// The token label the key lives on.
    pub fn token_label(&self) -> &str {
        &self.pool.token
    }

    /// The selector used to find the key.
    pub fn selector(&self) -> &KeySelector {
        &self.selector
    }

    /// The DER `SubjectPublicKeyInfo` of the token key's public components.
    ///
    /// Only public material is returned; the private key stays in the token.
    pub fn public_key_der(&self) -> &[u8] {
        &self.spki
    }

    /// Adapt this token key as a certificate key source for ACME/internal-CA issuance.
    ///
    /// Returns `None` when the token offers no CSR-compatible mechanism for this key; callers must
    /// then fail closed instead of generating a process-held PEM key. The recorded key id is the
    /// selector's `CKA_LABEL`, or its hex `CKA_ID` when no label was given.
    pub fn certificate_key_source(&self) -> Option<crate::certificate::CertificateKeySource> {
        let signer = self.csr_signer()?;
        let key_id = match (&self.selector.label, &self.selector.id) {
            (Some(label), _) => label.clone(),
            (None, Some(id)) => id.iter().map(|byte| format!("{byte:02x}")).collect(),
            (None, None) => "unlabelled".to_string(),
        };
        crate::certificate::CertificateKeySource::token(
            crate::certificate::TokenKeyRef::new(self.token_label(), key_id),
            std::sync::Arc::new(signer),
        )
        .ok()
    }

    /// Adapt this token key for PKCS#10 CSR signing (`crate::acme::csr::CsrSigner`).
    ///
    /// The scheme is pinned to what a CSR builder can encode: RSA PKCS#1 v1.5 (never RSA-PSS,
    /// which this runtime only offers for TLS handshakes) or ECDSA P-256/SHA-256. Returns `None`
    /// when the token supports no CSR-compatible mechanism for this key. Signing goes through the
    /// same per-token sign queue, `queue_wait`/`sign_timeout` budgets and quarantine latch as TLS
    /// handshakes; there is no software-key fallback.
    pub fn csr_signer(&self) -> Option<Pkcs11CsrSigner> {
        let plan = match self.kind {
            KeyKind::Rsa => self
                .plans
                .iter()
                .copied()
                .find(|plan| matches!(plan, PlanKind::RsaPkcs1Sha256))?,
            KeyKind::EcP256 => self
                .plans
                .iter()
                .copied()
                .find(|plan| matches!(plan, PlanKind::EcdsaP256Sha256))?,
        };
        Some(Pkcs11CsrSigner {
            pool: Arc::clone(&self.pool),
            plan,
            selector: self.selector.clone(),
            spki: self.spki.clone(),
        })
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let plan = PlanKind::choose(&self.plans, offered)?;
        Some(Box::new(Pkcs11Signer {
            pool: Arc::clone(&self.pool),
            plan,
            selector: self.selector.clone(),
            token: self.pool.token.clone(),
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.clone()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.kind.algorithm()
    }
}

/// One signature over one scheme; implements [`rustls::sign::Signer`].
pub struct Pkcs11Signer {
    pool: Arc<PoolInner>,
    plan: PlanKind,
    selector: KeySelector,
    token: String,
}

impl fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("token", &self.token)
            .field("scheme", &self.plan.scheme())
            .field("mechanism", &self.plan.mechanism_label())
            .finish()
    }
}

impl Signer for Pkcs11Signer {
    fn scheme(&self) -> SignatureScheme {
        self.plan.scheme()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let raw = dispatch_sign(&self.pool, self.plan, &self.selector, message)
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        if self.plan.is_ecdsa() {
            raw_ecdsa_to_der(&self.token, &raw, 32)
                .map_err(|error| rustls::Error::General(error.to_string()))
        } else {
            Ok(raw)
        }
    }
}

/// A token-backed key adapted to PKCS#10 CSR signing.
///
/// Obtained from [`Pkcs11SigningKey::csr_signer`]; the private key never leaves the token and no
/// key-export path exists. The CSR builder only sees the public SPKI, the pinned scheme and the
/// signature bytes.
#[derive(Clone)]
pub struct Pkcs11CsrSigner {
    pool: Arc<PoolInner>,
    plan: PlanKind,
    selector: KeySelector,
    spki: Vec<u8>,
}

impl fmt::Debug for Pkcs11CsrSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11CsrSigner")
            .field("token", &self.pool.token)
            .field("selector", &self.selector)
            .field("scheme", &self.plan.scheme())
            .field("mechanism", &self.plan.mechanism_label())
            .finish()
    }
}

impl CsrSigner for Pkcs11CsrSigner {
    fn spki(&self) -> &[u8] {
        &self.spki
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.plan.scheme()
    }

    fn sign(&self, message: &[u8]) -> crate::Result<Vec<u8>> {
        let raw = dispatch_sign(&self.pool, self.plan, &self.selector, message)
            .map_err(|error| csr_signing_error(&self.pool.token, &error))?;
        if self.plan.is_ecdsa() {
            raw_ecdsa_to_der(&self.pool.token, &raw, 32)
                .map_err(|error| csr_signing_error(&self.pool.token, &error))
        } else {
            Ok(raw)
        }
    }
}

fn csr_signing_error(token: &str, error: &Pkcs11Error) -> crate::Error {
    crate::Error::Issuer(format!(
        "signing certificate request on PKCS#11 token {token}: {error}"
    ))
}

/// Dispatch one sign to the token, never stalling an async worker.
///
/// rustls' signer (and the CSR signer) is synchronous. On a multi-thread Tokio runtime the token
/// wait must not stall an async worker: `block_in_place` hands this worker's other tasks to
/// another thread while the token dispatch/reply budget is spent. The wait is bounded by the
/// per-token queue and sign budgets, and there is at most one such wait per in-flight handshake
/// (bounded by `max_inflight_handshakes`). On other runtimes (current-thread, no runtime) the
/// caller is already a blocking context, so the call runs inline.
fn dispatch_sign(
    pool: &PoolInner,
    plan: PlanKind,
    selector: &KeySelector,
    message: &[u8],
) -> Result<Vec<u8>, Pkcs11Error> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| pool.sign(plan, selector, message))
        }
        _ => pool.sign(plan, selector, message),
    }
}

// ---------------------------------------------------------------------------
// Tests (pure logic only; no token required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        assert!(value.len() % 2 == 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex digit"))
            .collect()
    }

    #[test]
    fn ecdsa_raw_to_der_minimal() {
        // r = s = 1 -> SEQUENCE { INTEGER 1, INTEGER 1 }
        let mut raw = [0u8; 64];
        raw[31] = 1;
        raw[63] = 1;
        let der = raw_ecdsa_to_der("test-token", &raw, 32).expect("convert");
        assert_eq!(der, hex("3006020101020101"));
    }

    #[test]
    fn ecdsa_raw_to_der_strips_padding_and_pads_high_bit() {
        let mut raw = vec![0u8; 64];
        raw[31] = 0x7f; // r = 0x7f (31 redundant leading zeros stripped)
        raw[32] = 0x80; // s starts with a high bit: needs a 0x00 pad
        raw[63] = 0x02;
        let der = raw_ecdsa_to_der("test-token", &raw, 32).expect("convert");
        let mut expected = vec![0x30, 0x26, 0x02, 0x01, 0x7f, 0x02, 0x21, 0x00, 0x80];
        expected.extend_from_slice(&[0u8; 30]);
        expected.push(0x02);
        assert_eq!(der, expected);
    }

    #[test]
    fn ecdsa_raw_to_der_rejects_wrong_length() {
        let error = raw_ecdsa_to_der("test-token", &[0u8; 63], 32).expect_err("must reject");
        match error {
            Pkcs11Error::SignatureFormat { got, want, token } => {
                assert_eq!((got, want), (63, 64));
                assert_eq!(token, "test-token");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn scheme_selection_intersection() {
        let offered = [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ];
        assert_eq!(
            PlanKind::choose(PlanKind::rsa_candidates(), &offered),
            Some(PlanKind::RsaPssSha256)
        );
        let only_pkcs1 = [SignatureScheme::RSA_PKCS1_SHA384];
        assert_eq!(
            PlanKind::choose(PlanKind::rsa_candidates(), &only_pkcs1),
            Some(PlanKind::RsaPkcs1Sha384)
        );
        let ec_only = [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ];
        assert_eq!(
            PlanKind::choose(PlanKind::ec_candidates(), &ec_only),
            Some(PlanKind::EcdsaP256Sha256)
        );
        let no_match = [SignatureScheme::ED25519];
        assert_eq!(
            PlanKind::choose(PlanKind::rsa_candidates(), &no_match),
            None
        );

        // A token restricted to PKCS#1 must not pick PSS even when offered.
        let restricted = [PlanKind::RsaPkcs1Sha256];
        assert_eq!(
            PlanKind::choose(&restricted, &offered),
            Some(PlanKind::RsaPkcs1Sha256)
        );
    }

    #[test]
    fn plan_inputs_match_mechanism_contract() {
        assert_eq!(PlanKind::RsaPssSha256.payload(b"abc").len(), 32);
        assert_eq!(PlanKind::RsaPssSha384.payload(b"abc").len(), 48);
        assert_eq!(PlanKind::RsaPssSha512.payload(b"abc").len(), 64);
        assert_eq!(PlanKind::EcdsaP256Sha256.payload(b"abc").len(), 32);
        assert_eq!(PlanKind::RsaPkcs1Sha256.payload(b"abc"), b"abc".to_vec());
        assert_eq!(
            PlanKind::RsaPssSha256.mechanism_type(),
            MechanismType::RSA_PKCS_PSS
        );
        assert_eq!(
            PlanKind::RsaPkcs1Sha256.mechanism_type(),
            MechanismType::SHA256_RSA_PKCS
        );
        assert_eq!(
            PlanKind::EcdsaP256Sha256.mechanism_type(),
            MechanismType::ECDSA
        );
    }

    #[test]
    fn rsa_spki_matches_openssl() {
        let modulus = hex(
            "99591951af2ba36007905cd1bb789f5e9ce18bd0921a9b76ca509b77f54536a9a3a58f4d0f4e6514899bdba1445933fed3737bef9763da3977c928a49acae0740821acb5fc5393b8abd133ec08a947314e09b1d65334d8fe26f44bd3292cc5de46a2977ea6c7fb89a9799fefe796f1952f976273623ff9939f6c09cd4bdc77d859f2693ca140a1ba0f31633f729c19771fe271978e4733ddc7d8db02742662f82e79b7d96c1d2d74606a11182f8157d265af7d10f8b4e68aac127ecbc7e2817ae558517c08f53f0b5bf397a4226303101bf8b602b44e1953c2cd7eea620ab9597de5950c1c8f92b806822acc1d49e02d2b85e041357457ccfc4270cb5292b92f",
        );
        let expected = hex(
            "30820122300d06092a864886f70d01010105000382010f003082010a028201010099591951af2ba36007905cd1bb789f5e9ce18bd0921a9b76ca509b77f54536a9a3a58f4d0f4e6514899bdba1445933fed3737bef9763da3977c928a49acae0740821acb5fc5393b8abd133ec08a947314e09b1d65334d8fe26f44bd3292cc5de46a2977ea6c7fb89a9799fefe796f1952f976273623ff9939f6c09cd4bdc77d859f2693ca140a1ba0f31633f729c19771fe271978e4733ddc7d8db02742662f82e79b7d96c1d2d74606a11182f8157d265af7d10f8b4e68aac127ecbc7e2817ae558517c08f53f0b5bf397a4226303101bf8b602b44e1953c2cd7eea620ab9597de5950c1c8f92b806822acc1d49e02d2b85e041357457ccfc4270cb5292b92f0203010001",
        );
        assert_eq!(rsa_spki(&modulus, &[0x01, 0x00, 0x01]), expected);
    }

    #[test]
    fn ec_spki_matches_openssl() {
        let point = hex(
            "049170f21c20a83e45f4c9b9a7bb581d096f8a069e19c2fde53b4e78fac10d67d2ad5a599b27126dcff4e978caaaff088831b66ec074b68f63f9e6c434c43baf69",
        );
        let expected = hex(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200049170f21c20a83e45f4c9b9a7bb581d096f8a069e19c2fde53b4e78fac10d67d2ad5a599b27126dcff4e978caaaff088831b66ec074b68f63f9e6c434c43baf69",
        );
        assert_eq!(ec_p256_spki(&point), expected);
        // SoftHSM wraps CKA_EC_POINT in a DER OCTET STRING; both spellings unwrap.
        let mut wrapped = vec![0x04, 65];
        wrapped.extend_from_slice(&point);
        assert_eq!(unwrap_ec_point(&wrapped), Some(point.as_slice()));
        assert_eq!(unwrap_ec_point(&point), Some(point.as_slice()));
    }

    #[test]
    fn queue_wait_timeout_does_not_quarantine() {
        let queue = SignQueue::new("test-token".to_string(), 1);
        let make_job = || {
            let (dispatched_tx, _dispatched_rx) = sync_channel(1);
            let (reply_tx, _reply_rx) = sync_channel(1);
            Arc::new(Job {
                plan: PlanKind::EcdsaP256Sha256,
                selector: Arc::new(KeySelector::default()),
                payload: vec![0u8; 32],
                state: Mutex::new(JobState::Queued),
                dispatched: dispatched_tx,
                reply: reply_tx,
            })
        };
        // Fill the single slot with a job nobody consumes.
        queue
            .enqueue(make_job(), Instant::now() + Duration::from_secs(1))
            .expect("first job admitted");
        let second = make_job();
        let error = queue
            .enqueue(
                Arc::clone(&second),
                Instant::now() + Duration::from_millis(20),
            )
            .expect_err("queue is full");
        match error {
            Pkcs11Error::QueueWait { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
        assert!(!queue.is_quarantined());
    }

    fn test_job() -> Arc<Job> {
        let (dispatched, _) = sync_channel(1);
        let (reply, _) = sync_channel(1);
        Arc::new(Job {
            plan: PlanKind::EcdsaP256Sha256,
            selector: Arc::new(KeySelector::default()),
            payload: vec![0u8; 32],
            state: Mutex::new(JobState::Queued),
            dispatched,
            reply,
        })
    }

    #[test]
    fn submit_times_out_in_queue_without_quarantine() {
        let queue = SignQueue::new("test-token".to_string(), 1);
        // Occupy the only slot behind an unconsumed job.
        queue
            .enqueue(test_job(), Instant::now() + Duration::from_secs(1))
            .expect("admitted");
        let budget = Pkcs11Budget {
            queue_depth: 1,
            queue_wait: Duration::from_millis(20),
            sign_timeout: Duration::from_millis(20),
            ..Pkcs11Budget::default()
        };
        let error = submit(
            &queue,
            PlanKind::EcdsaP256Sha256,
            &KeySelector::default(),
            vec![0u8; 32],
            &budget,
            "test-token",
        )
        .expect_err("queue full");
        assert!(matches!(error, Pkcs11Error::QueueWait { .. }));
        assert!(!queue.is_quarantined());
    }

    #[test]
    fn post_dispatch_timeout_quarantines() {
        clear_quarantine_for_test();
        let queue = SignQueue::new("test-token".to_string(), 2);
        let budget = Pkcs11Budget {
            queue_depth: 2,
            queue_wait: Duration::from_millis(500),
            sign_timeout: Duration::from_millis(20),
            ..Pkcs11Budget::default()
        };
        // A session that dispatches the job (marks it) but then wedges in C_Sign.
        let consumer_queue = Arc::clone(&queue);
        let consumer = std::thread::spawn(move || {
            if let Some(job) = consumer_queue.pop_dispatched(Duration::from_millis(500)) {
                let _ = job.dispatched.send(());
                std::thread::sleep(Duration::from_millis(80));
            }
        });
        let error = submit(
            &queue,
            PlanKind::EcdsaP256Sha256,
            &KeySelector::default(),
            vec![0u8; 32],
            &budget,
            "test-token",
        )
        .expect_err("must time out");
        consumer.join().expect("consumer");
        match error {
            Pkcs11Error::SignTimeout { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
        assert!(queue.is_quarantined());
        assert!(is_quarantined());
    }

    #[test]
    fn handshake_semaphore_bounds_and_releases() {
        let limiter = HandshakeLimiter::new("test-token".to_string(), 1);
        let permit = limiter.acquire(Duration::from_millis(10)).expect("first");
        let error = limiter
            .acquire(Duration::from_millis(10))
            .expect_err("second must wait");
        assert!(matches!(error, Pkcs11Error::HandshakeBudget { .. }));
        drop(permit);
        let _second = limiter
            .acquire(Duration::from_millis(10))
            .expect("released");
    }

    /// Manual smoke check against the provisioned SoftHSM2 token. Not part of the
    /// required suite: run with
    /// `SOFTHSM2_CONF=... cargo test -p caddy-rs-tls --lib -- --ignored softhsm`.
    #[test]
    #[ignore = "requires the provisioned SoftHSM2 token (caddy-rs-test, PIN 123456)"]
    fn softhsm_token_smoke() {
        let module = Path::new("/root/caddy-rs/.scratch/softhsm-prefix/lib/softhsm/libsofthsm2.so");
        if !module.exists() {
            return;
        }
        let pin = AuthPin::new("123456".to_string());
        let pool = open_token(
            module,
            Some("caddy-rs-test"),
            None,
            pin,
            Pkcs11Budget::default(),
        )
        .expect("open token");
        let rsa = pool
            .signing_key(&KeySelector {
                label: Some("rsa2048".to_string()),
                id: Some(vec![0x01]),
            })
            .expect("rsa key");
        let signer = rsa
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .expect("rsa scheme");
        assert_eq!(signer.sign(b"smoke").expect("rsa sign").len(), 256);
        let ec = pool
            .signing_key(&KeySelector {
                label: Some("p256".to_string()),
                id: Some(vec![0x02]),
            })
            .expect("ec key");
        let signer = ec
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("ec scheme");
        let signature = signer.sign(b"smoke").expect("ec sign");
        assert_eq!(signature[0], 0x30);
        pool.shutdown();
    }

    #[test]
    fn errors_never_print_pin_material() {
        // A located error rendered from a failing operation must not contain the PIN.
        let error = Pkcs11Error::Cryptoki {
            token: "caddy-rs-test".to_string(),
            operation: "C_Login",
            rv: "CKR_PIN_INCORRECT".to_string(),
        };
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("123456"));
        assert!(rendered.contains("C_Login"));

        // The debug form of a selector with an ID is hex, never the PIN.
        let selector = KeySelector {
            label: Some("rsa2048".to_string()),
            id: Some(vec![1]),
        };
        let rendered = format!("{selector:?}");
        assert!(rendered.contains("rsa2048"));
        assert!(!rendered.contains("123456"));
    }
}
