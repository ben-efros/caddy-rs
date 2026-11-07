//! Scripted-transport tests for the S3-compatible backend.
//!
//! No network: the mock implements [`AcmeTransport`] and records requests, matching the
//! DigitalOcean/Route53 test pattern.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;

use super::*;
use crate::acme::{AcmeTransport, HttpRequest, HttpResponse};
use crate::renewal::ManualClock;

/// A scripted S3 server: maps `METHOD path` to a response and records every request.
struct MockS3 {
    requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<Vec<(String, HttpResponse)>>,
}

impl MockS3 {
    fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        }
    }

    fn expect(&self, method: HttpMethod, path: &str, response: HttpResponse) {
        self.responses
            .lock()
            .unwrap()
            .push((format!("{} {path}", method.as_str()), response));
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn last_authorization(&self) -> Option<String> {
        self.requests.lock().unwrap().last().and_then(|request| {
            request
                .headers
                .iter()
                .find(|(name, _)| name == "Authorization")
                .map(|(_, value)| value.clone())
        })
    }
}

#[async_trait]
impl AcmeTransport for MockS3 {
    async fn request(&self, request: HttpRequest) -> crate::Result<HttpResponse> {
        self.requests.lock().unwrap().push(request.clone());
        let path = request
            .url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&request.url);
        let path = path
            .split_once('/')
            .map(|(_, rest)| format!("/{rest}"))
            .unwrap_or_else(|| "/".into());
        let path = path.split('?').next().unwrap_or(&path).to_string();
        let key = format!("{} {path}", request.method.as_str());
        let mut responses = self.responses.lock().unwrap();
        if let Some(position) = responses.iter().position(|(expected, _)| *expected == key) {
            return Ok(responses.remove(position).1);
        }
        Ok(HttpResponse::new(404))
    }
}

fn settings() -> S3Settings {
    S3Settings {
        endpoint: "https://s3.example.test".to_string(),
        bucket: "certs".to_string(),
        region: "us-east-1".to_string(),
        prefix: String::new(),
        path_style: true,
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: None,
    }
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ))
}

const CERT_PEM: &str = include_str!("../../testdata/https/example.com.pem");
const CERT_KEY_PEM: &str = include_str!("../../testdata/https/example.com.key");

fn stored_certificate() -> crate::storage::StoredCertificate {
    crate::storage::StoredCertificate {
        certificate_pem: crate::storage::certificate_chain_pem(CERT_PEM).unwrap(),
        private_key_pem: crate::storage::private_key_pem(CERT_KEY_PEM).unwrap(),
        domains: vec!["example.com".to_string()],
        not_after_unix: crate::storage::certificate_not_after_unix(CERT_PEM).unwrap(),
        issuer_data: Some(serde_json::json!({
            "url": "https://acme.test/cert/1",
            "ca": "https://acme.test/directory",
            "account": "https://acme.test/account/1"
        })),
        metadata_extra: BTreeMap::new(),
    }
}

fn storage_with_mock(mock: Arc<MockS3>) -> S3Storage {
    S3Storage::with_clock(settings(), mock as Arc<dyn AcmeTransport>, clock())
}

#[test]
fn settings_parse_and_redact_secrets() {
    let mut extra = BTreeMap::new();
    extra.insert(
        "endpoint".to_string(),
        serde_json::json!("http://127.0.0.1:9000"),
    );
    extra.insert("bucket".to_string(), serde_json::json!("certs"));
    extra.insert("access_key_id".to_string(), serde_json::json!("ACCESS"));
    extra.insert("secret_access_key".to_string(), serde_json::json!("SECRET"));

    std::env::remove_var("AWS_ACCESS_KEY_ID");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    let config = caddy_rs_core::config::StorageConfig {
        module: Some("s3".to_string()),
        extra,
    };
    let settings = S3Settings::from_storage_config(&config, "storage").unwrap();
    assert_eq!(settings.bucket, "certs");
    assert!(
        settings.path_style,
        "custom endpoints default to path-style"
    );
    assert_eq!(settings.region, "us-east-1");
    let debug = format!("{settings:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("SECRET"), "{debug}");
}

#[test]
fn settings_errors_are_located() {
    let missing_bucket = caddy_rs_core::config::StorageConfig {
        module: Some("s3".to_string()),
        extra: BTreeMap::from([
            (
                "endpoint".to_string(),
                serde_json::json!("https://s3.example.test"),
            ),
            ("access_key_id".to_string(), serde_json::json!("a")),
            ("secret_access_key".to_string(), serde_json::json!("b")),
        ]),
    };
    let error = S3Settings::from_storage_config(&missing_bucket, "storage").unwrap_err();
    assert!(error.to_string().contains("storage.bucket"), "{error}");

    let bad_endpoint = caddy_rs_core::config::StorageConfig {
        module: Some("s3".to_string()),
        extra: BTreeMap::from([
            ("endpoint".to_string(), serde_json::json!("s3.example.test")),
            ("bucket".to_string(), serde_json::json!("certs")),
            ("access_key_id".to_string(), serde_json::json!("a")),
            ("secret_access_key".to_string(), serde_json::json!("b")),
        ]),
    };
    let error = S3Settings::from_storage_config(&bad_endpoint, "storage").unwrap_err();
    assert!(error.to_string().contains("storage.endpoint"), "{error}");
}

#[tokio::test]
async fn get_put_head_delete_round_trip() {
    let mock = Arc::new(MockS3::new());
    mock.expect(HttpMethod::Put, "/certs/key.bin", HttpResponse::new(200));
    mock.expect(
        HttpMethod::Get,
        "/certs/key.bin",
        HttpResponse::new(200).with_body(b"value".to_vec()),
    );
    mock.expect(
        HttpMethod::Head,
        "/certs/key.bin",
        HttpResponse::new(200).with_header("Content-Length", "5"),
    );
    mock.expect(HttpMethod::Delete, "/certs/key.bin", HttpResponse::new(204));
    mock.expect(
        HttpMethod::Delete,
        "/certs/missing.bin",
        HttpResponse::new(404),
    );

    let client = S3Client::with_clock(settings(), mock.clone(), clock());
    client.put("key.bin", b"value".to_vec(), &[]).await.unwrap();
    assert_eq!(
        client.get("key.bin").await.unwrap(),
        Some(b"value".to_vec())
    );
    assert_eq!(client.head("key.bin").await.unwrap(), Some(5));
    assert_eq!(client.get("missing.bin").await.unwrap(), None);
    client.delete("key.bin").await.unwrap();
    client.delete("missing.bin").await.unwrap();
    assert_eq!(mock.request_count(), 6);
    let authorization = mock.last_authorization().unwrap();
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"),
        "{authorization}"
    );
}

#[tokio::test]
async fn head_and_get_404_are_none() {
    let mock = Arc::new(MockS3::new());
    let client = S3Client::with_clock(settings(), mock, clock());
    assert_eq!(client.get("missing").await.unwrap(), None);
    assert_eq!(client.head("missing").await.unwrap(), None);
}

#[tokio::test]
async fn list_paginates_with_continuation_token() {
    let mock = Arc::new(MockS3::new());
    mock.expect(
        HttpMethod::Get,
        "/certs",
        HttpResponse::new(200).with_body(
            b"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>certificates/local/example.com.crt</Key></Contents><NextContinuationToken>page2</NextContinuationToken></ListBucketResult>".to_vec(),
        ),
    );
    mock.expect(
        HttpMethod::Get,
        "/certs",
        HttpResponse::new(200).with_body(
            b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>certificates/local/www.example.com.crt</Key></Contents></ListBucketResult>".to_vec(),
        ),
    );
    let client = S3Client::with_clock(settings(), mock.clone(), clock());
    let keys = client.list("certificates/").await.unwrap();
    assert_eq!(
        keys,
        vec![
            "certificates/local/example.com.crt".to_string(),
            "certificates/local/www.example.com.crt".to_string()
        ]
    );
    assert_eq!(mock.request_count(), 2);
}

#[tokio::test]
async fn lock_and_unlock_use_conditional_put_and_delete() {
    let mock = Arc::new(MockS3::new());
    mock.expect(
        HttpMethod::Put,
        "/certs/locks/example.com",
        HttpResponse::new(200),
    );
    mock.expect(
        HttpMethod::Put,
        "/certs/locks/example.com",
        HttpResponse::new(412),
    );
    mock.expect(
        HttpMethod::Delete,
        "/certs/locks/example.com",
        HttpResponse::new(204),
    );
    let client = S3Client::with_clock(settings(), mock.clone(), clock());
    client.lock("example.com").await.unwrap();
    let error = client.lock("example.com").await.unwrap_err();
    assert!(matches!(error, S3Error::LockHeld(_)), "{error:?}");
    client.unlock("example.com").await.unwrap();
}

#[tokio::test]
async fn certificate_storage_round_trip_through_traits() {
    let mock = Arc::new(MockS3::new());
    mock.expect(
        HttpMethod::Put,
        "/certs/certificates/local/example.com.crt",
        HttpResponse::new(200),
    );
    mock.expect(
        HttpMethod::Put,
        "/certs/certificates/local/example.com.key",
        HttpResponse::new(200),
    );
    mock.expect(
        HttpMethod::Put,
        "/certs/certificates/local/example.com.json",
        HttpResponse::new(200),
    );
    // load
    mock.expect(
        HttpMethod::Get,
        "/certs/certificates/local/example.com.crt",
        HttpResponse::new(200).with_body(CERT_PEM.as_bytes().to_vec()),
    );
    mock.expect(
        HttpMethod::Get,
        "/certs/certificates/local/example.com.key",
        HttpResponse::new(200).with_body(CERT_KEY_PEM.as_bytes().to_vec()),
    );
    mock.expect(
        HttpMethod::Get,
        "/certs/certificates/local/example.com.json",
        HttpResponse::new(200).with_body(
            serde_json::to_vec(&serde_json::json!({
                "sans": ["example.com"],
                "issuer_data": {
                    "url": "https://acme.test/cert/1",
                    "ca": "https://acme.test/directory",
                    "account": "https://acme.test/account/1"
                }
            }))
            .unwrap(),
        ),
    );
    mock.expect(
        HttpMethod::Get,
        "/certs",
        HttpResponse::new(200).with_body(
            b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>certificates/local/example.com.crt</Key></Contents><Contents><Key>certificates/local/example.com.key</Key></Contents></ListBucketResult>".to_vec(),
        ),
    );

    let storage = storage_with_mock(mock);
    let certificate = stored_certificate();
    use crate::storage::CertificateStorage;
    storage
        .store("local/example.com", &certificate)
        .await
        .unwrap();
    let loaded = storage
        .load("local/example.com")
        .await
        .unwrap()
        .expect("stored certificate");
    assert_eq!(loaded.domains, vec!["example.com".to_string()]);
    assert_eq!(loaded.certificate_pem, certificate.certificate_pem);
    assert_eq!(loaded.issuer_data, certificate.issuer_data);
    assert_eq!(
        storage.list("").await.unwrap(),
        vec!["local/example.com".to_string()]
    );
}

#[tokio::test]
async fn account_storage_round_trip_through_traits() {
    let mock = Arc::new(MockS3::new());
    mock.expect(
        HttpMethod::Put,
        "/certs/acme/ca/users/user/account.json",
        HttpResponse::new(200),
    );
    mock.expect(
        HttpMethod::Get,
        "/certs/acme/ca/users/user/account.json",
        HttpResponse::new(200).with_body(b"{\"account\":\"1\"}".to_vec()),
    );
    mock.expect(
        HttpMethod::Delete,
        "/certs/acme/ca/users/user/account.json",
        HttpResponse::new(204),
    );
    let storage = storage_with_mock(mock);
    use crate::acme::AcmeStorage;
    storage
        .store("acme/ca/users/user/account.json", b"{\"account\":\"1\"}")
        .await
        .unwrap();
    assert_eq!(
        storage
            .load("acme/ca/users/user/account.json")
            .await
            .unwrap(),
        Some(b"{\"account\":\"1\"}".to_vec())
    );
    storage
        .delete("acme/ca/users/user/account.json")
        .await
        .unwrap();
}

#[tokio::test]
async fn http_errors_are_typed_and_secret_free() {
    let mock = Arc::new(MockS3::new());
    mock.expect(
        HttpMethod::Get,
        "/certs/missing",
        HttpResponse::new(403).with_body(
            b"<Error><Code>AccessDenied</Code><Message>denied</Message></Error>".to_vec(),
        ),
    );
    let client = S3Client::with_clock(settings(), mock, clock());
    let error = client.get("missing").await.unwrap_err();
    let message = format!("{error}");
    assert!(message.contains("AccessDenied"), "{message}");
    assert!(
        !message.contains("wJalr"),
        "secret must never leak: {message}"
    );
}

#[test]
fn sigv4_signing_is_used_for_s3_requests() {
    // The shared SigV4 signer is covered by its AWS-vector test; this asserts the S3 client uses
    // the `s3` service and `Authorization` header.
    let mock = Arc::new(MockS3::new());
    mock.expect(HttpMethod::Get, "/certs/key", HttpResponse::new(200));
    let client = S3Client::with_clock(settings(), mock.clone(), clock());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(client.get("key")).unwrap();
    let request = mock.requests.lock().unwrap()[0].clone();
    let authorization = request
        .headers
        .iter()
        .find(|(name, _)| name == "Authorization")
        .unwrap()
        .1
        .clone();
    assert!(
        authorization.contains("/us-east-1/s3/aws4_request"),
        "{authorization}"
    );
    assert_eq!(
        request
            .headers
            .iter()
            .find(|(name, _)| name == "X-Amz-Date")
            .unwrap()
            .1,
        "20231114T221320Z"
    );
}

#[tokio::test]
async fn virtual_host_addressing_uses_bucket_host_and_signs_it() {
    let mock = Arc::new(MockS3::new());
    mock.expect(
        HttpMethod::Get,
        "/key.bin",
        HttpResponse::new(200).with_body(b"value".to_vec()),
    );
    let mut settings = settings();
    settings.path_style = false;
    let client = S3Client::with_clock(settings, mock.clone(), clock());
    assert_eq!(
        client.get("key.bin").await.unwrap(),
        Some(b"value".to_vec())
    );
    let request = mock.requests.lock().unwrap()[0].clone();
    assert!(
        request.url.starts_with("https://certs.s3.example.test/"),
        "virtual-host URL: {}",
        request.url
    );
    assert!(mock.last_authorization().is_some());
}

#[test]
fn path_style_and_virtual_host_targets() {
    let mock = Arc::new(MockS3::new());
    let mut settings = settings();
    settings.path_style = true;
    let client = S3Client::with_clock(settings.clone(), mock, clock());
    let (url, host, path) = client.request_target("key.bin", &[]).unwrap();
    assert_eq!(url, "https://s3.example.test/certs/key.bin");
    assert_eq!(host, "s3.example.test");
    assert_eq!(path, "/certs/key.bin");

    settings.path_style = false;
    let client = S3Client::with_clock(settings, Arc::new(MockS3::new()), clock());
    let (url, host, path) = client.request_target("key.bin", &[]).unwrap();
    assert_eq!(url, "https://certs.s3.example.test/key.bin");
    assert_eq!(host, "certs.s3.example.test");
    assert_eq!(path, "/key.bin");
}
