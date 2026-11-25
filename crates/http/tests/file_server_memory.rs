//! SEC-MEDIUM-HTTP B2: serving a file must not read it into memory per request.
//!
//! These tests measure the process-wide peak resident set size (`VmHWM`, reset through
//! `/proc/self/clear_refs`), so they live in their own integration-test binary (no unrelated test
//! shares the process) and serialise on a mutex (the two tests do not share the counters with
//! each other). They are Linux-only and skip with a printed note when `clear_refs` is not
//! writable (containers, restricted `/proc`). `rss_meter_detects_a_buffered_read` calibrates the
//! meter: if it cannot see a deliberate allocation of the same magnitude, the other tests would
//! pass vacuously, so that test fails instead.

#![cfg(target_os = "linux")]

use caddy_rs_http::{Request, ResponseOutcome, Router, RouterBuilder};
use http::{header, Method, StatusCode};
use http_body_util::BodyExt;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Growth of the process peak RSS must stay below this. The file sizes below are far larger, so a
/// whole-file read cannot hide inside it.
const BUDGET_KIB: u64 = 192 * 1024;

/// Reset the peak-RSS high-water mark; `false` when the kernel does not allow it here.
fn reset_peak_rss() -> bool {
    std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM")
}

/// Run `measured` and return how much the peak RSS grew while it ran.
async fn growth_of<F: std::future::Future>(measured: F) -> (F::Output, u64) {
    assert!(reset_peak_rss());
    let before = peak_rss_kib();
    let output = measured.await;
    (output, peak_rss_kib().saturating_sub(before))
}

fn skip_unless_measurable(test: &str) -> bool {
    if reset_peak_rss() {
        return false;
    }
    eprintln!("{test}: skipped, /proc/self/clear_refs is not writable here");
    true
}

fn sparse_file(dir: &std::path::Path, name: &str, len: u64) {
    let file = std::fs::File::create(dir.join(name)).unwrap();
    file.set_len(len).unwrap();
}

fn router(root: &std::path::Path) -> Router {
    let routes = serde_json::json!([{ "handle": [{
        "handler": "file_server", "root": root.to_string_lossy(), "hide": []
    }]}]);
    RouterBuilder::new()
        .build(routes.as_array().unwrap())
        .expect("routes build")
}

async fn send(router: &Router, request: Request) -> caddy_rs_http::StreamingResponse {
    match router.handle_upgradable(request).await.unwrap() {
        ResponseOutcome::Response(response) => response,
        ResponseOutcome::Upgrade(_) => panic!("unexpected upgrade"),
    }
}

/// Calibration: a deliberate 300 MiB allocation must register above the budget. If this fails the
/// meter is blind and the tests below prove nothing.
#[tokio::test]
async fn rss_meter_detects_a_buffered_read() {
    let _serial = SERIAL.lock().await;
    if skip_unless_measurable("rss_meter_detects_a_buffered_read") {
        return;
    }
    let (buffer, growth) = growth_of(async { vec![1u8; 300 << 20] }).await;
    assert_eq!(buffer.len(), 300 << 20);
    assert!(
        growth > BUDGET_KIB,
        "the RSS meter did not see a 300 MiB allocation (grew {growth} KiB)"
    );
}

#[tokio::test]
async fn range_head_and_not_modified_of_a_huge_file_do_not_load_it() {
    const GIB: u64 = 1 << 30;
    let _serial = SERIAL.lock().await;
    if skip_unless_measurable("range_head_and_not_modified_of_a_huge_file_do_not_load_it") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    sparse_file(dir.path(), "huge.bin", GIB);
    let router = router(dir.path());

    // A 1-byte range.
    let mut request = Request::new(Method::GET, "/huge.bin".parse().unwrap());
    request.headers.insert(
        header::RANGE,
        "bytes=1073741823-1073741823".parse().unwrap(),
    );
    let (response, range_growth) = growth_of(async {
        let response = send(&router, request).await;
        let status = response.status;
        let headers = response.headers.clone();
        let body = response.body.into_bytes().await.unwrap();
        (status, headers, body)
    })
    .await;
    assert_eq!(response.0, StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.2.len(), 1);

    // HEAD reports the full length without a body.
    let request = Request::new(Method::HEAD, "/huge.bin".parse().unwrap());
    let (head, head_growth) = growth_of(async {
        let response = send(&router, request).await;
        (response.status, response.headers)
    })
    .await;
    assert_eq!(head.0, StatusCode::OK);
    assert_eq!(
        head.1
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap(),
        GIB.to_string()
    );

    // A satisfied conditional request is a bodyless 304.
    let etag = head.1.get(header::ETAG).expect("etag").clone();
    let mut request = Request::new(Method::GET, "/huge.bin".parse().unwrap());
    request.headers.insert(header::IF_NONE_MATCH, etag);
    let (status, not_modified_growth) =
        growth_of(async { send(&router, request).await.status }).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);

    assert!(
        range_growth < BUDGET_KIB && head_growth < BUDGET_KIB && not_modified_growth < BUDGET_KIB,
        "the file was read into memory: peak RSS grew by range={range_growth} KiB, \
         head={head_growth} KiB, not_modified={not_modified_growth} KiB"
    );
}

/// A full GET of a large file is delivered in chunks, never buffered.
#[tokio::test]
async fn large_full_get_is_streamed_not_buffered() {
    const LEN: u64 = 512 << 20;
    let _serial = SERIAL.lock().await;
    if skip_unless_measurable("large_full_get_is_streamed_not_buffered") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    sparse_file(dir.path(), "big.bin", LEN);
    let router = router(dir.path());

    let request = Request::new(Method::GET, "/big.bin".parse().unwrap());
    let (received, growth) = growth_of(async {
        let response = send(&router, request).await;
        assert_eq!(response.status, StatusCode::OK);
        let mut body = Box::pin(response.body);
        let mut received = 0u64;
        while let Some(frame) = body.frame().await {
            if let Some(data) = frame.expect("body frame").data_ref() {
                received += data.len() as u64;
            }
        }
        received
    })
    .await;
    assert_eq!(received, LEN);
    assert!(
        growth < BUDGET_KIB,
        "a {LEN}-byte file was buffered: peak RSS grew by {growth} KiB"
    );
}
