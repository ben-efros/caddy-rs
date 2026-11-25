//! Request-path validation corpus for `file_server`.
//!
//! These vectors come from a survey of how other Rust web servers validate request paths and from
//! the path-traversal advisories filed against them. Each table row says what *this* server must
//! answer; the comment names the project and test the vector comes from, and says where our policy
//! is deliberately different (we follow Caddy: a `..` component is refused with 403 rather than
//! clamped or ignored).
//!
//! Sources (the vectors are facts about inputs and outcomes, rewritten here, not copied code; the
//! licences and the attribution are listed in `NOTICE.md`):
//!
//! * tower-http `ServeDir` (MIT): `services/fs/serve_dir/tests.rs`, `build_and_validate_path`, the
//!   Windows reserved-device-name tests, and RUSTSEC-2022-0043 / GHSA-wwh2-r387-g5rm.
//! * hyper-staticfile (MIT): `tests/static.rs` and RUSTSEC-2022-0069.
//! * warp `fs::sanitize_path` (MIT): RUSTSEC-2022-0082.
//! * actix-files (MIT OR Apache-2.0): `path_buf.rs` (`PathBufWrap`) tests.
//! * static-web-server (MIT OR Apache-2.0): `handle_*` and the short-name alias tests.
//! * Rocket `Segments::to_path_buf` (MIT OR Apache-2.0) segment rules.
//!
//! Every vector is also sent as `HEAD`, which must produce the same status as `GET`.
//!
//! The Windows-only table runs on Windows hosts; the pure-function tables in
//! `file_server.rs` run the same Windows rules on every platform.

use std::path::Path;

use caddy_rs_http::file_server::FileServerHandler;
use caddy_rs_http::{Handler, Outcome, Request};
use http::Method;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// 200 with the file (or the directory's index).
    Served,
    /// 404.
    NotFound,
    /// 403.
    Forbidden,
    /// 308 with exactly this `Location`.
    Redirect(&'static str),
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture directory");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "index.html", "root index");
    write(root, "file.txt", "file");
    write(root, "has space.txt", "space");
    write(root, "\u{4f60}\u{597d}\u{4e16}\u{754c}.txt", "cjk");
    write(root, "report~1.txt", "tilde");
    write(root, "a~b/file.txt", "tilde dir");
    write(root, "secret.env", "TOP SECRET");
    // A file whose name differs from the `hide *.env` pattern only in case: hidden where the file
    // system or the comparison is case-insensitive (Windows, macOS), an ordinary file where names
    // are case-sensitive. A vector for this must exist as a real file, or a 404 proves nothing.
    write(root, "Mixed.ENV", "MIXED CASE");
    write(root, ".dotfile", "dotfile");
    write(root, "sub/index.html", "sub index");
    write(root, "sub/page.html", "page");
    write(root, "foo.org/bar/index.html", "foo.org bar");
    // Names that look reserved or special on Windows but are ordinary and must still be served.
    write(root, "COM10.txt", "com10");
    write(root, "NULL.txt", "null");
    write(root, "CONIN.txt", "conin");
    write(root, "contact.html", "contact");
    dir
}

fn handler(root: &Path) -> FileServerHandler {
    FileServerHandler::from_json(
        &serde_json::json!({
            "handler": "file_server",
            "root": root,
            // Caddy semantics: dotfiles are served unless hidden; hide the secrets explicitly.
            "hide": ["*.env"]
        }),
        "handler",
    )
    .expect("handler")
}

async fn answer(handler: &FileServerHandler, method: Method, path: &str) -> (u16, Option<String>) {
    let request = Request::new(method, path.parse().expect("request target"));
    match handler.handle(request).await {
        Ok(Outcome::Respond(response)) => (
            response.status.as_u16(),
            response
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        ),
        Ok(Outcome::Continue(_)) => panic!("{path}: file_server passed the request on"),
        Err(error) => panic!("{path}: the handler failed instead of answering: {error}"),
    }
}

async fn check(handler: &FileServerHandler, vectors: &[(&str, Expect)]) {
    let mut failures = Vec::new();
    for (path, expect) in vectors {
        let (status, location) = answer(handler, Method::GET, path).await;
        let ok = match expect {
            Expect::Served => status == 200,
            Expect::NotFound => status == 404,
            Expect::Forbidden => status == 403,
            Expect::Redirect(target) => status == 308 && location.as_deref() == Some(*target),
        };
        if !ok {
            failures.push(format!(
                "GET {path}: expected {expect:?}, got {status} (location {location:?})"
            ));
        }
        // HEAD must be refused or served exactly like GET.
        let (head_status, _) = answer(handler, Method::HEAD, path).await;
        if head_status != status {
            failures.push(format!(
                "HEAD {path}: status {head_status} differs from GET {status}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} path-validation vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Vectors whose answer is the same on every platform.
#[tokio::test]
async fn common_vectors() {
    let dir = fixture();
    let handler = handler(dir.path());
    let long_component = format!("/{}", "a".repeat(300));
    let mut vectors: Vec<(&str, Expect)> = vec![
        // Ordinary names, encoded names.
        ("/file.txt", Expect::Served),
        ("/", Expect::Served), // hyper-staticfile: index of the root
        ("/has%20space.txt", Expect::Served), // hyper decodes_percent_notation; tower-http access_space
        ("/%E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C.txt", Expect::Served), // tower-http access_cjk
        ("/report~1.txt", Expect::Served), // static-web-server short_name_check_serves_names_with_tilde
        ("/a~b/file.txt", Expect::Served),
        ("/.dotfile", Expect::Served), // Caddy serves dotfiles; Rocket/actix/SWS hide them by default (documented)
        // Parent references, every encoding. We refuse (403) where others clamp or ignore.
        ("/%2e%2e/secret", Expect::Forbidden),
        ("/%2E%2E/%2e%2e/etc/passwd", Expect::Forbidden), // hyper-staticfile clamps; we refuse
        ("/../README.md", Expect::Forbidden), // actix path_traversal serves README.md; warp 404; we refuse
        ("/xxx/../file.txt", Expect::Forbidden), // hyper normalizes_path serves it; we refuse
        ("/xxx/..%2ffile.txt", Expect::Forbidden), // hyper normalizes_percent_encoded_path
        ("/a/%2E%2E/b", Expect::Forbidden),   // Rocket segment rule, own vector
        ("/..%2f..%2fetc%2fpasswd", Expect::Forbidden),
        // Double decoding is never performed: the literal text `%2e%2e` is just a file name.
        ("/%252e%252e/secret", Expect::NotFound), // fiber GHSA-m3c2-496v-cw3v class
        ("/%252e%252e%252fsecret", Expect::NotFound),
        // Encoded separator is a real separator (hyper, warp, tower-http); actix rejects it.
        ("/sub%2Fpage.html", Expect::Served),
        ("/sub%2Fmissing.html", Expect::NotFound),
        // NUL and invalid UTF-8.
        ("/invalid-path%00", Expect::Forbidden), // tower-http calls_fallback_on_null (they fall back)
        ("/file.txt%00.jpg", Expect::Forbidden),
        ("/weird_%c3%28_path", Expect::NotFound), // tower-http calls_fallback_on_invalid_paths
        ("/%ff", Expect::NotFound),
        ("/%c0%ae%c0%ae/secret", Expect::NotFound), // overlong encoding of `..` must not become `..`
        // A file used as a directory, and names the OS refuses, are 404, never a server error.
        ("/index.html/some_file", Expect::NotFound), // tower-http not_found_when_not_a_directory
        ("/file.txt/x/y/z", Expect::NotFound),
        // Hidden files and the case-insensitivity of the comparison.
        ("/secret.env", Expect::NotFound),
        ("/SECRET.ENV", Expect::NotFound),
        ("/sub/../secret.env", Expect::Forbidden),
        // Directory redirects.
        ("/sub", Expect::Redirect("/sub/")), // hyper redirects_if_trailing_slash_is_missing; actix
        ("/sub/", Expect::Served),
        // No open redirect: a leading `//` must not become a protocol-relative Location.
        ("//foo.org/bar", Expect::Redirect("/foo.org/bar/")), // hyper redirects_to_sanitized_path
        ("///foo.org/bar", Expect::Redirect("/foo.org/bar/")),
        // Names that merely resemble Windows specials are ordinary files everywhere.
        ("/COM10.txt", Expect::Served),
        ("/NULL.txt", Expect::Served),
        ("/CONIN.txt", Expect::Served),
        ("/contact.html", Expect::Served),
    ];
    vectors.push((long_component.as_str(), Expect::NotFound));
    // `hide *.env` against a real file named `Mixed.ENV`: hidden exactly when hide comparison is
    // case-insensitive on this platform.
    let mixed_case = if cfg!(any(windows, target_os = "macos")) {
        Expect::NotFound
    } else {
        Expect::Served
    };
    vectors.push(("/Mixed.ENV", mixed_case));
    check(&handler, &vectors).await;
}

/// On Unix `\` and `:` are ordinary file-name bytes: a request is not refused for containing them,
/// and a file that really has such a name is served.
#[cfg(unix)]
#[tokio::test]
async fn unix_treats_backslash_and_colon_as_name_bytes() {
    let dir = fixture();
    write(dir.path(), "back\\slash.txt", "backslash");
    write(dir.path(), "col:on.txt", "colon");
    let handler = handler(dir.path());
    check(
        &handler,
        &[
            ("/back%5cslash.txt", Expect::Served),
            ("/col%3Aon.txt", Expect::Served),
            // No such files: plain 404, not a traversal refusal.
            ("/..%5csecret", Expect::NotFound),
            ("/C:/windows/win.ini", Expect::NotFound), // tower-http reject_windows_drive_prefixed_path
            ("/anypath/c%3A/windows/win.ini", Expect::NotFound),
            ("/f%3A%3A%24DATA", Expect::NotFound),
            ("/CON", Expect::NotFound),
            ("/a%2A", Expect::NotFound),
        ],
    )
    .await;
}

/// A symlink below the root is refused; the root itself may be a symlink (the usual release
/// layout), and a symlink out of the root never leaks the target.
#[cfg(unix)]
#[tokio::test]
async fn symlink_policy() {
    let outside = tempfile::tempdir().expect("outside");
    write(outside.path(), "leak.txt", "LEAKED");
    let dir = fixture();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).expect("symlink dir");
    std::os::unix::fs::symlink(outside.path().join("leak.txt"), dir.path().join("leak.txt"))
        .expect("symlink file");
    let handler = handler(dir.path());
    check(
        &handler,
        &[
            ("/escape/leak.txt", Expect::Forbidden), // static-web-server handle_follow_symlinks
            ("/leak.txt", Expect::Forbidden),
            ("/file.txt", Expect::Served),
        ],
    )
    .await;

    // A symlinked *root* is how releases are usually deployed (`current -> releases/<id>`).
    let parent = tempfile::tempdir().expect("parent");
    std::os::unix::fs::symlink(dir.path(), parent.path().join("current")).expect("symlink root");
    let rooted = self::handler(&parent.path().join("current"));
    check(
        &rooted,
        &[
            ("/file.txt", Expect::Served),
            ("/sub/page.html", Expect::Served),
            ("/escape/leak.txt", Expect::Forbidden),
        ],
    )
    .await;
}

/// Windows vectors: drive prefixes, UNC, ADS, trailing dots, reserved device names and the
/// characters the file system cannot hold. Runs only on a Windows host; the same rules are covered
/// on every platform by the `windows = true` tables in `file_server.rs`.
#[cfg(windows)]
#[tokio::test]
async fn windows_vectors() {
    let dir = fixture();
    let handler = handler(dir.path());
    check(
        &handler,
        &[
            // Backslash and drive/UNC/rooted prefixes (RUSTSEC-2022-0069, -0043, -0082).
            ("/..%5csecret", Expect::Forbidden),
            ("/x%5c..%5cy", Expect::Forbidden),
            ("/C:/Windows/win.ini", Expect::Forbidden), // tower-http reject_windows_drive_prefixed_path
            ("/c:win.ini", Expect::Forbidden),
            ("/C:test.txt", Expect::Forbidden), // actix windows_drive_traversal
            ("/C:../whatever", Expect::Forbidden),
            ("/:test.txt", Expect::Forbidden),
            (
                "/foo/bar/c:/windows/web/screen/img101.png",
                Expect::Forbidden,
            ), // RUSTSEC-2022-0069
            ("/anypath/c%3A/windows/win.ini", Expect::Forbidden), // tower-http percent-encoded drive
            ("/%5cWindows/win.ini", Expect::Forbidden),
            ("/%5c%5chost%5cshare%5cf", Expect::Forbidden),
            // Alternate data streams and Win32 name normalisation.
            ("/f%3A%3A%24DATA", Expect::Forbidden),
            ("/file.txt%3Astream", Expect::Forbidden),
            ("/secret.env.", Expect::Forbidden),
            ("/secret.env%20", Expect::Forbidden),
            // Reserved device names, with and without extension, any case, superscript digits.
            ("/CON", Expect::NotFound),
            ("/con", Expect::NotFound),
            ("/NUL", Expect::NotFound),
            ("/aux.txt", Expect::NotFound),
            ("/AUX.tar.gz", Expect::NotFound),
            ("/dir/com1", Expect::NotFound),
            ("/com%C2%B9", Expect::NotFound),
            ("/lpt9", Expect::NotFound),
            ("/CONIN$", Expect::NotFound),
            ("/CONOUT$", Expect::NotFound),
            ("/%63on", Expect::NotFound),
            ("/NUL%20%20.txt", Expect::NotFound),
            // Characters Windows cannot store: not found, never a 500.
            ("/a%2A", Expect::NotFound), // actix BadStart('*')
            ("/a%3F", Expect::NotFound),
            ("/x%3C", Expect::NotFound), // actix BadEnd('<')
            ("/x%3E", Expect::NotFound), // actix BadEnd('>')
            ("/x%22", Expect::NotFound),
            ("/x%7C", Expect::NotFound), // tower-http calls_fallback_on_invalid_filenames
            ("/x%01", Expect::NotFound),
            // Still served.
            ("/COM10.txt", Expect::Served),
            ("/NULL.txt", Expect::Served),
            ("/CONIN.txt", Expect::Served),
            ("/contact.html", Expect::Served),
            ("/report~1.txt", Expect::Served),
        ],
    )
    .await;
}

/// An 8.3 short name must not reach a file that `hide` covers (static-web-server's short-name
/// alias tests; needs a volume with short-name generation enabled, otherwise the test is skipped).
#[cfg(windows)]
#[tokio::test]
async fn windows_short_name_alias_cannot_bypass_hide() {
    let dir = fixture();
    write(dir.path(), "longsecretfilename.env", "TOP SECRET");
    let long = dir.path().join("longsecretfilename.env");
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(New-Object -ComObject Scripting.FileSystemObject).GetFile('{}').ShortName",
                long.display()
            ),
        ])
        .output()
        .expect("run powershell");
    let short = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if short.is_empty() || short.eq_ignore_ascii_case("longsecretfilename.env") {
        eprintln!("8.3 short names are disabled on this volume; skipping");
        return;
    }
    let handler = handler(dir.path());
    check(
        &handler,
        &[
            ("/longsecretfilename.env", Expect::NotFound),
            (&format!("/{short}"), Expect::NotFound),
            (&format!("/{}", short.to_lowercase()), Expect::NotFound),
        ],
    )
    .await;
}

/// A directory junction inside the root that points outside it must not be followed.
#[cfg(windows)]
#[tokio::test]
async fn windows_junction_is_refused() {
    let outside = tempfile::tempdir().expect("outside");
    write(outside.path(), "leak.txt", "LEAKED");
    let dir = fixture();
    let junction = dir.path().join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(outside.path())
        .output()
        .expect("run mklink");
    assert!(status.status.success(), "mklink /J failed: {status:?}");
    let handler = handler(dir.path());
    check(
        &handler,
        &[
            ("/junction/leak.txt", Expect::Forbidden),
            ("/file.txt", Expect::Served),
        ],
    )
    .await;
}
