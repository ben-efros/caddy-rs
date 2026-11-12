//! File/glob imports: resolution relative to the importing file and origin diagnostics.
//!
//! Caddy resolves an `import <file>`/`<glob>` relative to the file that contains the directive and
//! reports errors against the imported file (`sub/extra.caddyfile:3`). The parser carries that
//! filename on its positions and the adapter reports it in located errors.

use std::path::PathBuf;

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "caddy-rs-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create temp dir");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(&path, contents).expect("write fixture");
        path
    }

    fn adapt(&self, caddyfile: &str) -> caddy_rs_core::Result<caddy_rs_core::AdaptedConfig> {
        caddy_rs_config::adapt_with_source(caddyfile, Some(&self.root.join("Caddyfile")))
    }

    fn caddyfile(&self) -> PathBuf {
        self.root.join("Caddyfile")
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn route_handlers<'a>(adapted: &'a caddy_rs_core::AdaptedConfig) -> &'a serde_json::Value {
    &adapted.config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"][0]
        ["handle"]
}

#[test]
fn nested_file_imports_resolve_relative_to_each_file() {
    let tree = TempTree::new("nested-import");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/one.caddyfile\n}\n",
    );
    // `one` imports `two.caddyfile` from its own directory (`sub/`), not from the root.
    tree.write(
        "sub/one.caddyfile",
        "import two.caddyfile\nrespond \"from one\"\n",
    );
    tree.write("sub/two.caddyfile", "header X-Two yes\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree.adapt(&caddyfile).expect("nested imports adapt");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Two": ["yes"]}}},
            {"handler": "static_response", "body": "from one"},
        ])
    );
    // The adapted configuration round-trips through the typed model unchanged and validates.
    let config = caddy_rs_core::Config::from_value(adapted.config.clone()).expect("typed model");
    assert_eq!(config.to_value().expect("serializes"), adapted.config);
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    caddy_rs_core::validate_config(&config, &registry).expect("nested-import config validates");
}

#[test]
fn nested_subdirectory_import_resolves_relative_to_importing_file() {
    let tree = TempTree::new("nested-subdir-import");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/one.caddyfile\n}\n",
    );
    tree.write(
        "sub/one.caddyfile",
        "import deep/two.caddyfile\nrespond \"one\"\n",
    );
    tree.write("sub/deep/two.caddyfile", "header X-Deep yes\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("nested subdirectory imports adapt");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Deep": ["yes"]}}},
            {"handler": "static_response", "body": "one"},
        ])
    );
}

#[test]
fn glob_import_inside_imported_file_resolves_relative_to_it() {
    let tree = TempTree::new("nested-glob-import");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/one.caddyfile\n}\n",
    );
    tree.write(
        "sub/one.caddyfile",
        "import parts/*.caddyfile\nrespond \"done\"\n",
    );
    tree.write("sub/parts/a.caddyfile", "header X-A yes\n");
    tree.write("sub/parts/b.caddyfile", "header X-B yes\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree.adapt(&caddyfile).expect("nested glob imports adapt");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-A": ["yes"]}}},
            {"handler": "headers", "response": {"set": {"X-B": ["yes"]}}},
            {"handler": "static_response", "body": "done"},
        ])
    );
}

#[test]
fn diagnostics_name_the_imported_file_and_line() {
    let tree = TempTree::new("import-diagnostic");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/one.caddyfile\n}\n",
    );
    tree.write("sub/one.caddyfile", "respond \"one\"\n");
    tree.write("sub/two.caddyfile", "bogus_directive here\n");
    tree.write(
        "sub/one.caddyfile",
        "import two.caddyfile\nrespond \"one\"\n",
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("unsupported directive fails loudly");
    let message = error.to_string();
    assert!(message.contains("sub/two.caddyfile:1"), "{message}");
    assert!(message.contains("bogus_directive"), "{message}");
}

#[test]
fn parser_positions_carry_the_imported_filename() {
    let tree = TempTree::new("import-positions");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/one.caddyfile\n}\n",
    );
    tree.write("sub/one.caddyfile", "import two.caddyfile\n");
    tree.write("sub/two.caddyfile", "header X-Two yes\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let parsed =
        caddy_rs_config::parse_with_source(&caddyfile, Some(&tree.caddyfile())).expect("parses");
    let directives = &parsed.sites[0].directives;
    let header = directives
        .iter()
        .find(|directive| directive.name == "header")
        .expect("imported header directive");
    assert_eq!(header.position.label(), "sub/two.caddyfile:1");
}

#[test]
fn missing_import_inside_imported_file_names_the_importing_file() {
    let tree = TempTree::new("import-missing");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/one.caddyfile\n}\n",
    );
    tree.write("sub/one.caddyfile", "\nimport missing.caddyfile\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("missing nested import fails loudly");
    let message = error.to_string();
    assert!(message.contains("sub/one.caddyfile:2"), "{message}");
    assert!(message.contains("missing.caddyfile"), "{message}");
}

#[test]
fn cross_file_import_cycles_are_rejected() {
    let tree = TempTree::new("import-cycle");
    tree.write("Caddyfile", "example.com {\n\timport sub/a.caddyfile\n}\n");
    tree.write("sub/a.caddyfile", "import b.caddyfile\n");
    tree.write("sub/b.caddyfile", "import a.caddyfile\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree.adapt(&caddyfile).expect_err("cycle fails loudly");
    assert!(error.to_string().contains("cycle of imports"), "{error}");
}

#[test]
fn file_import_without_a_source_path_fails_loudly() {
    let error = caddy_rs_config::adapt("example.com {\n\timport missing.caddyfile\n}\n")
        .expect_err("stdin adapt cannot resolve file imports");
    let message = error.to_string();
    assert!(message.contains("File to import not found"), "{message}");
    assert!(message.contains("source"), "{message}");
}

#[test]
fn absolute_file_import_is_allowed() {
    let tree = TempTree::new("absolute-file-import");
    let external = TempTree::new("absolute-file-source");
    let imported = external.write("snippet.conf", "header X-Absolute yes\n");
    tree.write(
        "Caddyfile",
        &format!("example.com {{\n\timport {}\n}}\n", imported.display()),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("an explicit absolute import path must adapt");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Absolute": ["yes"]}}},
        ])
    );
}

#[test]
fn absolute_glob_import_is_allowed() {
    // The reported deployment shape: `import /etc/caddy/host_*.conf`.
    let tree = TempTree::new("absolute-glob-import");
    let external = TempTree::new("absolute-glob-source");
    external.write("host_a.conf", "header X-Host a\n");
    external.write("host_b.conf", "header X-Host b\n");
    let pattern = format!("{}/host_*.conf", external.root.display());
    tree.write(
        "Caddyfile",
        &format!("example.com {{\n\timport {pattern}\n}}\n"),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("an explicit absolute glob import must adapt");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Host": ["a"]}}},
            {"handler": "headers", "response": {"set": {"X-Host": ["b"]}}},
        ])
    );
}

#[test]
fn absolute_directory_import_is_rejected() {
    let tree = TempTree::new("absolute-dir-import");
    let external = TempTree::new("absolute-dir-source");
    let directory = external.root.join("hosts");
    std::fs::create_dir_all(&directory).expect("create directory");
    tree.write(
        "Caddyfile",
        &format!("example.com {{\n\timport {}\n}}\n", directory.display()),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("a directory cannot be imported");
    assert!(error.to_string().contains("is a directory"), "{error}");
}

#[cfg(unix)]
#[test]
fn absolute_import_writable_by_others_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let tree = TempTree::new("absolute-writable-import");
    let external = TempTree::new("absolute-writable-source");
    let imported = external.write("snippet.conf", "header X-Bad yes\n");
    std::fs::set_permissions(&imported, std::fs::Permissions::from_mode(0o666))
        .expect("chmod 0666");
    tree.write(
        "Caddyfile",
        &format!("example.com {{\n\timport {}\n}}\n", imported.display()),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("a group/world-writable import must be rejected");
    assert!(
        error.to_string().contains("writable by group or others"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn relative_import_through_escaping_symlink_is_rejected() {
    let tree = TempTree::new("symlink-escape-import");
    let external = TempTree::new("symlink-escape-source");
    let target = external.write("snippet.conf", "header X-Escape yes\n");
    std::os::unix::fs::symlink(&target, tree.root.join("link.conf")).expect("create symlink");
    tree.write("Caddyfile", "example.com {\n\timport link.conf\n}\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("a symlink out of the Caddyfile directory must be rejected");
    assert!(
        error
            .to_string()
            .contains("escapes the Caddyfile directory through a symbolic link"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn relative_import_through_in_tree_symlink_is_allowed() {
    let tree = TempTree::new("symlink-inside-import");
    tree.write("sub/target.conf", "header X-Symlink yes\n");
    std::os::unix::fs::symlink(
        tree.root.join("sub/target.conf"),
        tree.root.join("link.conf"),
    )
    .expect("create symlink");
    tree.write("Caddyfile", "example.com {\n\timport link.conf\n}\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("a symlink inside the Caddyfile directory is allowed");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Symlink": ["yes"]}}},
        ])
    );
}

#[test]
fn parent_traversal_import_is_rejected() {
    let tree = TempTree::new("traversal-import");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport ../../../etc/passwd\n}\n",
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("traversal import should be rejected");
    let message = error.to_string();
    assert!(
        message.contains("outside") || message.contains("traversal") || message.contains(".."),
        "expected traversal rejection, got: {message}"
    );
}

#[test]
fn traversal_through_child_directory_is_rejected() {
    let tree = TempTree::new("traversal-child-import");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/../../etc/passwd\n}\n",
    );
    tree.write("sub/dummy.conf", "# dummy\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("traversal import through child dir should be rejected");
    let message = error.to_string();
    assert!(
        message.contains("outside") || message.contains("traversal") || message.contains(".."),
        "expected traversal rejection, got: {message}"
    );
}

#[test]
fn legitimate_relative_import_still_works() {
    let tree = TempTree::new("legitimate-import");
    tree.write("Caddyfile", "example.com {\n\timport extra.conf\n}\n");
    tree.write("extra.conf", "header X-Extra yes\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("legitimate import should work");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Extra": ["yes"]}}},
        ])
    );
}

#[test]
fn dot_dot_within_tree_still_works() {
    let tree = TempTree::new("ddot-within-tree");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/../extra.conf\n}\n",
    );
    tree.write("extra.conf", "header X-Extra yes\n");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("self-referential .. should work");
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Extra": ["yes"]}}},
        ])
    );
}

#[test]
fn import_error_does_not_leak_absolute_path() {
    let tree = TempTree::new("sanitize-path");
    tree.write(
        "Caddyfile",
        "example.com {\n\timport sub/bad.caddyfile\n}\n",
    );
    // Write invalid UTF-8 bytes so parsing fails inside the file import path.
    let bad_path = tree.root.join("sub/bad.caddyfile");
    std::fs::create_dir_all(bad_path.parent().unwrap()).expect("create sub dir");
    std::fs::write(&bad_path, &[0x80, 0x81, 0x82]).expect("write bad bytes");
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("invalid utf-8 import should fail");
    let message = error.to_string();
    // Must still mention the relative path so the user knows which file failed.
    assert!(message.contains("sub/bad.caddyfile"), "{message}");
    // Must NOT contain the absolute temp directory path.
    let root_str = tree.root.to_str().expect("valid utf-8 root");
    assert!(!message.contains(root_str), "{message}");
}

#[test]
fn glob_pattern_error_does_not_leak_absolute_path() {
    let tree = TempTree::new("sanitize-glob");
    let root_str = tree.root.to_str().expect("valid utf-8 root").to_string();
    for pattern in ["sub/*/*.caddyfile", "sub/[ab].caddyfile"] {
        tree.write(
            "Caddyfile",
            &format!("example.com {{\n\timport {pattern}\n}}\n"),
        );
        let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
        let error = tree
            .adapt(&caddyfile)
            .expect_err("multi-wildcard glob should be rejected");
        let message = error.to_string();
        assert!(message.contains("Glob pattern"), "{message}");
        // The pattern as written by the user must still be reported.
        assert!(message.contains(pattern), "{message}");
        // The absolute temp directory must not leak into the diagnostic.
        assert!(!message.contains(&root_str), "{message}");
    }
}

#[test]
fn stock_compat_true_allows_parent_directory_imports_like_caddy() {
    let tree = TempTree::new("stock-compat-escape");
    let external = TempTree::new("stock-compat-escape-source");
    external.write("snippet.conf", "header X-Stock yes\n");
    let external_name = external
        .root
        .file_name()
        .expect("external dir name")
        .to_string_lossy()
        .to_string();
    tree.write(
        "Caddyfile",
        &format!(
            "{{\n\tstock_compat true\n}}\nexample.com {{\n\timport ../{external_name}/snippet.conf\n}}\n"
        ),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let adapted = tree
        .adapt(&caddyfile)
        .expect("stock_compat true must permit a `..` import like Caddy");
    assert_eq!(
        adapted.config["stock_compat"],
        serde_json::json!(true),
        "the adapter must emit the switch it applied"
    );
    assert_eq!(
        route_handlers(&adapted),
        &serde_json::json!([
            {"handler": "headers", "response": {"set": {"X-Stock": ["yes"]}}},
        ])
    );
}

#[cfg(unix)]
#[test]
fn stock_compat_true_allows_world_writable_absolute_imports() {
    use std::os::unix::fs::PermissionsExt;
    let tree = TempTree::new("stock-compat-writable");
    let external = TempTree::new("stock-compat-writable-source");
    let imported = external.write("snippet.conf", "header X-Writable yes\n");
    std::fs::set_permissions(&imported, std::fs::Permissions::from_mode(0o666))
        .expect("chmod 0666");
    tree.write(
        "Caddyfile",
        &format!(
            "{{\n\tstock_compat true\n}}\nexample.com {{\n\timport {}\n}}\n",
            imported.display()
        ),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    tree.adapt(&caddyfile)
        .expect("stock_compat true must not apply the safe-mode permission rule");
}

#[test]
fn stock_compat_false_keeps_the_strict_import_policy() {
    let tree = TempTree::new("stock-compat-strict");
    let external = TempTree::new("stock-compat-strict-source");
    external.write("snippet.conf", "header X-Nope yes\n");
    let external_name = external
        .root
        .file_name()
        .expect("external dir name")
        .to_string_lossy()
        .to_string();
    tree.write(
        "Caddyfile",
        &format!(
            "{{\n\tstock_compat false\n}}\nexample.com {{\n\timport ../{external_name}/snippet.conf\n}}\n"
        ),
    );
    let caddyfile = std::fs::read_to_string(tree.caddyfile()).expect("read root");
    let error = tree
        .adapt(&caddyfile)
        .expect_err("stock_compat false keeps the default containment rule");
    assert!(
        error
            .to_string()
            .contains("Import path escapes the Caddyfile directory"),
        "{error}"
    );
}

#[test]
fn stock_compat_option_parses_all_documented_forms() {
    for (input, expected) in [
        ("{\n\tstock_compat\n}\n", Some(true)),
        ("{\n\tstock_compat true\n}\n", Some(true)),
        ("{\n\tstock_compat false\n}\n", None),
    ] {
        let adapted = caddy_rs_config::adapt(&format!("{input}:80 {{\n\trespond ok\n}}\n"))
            .expect("stock_compat option form must adapt");
        assert_eq!(
            adapted.config.get("stock_compat").cloned(),
            expected.map(|value| serde_json::json!(value)),
            "unexpected stock_compat output for {input:?}"
        );
    }
}

#[test]
fn malformed_stock_compat_option_fails_with_a_located_error() {
    for (input, needle) in [
        (
            "{\n\tstock_compat {\n\t\tfoo\n\t}\n}\n:80 {\n\trespond ok\n}\n",
            "does not take a block",
        ),
        (
            "{\n\tstock_compat true false\n}\n:80 {\n\trespond ok\n}\n",
            "wrong argument count",
        ),
        (
            "{\n\tstock_compat yes\n}\n:80 {\n\trespond ok\n}\n",
            "must be 'true' or 'false'",
        ),
    ] {
        let error = caddy_rs_config::adapt(input).expect_err("malformed stock_compat is rejected");
        let message = error.to_string();
        assert!(message.contains("stock_compat"), "{message}");
        assert!(message.contains(needle), "{message}");
        assert!(
            message.contains("line"),
            "expected a located error: {message}"
        );
    }
}

#[test]
fn stock_compat_round_trips_through_the_typed_config() {
    let adapted = caddy_rs_config::adapt("{\n\tstock_compat true\n}\n:80 {\n\trespond ok\n}\n")
        .expect("stock_compat adapts");
    let config = caddy_rs_core::Config::from_value(adapted.config.clone()).expect("decode config");
    assert!(config.stock_compat());
    assert_eq!(
        config.to_value().expect("encode config"),
        adapted.config,
        "the typed model must round-trip the switch"
    );
    let registry = caddy_rs_core::ModuleRegistry::builtin();
    caddy_rs_core::validate_config(&config, &registry).expect("stock_compat config validates");
}

#[test]
fn stock_compat_must_be_a_boolean_in_json() {
    for value in [
        serde_json::json!("true"),
        serde_json::json!(1),
        serde_json::json!(null),
    ] {
        let error = caddy_rs_core::Config::from_value(serde_json::json!({"stock_compat": value}))
            .expect_err("a non-boolean stock_compat must be rejected");
        assert!(
            error.to_string().contains("stock_compat"),
            "the error must name the field: {error}"
        );
    }
}

#[test]
fn duplicate_stock_compat_option_is_rejected() {
    // The policy is detected from the first occurrence; a second occurrence must not let the
    // parsed value and the enforced policy disagree (security review F1).
    for input in [
        "{\n\tstock_compat true\n\tstock_compat false\n}\n:80 {\n\trespond ok\n}\n",
        "{\n\tstock_compat false\n\tstock_compat true\n}\n:80 {\n\trespond ok\n}\n",
    ] {
        let error = caddy_rs_config::adapt(input).expect_err("duplicate stock_compat is rejected");
        assert!(
            error.to_string().contains("specified more than once"),
            "{error}"
        );
    }
}

#[cfg(unix)]
#[test]
fn stdin_absolute_import_requires_root_ownership() {
    let external = TempTree::new("stdin-owner-source");
    let imported = external.write("snippet.conf", "header X-Stdin yes\n");
    // Root-owned file: the owner anchor is unknown when adapting stdin, so the strict default
    // (root-owned) applies and the import is accepted.
    caddy_rs_config::adapt(&format!(":80 {{\n\timport {}\n}}\n", imported.display()))
        .expect("a root-owned absolute import from stdin adapts");
    // A third-uid file cannot be anchored to an importing Caddyfile owner, so it is rejected
    // instead of silently skipping the ownership rule (security review F2).
    if std::os::unix::fs::chown(&imported, Some(12345), Some(12345)).is_ok() {
        let error =
            caddy_rs_config::adapt(&format!(":80 {{\n\timport {}\n}}\n", imported.display()))
                .expect_err("a non-root-owned absolute import from stdin is rejected");
        assert!(
            error.to_string().contains("must be owned by root"),
            "{error}"
        );
        let _ = std::os::unix::fs::chown(&imported, Some(0), Some(0));
    }
}
