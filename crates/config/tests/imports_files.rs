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
