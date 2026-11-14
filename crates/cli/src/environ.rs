//! `environ`: print the process environment the way Caddy's `environ` command does.
//!
//! Caddy prints five `caddy.*` fields, seven `runtime.*`/`os.*` facts, a blank line, and then every
//! environment variable. The field names are preserved so scripts that inspect a Caddy process keep
//! working, but the values are the caddy-rs equivalents: `runtime.Version` is the rustc version,
//! `runtime.Compiler` is `rustc`, and `runtime.GOARCH` is Rust's architecture name. See the
//! `docs/compatibility` notes for the deliberate `.caddy-rs` data/config-directory convention.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::build_info::RUSTC_VERSION;

/// Load every `--envfile`, then print the environment.
pub(crate) fn run(envfiles: &[PathBuf]) -> Result<()> {
    for envfile in envfiles {
        load_env_file(envfile).with_context(|| "loading additional environment variables")?;
    }
    print_environment();
    Ok(())
}

/// Parse one `KEY=VALUE` file and set variables that are not already present.
///
/// This mirrors `cmd/commandfuncs.go` in the oracle: the file may contain comments, `export `
/// prefixes, quoted multi-line values, and `#` comments after values. Existing process variables
/// are never overwritten.
fn load_env_file(path: &Path) -> Result<()> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        anyhow::anyhow!(
            "reading environment file: open {}: {}",
            path.display(),
            io_error_text(&error)
        )
    })?;
    let variables = parse_env_file(&contents).with_context(|| "parsing environment file")?;
    for (key, value) in variables {
        if std::env::var_os(&key).is_none() {
            std::env::set_var(&key, &value);
        }
    }
    Ok(())
}

/// Render an I/O error with Go's lowercase wording, keeping the affected path elsewhere.
pub(crate) fn io_error_text(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => error.to_string(),
    }
}

/// Parse Caddy's `KEY=VALUE` environment-file dialect.
fn parse_env_file(input: &str) -> Result<Vec<(String, String)>> {
    let lines: Vec<&str> = input.lines().collect();
    let mut variables = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let mut line = lines[index].trim().to_string();
        index += 1;
        let line_number = index;

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            bail!("can't parse line {line_number}; line should be in KEY=VALUE format");
        };
        let mut key = key.to_string();
        let mut value = value.to_string();

        // Sometimes keys are prefixed by "export " so the file can be sourced in bash.
        if let Some(unprefixed) = key.strip_prefix("export ") {
            key = unprefixed.to_string();
        }
        if key.is_empty() {
            bail!("missing or empty key on line {line_number}");
        }
        if key.contains(' ') {
            bail!("invalid key on line {line_number}: contains whitespace: {key}");
        }
        if value.starts_with(' ') || value.starts_with('\t') {
            bail!("invalid value on line {line_number}: whitespace before value: '{value}'");
        }

        // Remove any trailing comment after the value.
        if let Some((before_comment, _)) = value.split_once('#') {
            value = before_comment.trim_end_matches([' ', '\t']).to_string();
        }

        // Quoted values may span lines; the oracle's loop condition inspects the original line,
        // not the comment-stripped value, so preserve that behaviour here.
        if let Some(quote) = value
            .chars()
            .next()
            .filter(|quote| *quote == '"' || *quote == '\'')
        {
            let escaped = format!("\\{quote}");
            let quote_text = quote.to_string();
            while !line.ends_with(quote) || line.ends_with(&escaped) {
                value = value.replace(&escaped, &quote_text);
                if index >= lines.len() {
                    break;
                }
                let next = lines[index].replace(&escaped, &quote_text);
                index += 1;
                line = next.clone();
                value.push('\n');
                value.push_str(&next);
            }
            value = value.strip_prefix(quote).unwrap_or(&value).to_string();
            value = value.strip_suffix(quote).unwrap_or(&value).to_string();
        }

        // Caddy parses the file into a map, so a later duplicate key replaces the earlier
        // value. Keep the first position (deterministic output) but the last value.
        match variables.iter().position(|(existing, _)| existing == &key) {
            Some(position) => variables[position].1 = value,
            None => variables.push((key, value)),
        }
    }

    Ok(variables)
}

/// The user's home directory, using the same fallbacks as Caddy's `caddy.HomeDir()`.
fn home_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        return PathBuf::from(home);
    }
    if cfg!(windows) {
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let mut home = PathBuf::from(drive);
            home.push(path);
            return home;
        }
        if let Some(profile) = std::env::var_os("USERPROFILE").filter(|home| !home.is_empty()) {
            return PathBuf::from(profile);
        }
    }
    PathBuf::from(".")
}

/// The Rust analogue of Caddy's `runtime.NumCPU()` / default `runtime.GOMAXPROCS(0)`.
fn parallelism() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

fn print_environment() {
    println!("caddy.HomeDir={}", home_dir().display());
    println!(
        "caddy.AppDataDir={}",
        caddy_rs_admin::pki::resolve_data_dir(None, None).display()
    );
    println!(
        "caddy.AppConfigDir={}",
        caddy_rs_core::autosave::config_dir().display()
    );
    println!(
        "caddy.ConfigAutosavePath={}",
        caddy_rs_core::autosave::default_autosave_path().display()
    );
    println!("caddy.Version={}", caddy_rs_core::VERSION);
    println!("runtime.GOOS={}", std::env::consts::OS);
    println!("runtime.GOARCH={}", std::env::consts::ARCH);
    println!("runtime.Compiler=rustc");
    println!("runtime.NumCPU={}", parallelism());
    println!("runtime.GOMAXPROCS={}", parallelism());
    println!("runtime.Version={RUSTC_VERSION}");
    match std::env::current_dir() {
        Ok(directory) => println!("os.Getwd={}", directory.display()),
        Err(error) => println!("os.Getwd=<error: {error}>"),
    }
    println!();
    for (key, value) in std::env::vars_os() {
        println!("{}={}", key.to_string_lossy(), value.to_string_lossy());
    }
}

#[cfg(test)]
mod tests {
    use super::parse_env_file;

    #[test]
    fn parser_matches_caddys_env_file_dialect() {
        let variables = parse_env_file(
            "# comment\n\
             export EXPORTED=value\n\
             PLAIN=value # trailing comment\n\
             QUOTED=\"line one\nline two\"\n",
        )
        .expect("parse");
        assert_eq!(
            variables,
            vec![
                ("EXPORTED".to_string(), "value".to_string()),
                ("PLAIN".to_string(), "value".to_string()),
                ("QUOTED".to_string(), "line one\nline two".to_string()),
            ]
        );
    }

    #[test]
    fn parser_last_duplicate_key_wins() {
        let variables = parse_env_file("DUP=first\nDUP=second\n").expect("parse");
        assert_eq!(
            variables,
            vec![("DUP".to_string(), "second".to_string())],
            "Caddy parses into a map, so the last duplicate must win"
        );
    }

    #[test]
    fn parser_reports_the_line_and_reason() {
        let error = parse_env_file("GOOD=1\nNOT_A_PAIR\n").expect_err("invalid line");
        assert!(error.to_string().contains("line 2"), "{error}");
        assert!(error.to_string().contains("KEY=VALUE"), "{error}");

        let error = parse_env_file("=value\n").expect_err("empty key");
        assert!(error.to_string().contains("line 1"), "{error}");
        assert!(error.to_string().contains("empty key"), "{error}");
    }
}
