//! Adapt a Caddyfile and print the resulting Caddy JSON. Usage: `cargo run -p caddy-rs-config --example adapt -- FILE`.

use caddy_rs_core::ConfigAdapter;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: adapt <Caddyfile>");
        return ExitCode::from(2);
    };
    let input = match std::fs::read(&path) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("cannot read `{path}`: {error}");
            return ExitCode::FAILURE;
        }
    };
    match caddy_rs_config::CaddyfileAdapter.adapt(&input) {
        Ok(adapted) => {
            match serde_json::to_string_pretty(&adapted.config) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("cannot serialize adapted config: {error}");
                    return ExitCode::FAILURE;
                }
            }
            for warning in adapted.warnings {
                eprintln!("warning: {warning}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("adapt failed: {error}");
            ExitCode::FAILURE
        }
    }
}
