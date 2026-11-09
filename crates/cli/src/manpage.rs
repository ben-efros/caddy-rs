//! `manpage`: generate section-8 roff manual pages from the clap command tree.
//!
//! Caddy uses cobra's `doc.GenManTree` with `Title: "Caddy"` and `Section: "8"`, writing one page
//! per command into `--directory` (created when missing), and fails with `ExitCodeFailedQuit` when
//! the directory is empty. `clap_mangen` is not available in this offline build, so the pages are
//! rendered here from the same clap definition the parser uses. The output is plain, valid roff:
//! `.TH`, `.SH`, `.TP` and `.B` macros only.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Arg, ArgAction, Command, CommandFactory};

use crate::Cli;

/// Write the root page and one page for every visible subcommand.
pub(crate) fn write(directory: Option<&str>) -> Result<()> {
    let directory = directory
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            failed_quit(
                "designated output directory and specified section are required".to_string(),
            )
        })?;
    let directory = PathBuf::from(directory);
    std::fs::create_dir_all(&directory).map_err(|error| {
        failed_quit(format!(
            "creating output directory `{}`: {error}",
            directory.display()
        ))
    })?;

    let root = Cli::command();
    let mut path = vec![root.get_name().to_string()];
    write_pages(&root, &mut path, true, &directory)
}

fn failed_quit(message: String) -> anyhow::Error {
    anyhow::Error::new(crate::CliExit { code: 3, message })
}

fn write_pages(
    command: &Command,
    path: &mut Vec<String>,
    is_root: bool,
    directory: &Path,
) -> Result<()> {
    let page = render(command, path, is_root);
    let filename = format!("{}.8", path.join("-"));
    let destination = directory.join(&filename);
    std::fs::write(&destination, page).map_err(|error| {
        failed_quit(format!(
            "writing man page `{}`: {error}",
            destination.display()
        ))
    })?;

    for subcommand in command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
    {
        path.push(subcommand.get_name().to_string());
        write_pages(subcommand, path, false, directory)?;
        path.pop();
    }
    Ok(())
}

fn render(command: &Command, path: &[String], is_root: bool) -> String {
    let name = path.join(" ");
    let title = path.join("-").to_uppercase();
    let about = command
        .get_about()
        .map(ToString::to_string)
        .unwrap_or_default();
    let long_about = command
        .get_long_about()
        .map(ToString::to_string)
        .unwrap_or_default();
    let description = if long_about.is_empty() {
        &about
    } else {
        &long_about
    };

    let mut page = String::new();
    let _ = writeln!(
        page,
        ".TH \"{title}\" \"8\" \"\" \"caddy-rs {}\" \"System Administration\"",
        caddy_rs_core::VERSION
    );
    let _ = writeln!(page, ".SH NAME");
    let _ = writeln!(page, "{} \\- {}", roff(&path.join("-")), roff(&about));

    let _ = writeln!(page, ".SH SYNOPSIS");
    let _ = write!(page, ".B {}", roff(&name));
    if !command.get_subcommands().next().is_none() {
        let _ = write!(page, " [\\fIsubcommand\\fR]");
    }
    let positional_synopsis: Vec<String> = command
        .get_arguments()
        .filter(|argument| argument.is_positional() && !argument.is_hide_set())
        .map(synopsis_positional)
        .collect();
    if !positional_synopsis.is_empty() {
        let _ = write!(page, " {}", positional_synopsis.join(" "));
    }
    let _ = writeln!(page, " [\\fIoptions\\fR]");

    let _ = writeln!(page, ".SH DESCRIPTION");
    write_paragraphs(&mut page, description);

    let subcommands: Vec<&Command> = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .collect();
    if !subcommands.is_empty() {
        let _ = writeln!(page, ".SH SUBCOMMANDS");
        for subcommand in &subcommands {
            let _ = writeln!(page, ".TP");
            let _ = writeln!(page, ".B {}", roff(subcommand.get_name()));
            let subcommand_about = subcommand
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            let _ = writeln!(page, "{}", roff(&subcommand_about));
        }
    }

    let positionals: Vec<&Arg> = command
        .get_arguments()
        .filter(|argument| argument.is_positional() && !argument.is_hide_set())
        .collect();
    if !positionals.is_empty() {
        let _ = writeln!(page, ".SH ARGUMENTS");
        for argument in positionals {
            let _ = writeln!(page, ".TP");
            let name = argument
                .get_value_names()
                .and_then(|names| names.first())
                .map(ToString::to_string)
                .unwrap_or_else(|| argument.get_id().to_string());
            let _ = writeln!(page, ".B <{}>", roff(&name));
            let help = argument
                .get_help()
                .map(ToString::to_string)
                .unwrap_or_default();
            let _ = writeln!(page, "{}", roff(&help));
        }
    }

    let options: Vec<&Arg> = command
        .get_arguments()
        .filter(|argument| !argument.is_positional() && !argument.is_hide_set())
        .collect();
    let mut rendered_options: Vec<String> = options
        .iter()
        .map(|argument| option_synopsis(argument))
        .collect();
    if !command.is_disable_help_flag_set() {
        rendered_options.push("\\-h, \\-\\-help".to_string());
    }
    if !rendered_options.is_empty() {
        let _ = writeln!(page, ".SH OPTIONS");
        for (index, argument) in options.iter().enumerate() {
            let _ = writeln!(page, ".TP");
            let _ = writeln!(page, ".B {}", rendered_options[index]);
            let help = argument
                .get_help()
                .map(ToString::to_string)
                .unwrap_or_default();
            let _ = writeln!(page, "{}", roff(&help));
        }
        if !command.is_disable_help_flag_set() {
            let _ = writeln!(page, ".TP");
            let _ = writeln!(page, ".B \\-h, \\-\\-help");
            let _ = writeln!(page, "Print help.");
        }
    }

    let _ = writeln!(page, ".SH SEE ALSO");
    if is_root {
        let mut references: Vec<String> = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| format!("caddy-rs\\-{}(8)", roff(subcommand.get_name())))
            .collect();
        references.push("caddy-rs(8)".to_string());
        let _ = writeln!(page, ".BR {} ", references.join(", "));
    } else {
        let _ = writeln!(page, ".BR caddy-rs (8)");
    }

    page
}

fn synopsis_positional(argument: &Arg) -> String {
    let name = argument
        .get_value_names()
        .and_then(|names| names.first())
        .map(ToString::to_string)
        .unwrap_or_else(|| argument.get_id().to_string());
    if argument.is_required_set() {
        format!("\\fI<{}>\\fR", roff(&name))
    } else {
        format!("[\\fI<{}>\\fR]", roff(&name))
    }
}

fn option_synopsis(argument: &Arg) -> String {
    let mut synopsis = String::new();
    if let Some(short) = argument.get_short() {
        let _ = write!(synopsis, "\\-{short}");
    }
    if let Some(long) = argument.get_long() {
        if !synopsis.is_empty() {
            synopsis.push_str(", ");
        }
        let _ = write!(synopsis, "\\-\\-{long}");
    }
    let takes_value = !matches!(
        argument.get_action(),
        ArgAction::SetTrue
            | ArgAction::SetFalse
            | ArgAction::Count
            | ArgAction::Help
            | ArgAction::Version
    );
    if takes_value {
        if let Some(value_name) = argument.get_value_names().and_then(|names| names.first()) {
            let _ = write!(synopsis, " \\fI<{}>\\fR", roff(&value_name.to_string()));
        }
    }
    synopsis
}

fn write_paragraphs(page: &mut String, text: &str) {
    for (index, paragraph) in text.split("\n\n").enumerate() {
        if paragraph.trim().is_empty() {
            continue;
        }
        if index > 0 {
            let _ = writeln!(page, ".PP");
        }
        let _ = writeln!(page, "{}", roff(paragraph.trim()));
    }
}

/// Escape text for a roff line: backslashes and hyphens become roff escapes, and a line that
/// begins with the control characters `.` or `'` is prefixed with `\&` so it stays text.
fn roff(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('-', "\\-");
    escaped
        .lines()
        .map(|line| {
            if line.starts_with('.') || line.starts_with('\'') {
                format!("\\&{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
