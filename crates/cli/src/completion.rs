//! `completion`: hand-rolled shell completion scripts generated from the clap command tree.
//!
//! Caddy uses cobra's generated completions. `clap_complete` is deliberately not a dependency of
//! this offline build, so this module walks the same clap tree the parser uses and emits small but
//! correct bash, zsh, fish and PowerShell scripts. Every compiled subcommand and flag is covered;
//! value completion beyond positional possible-values is left to the shell.

use std::fmt::Write as _;

use anyhow::{bail, Result};
use clap::{ArgAction, CommandFactory};

use crate::Cli;

/// Shells accepted by `completion <shell>`, matching Caddy's valid arguments.
const SHELLS: [&str; 4] = ["bash", "zsh", "fish", "powershell"];

/// A flattened description of one command in the clap tree.
struct CommandSpec {
    /// Command path below the binary, e.g. `["pki", "list"]`; empty for the root command.
    path: Vec<String>,
    about: String,
    options: Vec<OptionSpec>,
    positionals: Vec<PositionalSpec>,
    subcommands: Vec<CommandSpec>,
}

struct OptionSpec {
    short: Option<char>,
    long: Option<String>,
    help: String,
    takes_value: bool,
}

struct PositionalSpec {
    help: String,
    values: Vec<String>,
}

/// Generate a completion script for `shell`.
pub(crate) fn generate(shell: &str) -> Result<String> {
    let root = Cli::command();
    let spec = collect(&root, Vec::new());
    let script = match shell {
        "bash" => bash(&spec),
        "zsh" => zsh(&spec),
        "fish" => fish(&spec),
        "powershell" => powershell(&spec),
        // Caddy validates the shell with cobra.OnlyValidArgs before RunE, so this is the
        // message a user actually sees (the switch default below it is unreachable).
        other => bail!("invalid argument \"{other}\" for \"caddy-rs completion\""),
    };
    Ok(script)
}

/// Dispatch the `completion` argument vector.
///
/// The command deliberately keeps a single positional vector instead of clap subcommands: Caddy
/// accepts `completion <shell>` positionally, and the existing "invalid argument ... for
/// \"caddy-rs completion\"" message for an unknown shell must survive. `install`, `uninstall` and
/// `status` are reserved action words in the same position.
pub(crate) fn dispatch(arguments: &[String], shells: &[String], dry_run: bool) -> Result<()> {
    match arguments {
        [action] if action == "install" => crate::completion_install::install(shells, dry_run),
        [action] if action == "uninstall" => crate::completion_install::uninstall(shells, dry_run),
        [action] if action == "status" => {
            if !shells.is_empty() {
                bail!("`completion status` does not accept --shell; it reports every shell");
            }
            if dry_run {
                bail!("`completion status` does not accept --dry-run; it never writes");
            }
            crate::completion_install::status()
        }
        [shell] => {
            if !shells.is_empty() {
                bail!(
                    "`--shell` is only valid with `completion install` or `completion uninstall`"
                );
            }
            if dry_run {
                bail!(
                    "`--dry-run` is only valid with `completion install` or `completion uninstall`"
                );
            }
            print!("{}", generate(shell)?);
            Ok(())
        }
        arguments => bail!("accepts 1 arg(s), received {}", arguments.len()),
    }
}

fn collect(command: &clap::Command, path: Vec<String>) -> CommandSpec {
    let mut options = Vec::new();
    let mut positionals = Vec::new();

    for argument in command
        .get_arguments()
        .filter(|argument| !argument.is_hide_set())
    {
        let help = argument
            .get_help()
            .map(ToString::to_string)
            .unwrap_or_default();
        if argument.is_positional() {
            positionals.push(PositionalSpec {
                help,
                values: argument
                    .get_possible_values()
                    .into_iter()
                    .map(|value| value.get_name().to_string())
                    .collect(),
            });
        } else {
            options.push(OptionSpec {
                short: argument.get_short(),
                long: argument.get_long().map(ToString::to_string),
                help,
                takes_value: !matches!(
                    argument.get_action(),
                    ArgAction::SetTrue
                        | ArgAction::SetFalse
                        | ArgAction::Count
                        | ArgAction::Help
                        | ArgAction::Version
                ),
            });
        }
    }

    if !command.is_disable_help_flag_set() {
        options.push(OptionSpec {
            short: Some('h'),
            long: Some("help".to_string()),
            help: "Print help.".to_string(),
            takes_value: false,
        });
    }

    if path == ["completion"] {
        if let Some(positional) = positionals.first_mut() {
            if positional.values.is_empty() {
                positional.values = SHELLS
                    .iter()
                    .map(ToString::to_string)
                    .chain(["install", "uninstall", "status"].map(String::from))
                    .collect();
            }
        }
    }

    let subcommands = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| {
            let mut subcommand_path = path.clone();
            subcommand_path.push(subcommand.get_name().to_string());
            collect(subcommand, subcommand_path)
        })
        .collect();

    CommandSpec {
        path,
        about: command
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default(),
        options,
        positionals,
        subcommands,
    }
}

fn flatten<'a>(spec: &'a CommandSpec, output: &mut Vec<&'a CommandSpec>) {
    output.push(spec);
    for subcommand in &spec.subcommands {
        flatten(subcommand, output);
    }
}

fn path_key(spec: &CommandSpec) -> String {
    spec.path.join(" ")
}

fn completion_tokens(spec: &CommandSpec) -> Vec<String> {
    let mut tokens: Vec<String> = spec
        .subcommands
        .iter()
        .map(|subcommand| subcommand.path.last().cloned().unwrap_or_default())
        .collect();
    for option in &spec.options {
        if let Some(long) = &option.long {
            tokens.push(format!("--{long}"));
        }
        if let Some(short) = option.short {
            tokens.push(format!("-{short}"));
        }
    }
    for positional in &spec.positionals {
        tokens.extend(positional.values.iter().cloned());
    }
    tokens
}

/// Parent commands whose next non-flag word is a subcommand, used by the bash/zsh walkers.
fn parent_paths(spec: &CommandSpec) -> Vec<String> {
    let mut parents = Vec::new();
    fn visit(spec: &CommandSpec, parents: &mut Vec<String>) {
        if !spec.subcommands.is_empty() && !spec.path.is_empty() {
            parents.push(path_key(spec));
        }
        for subcommand in &spec.subcommands {
            visit(subcommand, parents);
        }
    }
    visit(spec, &mut parents);
    parents
}

fn bash(spec: &CommandSpec) -> String {
    let mut commands = Vec::new();
    flatten(spec, &mut commands);
    let mut script =
        String::from("# bash completion for caddy-rs (generated from the clap command tree)\n");
    script.push_str("_caddy_rs() {\n");
    script.push_str("    local cur cmd word i opts\n");
    script.push_str("    COMPREPLY=()\n");
    script.push_str("    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n");
    script.push_str("    cmd=\"\"\n");
    script.push_str("    for ((i = 1; i < COMP_CWORD; i++)); do\n");
    script.push_str("        word=\"${COMP_WORDS[i]}\"\n");
    script.push_str("        case \"$word\" in\n");
    script.push_str("            -*) continue ;;\n");
    script.push_str("        esac\n");
    script.push_str("        if [ -z \"$cmd\" ]; then\n");
    script.push_str("            cmd=\"$word\"\n");
    script.push_str("        else\n");
    script.push_str("            case \"$cmd\" in\n");
    for parent in parent_paths(spec) {
        let _ = writeln!(
            script,
            "                \"{parent}\") cmd=\"$cmd $word\" ;;"
        );
    }
    script.push_str("            esac\n");
    script.push_str("        fi\n");
    script.push_str("    done\n");
    script.push_str("    case \"$cmd\" in\n");
    for command in commands {
        let tokens = completion_tokens(command).join(" ");
        let _ = writeln!(
            script,
            "        \"{}\") opts=\"{tokens}\" ;;",
            path_key(command)
        );
    }
    script.push_str("        *) opts=\"\" ;;\n");
    script.push_str("    esac\n");
    script.push_str("    COMPREPLY=( $(compgen -W \"$opts\" -- \"$cur\") )\n");
    script.push_str("}\n");
    script.push_str("complete -o default -F _caddy_rs caddy-rs\n");
    script
}

/// Quote a value for a zsh `_describe` array entry (`name:description`).
fn zsh_entry(value: &str, description: &str) -> String {
    let entry = format!("{value}:{description}");
    format!("'{}'", entry.replace('\\', "\\\\").replace('\'', "'\\''"))
}

fn zsh(spec: &CommandSpec) -> String {
    let mut commands = Vec::new();
    flatten(spec, &mut commands);
    let mut script = String::from("#compdef caddy-rs\n");
    script.push_str("# zsh completion for caddy-rs (generated from the clap command tree)\n");
    script.push_str("_caddy_rs() {\n");
    script.push_str("    local cmd word i\n");
    script.push_str("    local -a opts\n");
    script.push_str("    cmd=\"\"\n");
    script.push_str("    for ((i = 2; i < CURRENT; i++)); do\n");
    script.push_str("        word=\"${words[i]}\"\n");
    script.push_str("        case \"$word\" in\n");
    script.push_str("            -*) continue ;;\n");
    script.push_str("        esac\n");
    script.push_str("        if [[ -z \"$cmd\" ]]; then\n");
    script.push_str("            cmd=\"$word\"\n");
    script.push_str("        else\n");
    script.push_str("            case \"$cmd\" in\n");
    for parent in parent_paths(spec) {
        let _ = writeln!(
            script,
            "                \"{parent}\") cmd=\"$cmd $word\" ;;"
        );
    }
    script.push_str("            esac\n");
    script.push_str("        fi\n");
    script.push_str("    done\n");
    script.push_str("    case \"$cmd\" in\n");
    for command in commands {
        let mut entries = Vec::new();
        for subcommand in &command.subcommands {
            let name = subcommand.path.last().cloned().unwrap_or_default();
            entries.push(zsh_entry(&name, &subcommand.about));
        }
        for option in &command.options {
            if let Some(long) = &option.long {
                entries.push(zsh_entry(&format!("--{long}"), &option.help));
            }
            if let Some(short) = option.short {
                entries.push(zsh_entry(&format!("-{short}"), &option.help));
            }
        }
        for positional in &command.positionals {
            for value in &positional.values {
                entries.push(zsh_entry(value, &positional.help));
            }
        }
        let _ = writeln!(
            script,
            "        \"{}\") opts=( {} ) ;;",
            path_key(command),
            entries.join(" ")
        );
    }
    script.push_str("        *) opts=() ;;\n");
    script.push_str("    esac\n");
    script.push_str("    if (( ${#opts[@]} )); then\n");
    script.push_str("        _describe 'caddy-rs' opts\n");
    script.push_str("    fi\n");
    script.push_str("}\n");
    script.push_str("compdef _caddy_rs caddy-rs\n");
    script
}

fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn fish_condition(path: &[String]) -> String {
    if path.is_empty() {
        "__fish_use_subcommand".to_string()
    } else {
        path.iter()
            .map(|segment| format!("__fish_seen_subcommand_from {segment}"))
            .collect::<Vec<_>>()
            .join("; and ")
    }
}

fn fish(spec: &CommandSpec) -> String {
    let mut commands = Vec::new();
    flatten(spec, &mut commands);
    let mut script =
        String::from("# fish completion for caddy-rs (generated from the clap command tree)\n");
    script.push_str("complete -c caddy-rs -f\n");
    for command in commands {
        let condition = fish_condition(&command.path);
        for subcommand in &command.subcommands {
            let name = subcommand.path.last().cloned().unwrap_or_default();
            let _ = writeln!(
                script,
                "complete -c caddy-rs -n {} -a {} -d {}",
                fish_quote(&condition),
                fish_quote(&name),
                fish_quote(&subcommand.about)
            );
        }
        for option in &command.options {
            let mut line = format!("complete -c caddy-rs -n {} -f", fish_quote(&condition));
            if let Some(long) = &option.long {
                let _ = write!(line, " -l {long}");
            }
            if let Some(short) = option.short {
                let _ = write!(line, " -s {short}");
            }
            if option.takes_value {
                line.push_str(" -r");
            }
            if !option.help.is_empty() {
                let _ = write!(line, " -d {}", fish_quote(&option.help));
            }
            script.push_str(&line);
            script.push('\n');
        }
        for positional in &command.positionals {
            if positional.values.is_empty() {
                continue;
            }
            let values = positional.values.join(" ");
            let _ = writeln!(
                script,
                "complete -c caddy-rs -n {} -a {} -d {}",
                fish_quote(&condition),
                fish_quote(&values),
                fish_quote(&positional.help)
            );
        }
    }
    script
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn powershell(spec: &CommandSpec) -> String {
    let mut commands = Vec::new();
    flatten(spec, &mut commands);
    let mut script = String::from(
        "# PowerShell completion for caddy-rs (generated from the clap command tree)\n",
    );
    script.push_str("using namespace System.Management.Automation\n");
    script.push_str("using namespace System.Management.Automation.Language\n\n");
    script.push_str("Register-ArgumentCompleter -Native -CommandName 'caddy-rs' -ScriptBlock {\n");
    script.push_str("    param($wordToComplete, $commandAst, $cursorPosition)\n");
    script.push_str("    $commandElements = $commandAst.CommandElements\n");
    script.push_str("    $command = @('caddy-rs')\n");
    script.push_str("    for ($i = 1; $i -lt $commandElements.Count; $i++) {\n");
    script.push_str("        $element = $commandElements[$i]\n");
    script.push_str("        if ($element -isnot [StringConstantExpressionAst] -or\n");
    script.push_str("            $element.Value.StartsWith('-') -or\n");
    script.push_str("            $element.Extent.EndOffset -gt $cursorPosition) { continue }\n");
    script.push_str("        $command += $element.Value\n");
    script.push_str("    }\n");
    script.push_str("    $commandPath = $command -join ' '\n");
    script.push_str("    $completions = @()\n");
    script.push_str("    switch ($commandPath) {\n");
    for command in commands {
        let tokens = completion_tokens(command)
            .into_iter()
            .map(|token| ps_quote(&token))
            .collect::<Vec<_>>()
            .join(", ");
        let key = if command.path.is_empty() {
            "caddy-rs".to_string()
        } else {
            format!("caddy-rs {}", command.path.join(" "))
        };
        let _ = writeln!(
            script,
            "        {} {{ $completions = @({tokens}) }}",
            ps_quote(&key)
        );
    }
    script.push_str("        default { $completions = @() }\n");
    script.push_str("    }\n");
    script.push_str(
        "    $completions | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {\n",
    );
    script.push_str(
        "        [CompletionResult]::new($_, $_, [CompletionResultType]::ParameterValue, $_)\n",
    );
    script.push_str("    }\n");
    script.push_str("}\n");
    script
}
