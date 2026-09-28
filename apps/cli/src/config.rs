//! `teifs serve`'s settings: flags, then environment variables, then a settings file,
//! then defaults.
//!
//! The settings file (`--config`, `TEIFS_CONFIG`) is TOML with the flags' names as keys
//! (`listen = "0.0.0.0:9000"`, `upload-expiry = "7d"`, `domains = ["s3.example.com"]`).
//! Its values become the flags' defaults, so a flag or an environment variable always
//! wins over it, and they're checked like flags are. Relative paths in it are relative
//! to its own folder, wherever `teifs` is started from. Secrets never go in it: the secret
//! key comes from `TEIFS_SECRET_KEY` or a file named by `secret-key-file`. MinIO's
//! `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` are used when nothing else sets the keys.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use clap::{
    Arg, ArgAction, ArgMatches, Command, CommandFactory, FromArgMatches, parser::ValueSource,
};

use crate::{Cli, ServeArgs};

/// Settings that are paths: relative ones in the settings file are relative to its folder.
const PATHS: [&str; 3] = ["dir", "kms_keyring", "secret_key_file"];

/// The subcommands that take `serve`'s settings, by their path from the top.
const SERVE_COMMANDS: [&[&str]; 2] = [&["serve"], &["config", "show"]];

/// A drive's own settings file, which `teifs serve DIR` reads when no other is named.
pub(crate) fn drive_settings(drive: &Path) -> PathBuf {
    drive.join(teifs_store::SYSTEM_DIR).join("settings.toml")
}

/// Where each of `serve`'s settings came from.
#[derive(Default)]
pub(crate) struct Sources {
    /// The settings file, if one was read.
    file: Option<PathBuf>,
    /// The settings it set (argument ids).
    from_file: BTreeSet<String>,
    /// The settings as parsed.
    matches: Option<ArgMatches>,
}

/// Parses the command line, with the settings file's values under the flags and
/// environment variables. Help, version and usage errors exit, as clap does.
pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<(Cli, Sources), String> {
    let args: Vec<OsString> = args.into_iter().collect();
    let first = Cli::command().get_matches_from(&args);
    let path = serve_matches(&first).and_then(|m| {
        m.get_one::<PathBuf>("config").cloned().or_else(|| {
            let own = drive_settings(m.get_one::<PathBuf>("dir")?);
            own.is_file().then_some(own)
        })
    });
    let (matches, sources) = match path {
        None => {
            let sources = Sources {
                matches: serve_matches(&first).cloned(),
                ..Sources::default()
            };
            (first, sources)
        }
        Some(path) => {
            let defaults = read_file(&path)?;
            let mut command = Cli::command();
            for names in SERVE_COMMANDS {
                command = with_defaults(command, names, &defaults);
            }
            let matches = command.get_matches_from(&args);
            let sources = Sources {
                file: Some(path),
                from_file: defaults.into_iter().map(|(id, _)| id).collect(),
                matches: serve_matches(&matches).cloned(),
            };
            (matches, sources)
        }
    };
    let cli = Cli::from_arg_matches(&matches).map_err(|e| e.to_string())?;
    Ok((cli, sources))
}

/// The matches of whichever subcommand takes `serve`'s settings.
fn serve_matches(matches: &ArgMatches) -> Option<&ArgMatches> {
    match matches.subcommand()? {
        ("serve", serve) => Some(serve),
        ("config", config) => config.subcommand_matches("show"),
        _ => None,
    }
}

/// `serve`'s settings (every argument but help and the settings file itself).
fn settings(serve: &Command) -> impl Iterator<Item = &Arg> {
    serve.get_arguments().filter(|arg| {
        !matches!(arg.get_action(), ArgAction::Help | ArgAction::Version)
            && arg.get_id() != "config"
    })
}

/// A setting's name in the settings file: its id, in the flags' style.
fn key_name(arg: &Arg) -> String {
    arg.get_id().as_str().replace('_', "-")
}

fn serve_command() -> Command {
    Cli::command()
        .find_subcommand("serve")
        .expect("serve is a subcommand")
        .clone()
}

/// Reads the settings file: each setting's id and its values as the flag would take them.
fn read_file(path: &Path) -> Result<Vec<(String, Vec<String>)>, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("can't read the settings file {}: {e}", path.display()))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e| format!("the settings file {} isn't valid TOML: {e}", path.display()))?;
    let serve = serve_command();
    let mut defaults = Vec::new();
    for (key, value) in table {
        let fail = |why: String| format!("{}: `{key}`: {why}", path.display());
        let id = key.replace('-', "_");
        if id == "secret_key" {
            return Err(fail(
                "secrets don't go in the settings file; name a file holding the secret key with `secret-key-file`, or set TEIFS_SECRET_KEY".into(),
            ));
        }
        let arg = settings(&serve)
            .find(|arg| arg.get_id() == id.as_str() || arg.get_long() == Some(key.as_str()))
            .ok_or_else(|| {
                fail("isn't a setting (settings are named like `teifs serve`'s flags)".into())
            })?;
        let many = matches!(arg.get_action(), ArgAction::Append);
        let values = match value {
            toml::Value::Array(items) if many => items
                .into_iter()
                .map(scalar)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| fail("the list may only hold strings".into()))?,
            toml::Value::Array(_) => return Err(fail("takes one value, not a list".into())),
            value => vec![
                scalar(value)
                    .ok_or_else(|| fail("must be a string, a number or true/false".into()))?,
            ],
        };
        let values = if PATHS.contains(&arg.get_id().as_str()) {
            let base = path.parent().unwrap_or(Path::new(""));
            values
                .into_iter()
                .map(|value| base.join(value).into_os_string().into_string())
                .collect::<Result<_, _>>()
                .map_err(|_| fail("the settings file's folder must have a UTF-8 path".into()))?
        } else {
            values
        };
        // Checked now, so a bad value names the file rather than a flag nobody typed.
        check(&serve, arg, &values).map_err(fail)?;
        defaults.push((arg.get_id().to_string(), values));
    }
    Ok(defaults)
}

/// Checks `values` as `arg`'s, by parsing `serve` with them as its only input.
fn check(serve: &Command, arg: &Arg, values: &[String]) -> Result<(), String> {
    let probe = serve
        .get_arguments()
        .fold(serve.clone().no_binary_name(true), |probe, other| {
            probe.mut_arg(other.get_id(), |other| other.env(None))
        })
        .mut_arg(arg.get_id(), |arg| arg.default_values(values.to_vec()));
    probe
        .try_get_matches_from(Vec::<OsString>::new())
        .map(drop)
        .map_err(|e| clap_message(&e))
}

/// A TOML value as a flag's value.
fn scalar(value: toml::Value) -> Option<String> {
    match value {
        toml::Value::String(text) => Some(text),
        toml::Value::Integer(number) => Some(number.to_string()),
        toml::Value::Boolean(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// The first line of a clap error, without its `error: ` prefix.
fn clap_message(err: &clap::Error) -> String {
    let text = err.to_string();
    let line = text.lines().next().unwrap_or_default();
    line.strip_prefix("error: ").unwrap_or(line).to_owned()
}

/// Makes `defaults` the defaults of the subcommand at `names`.
fn with_defaults(command: Command, names: &[&str], defaults: &[(String, Vec<String>)]) -> Command {
    match names {
        [] => defaults.iter().fold(command, |command, (id, values)| {
            command.mut_arg(id, |arg| arg.default_values(values.clone()))
        }),
        [name, rest @ ..] => command.mut_subcommand(name, |sub| with_defaults(sub, rest, defaults)),
    }
}

/// The access key and where the secret key comes from, when they're set.
pub(crate) struct Keys {
    pub access: String,
    pub secret: Secret,
    /// Taken from MinIO's variables.
    pub from_minio: bool,
}

/// Where the secret key is.
pub(crate) enum Secret {
    /// In an environment variable.
    Env(&'static str),
    /// In a file of its own.
    File(PathBuf),
}

/// The shortest secret key accepted (as MinIO).
const MIN_SECRET_LEN: usize = 8;

impl Secret {
    /// The secret key.
    pub fn read(&self) -> Result<String, String> {
        let secret = match self {
            Self::Env(name) => env(name).ok_or_else(|| format!("{name} is empty"))?,
            Self::File(path) => {
                let text = fs::read_to_string(path).map_err(|e| {
                    format!("can't read the secret key from {}: {e}", path.display())
                })?;
                // Written by `echo` or an editor: one line break at the end isn't part of it.
                let text = text.strip_suffix('\n').unwrap_or(&text);
                text.strip_suffix('\r').unwrap_or(text).to_owned()
            }
        };
        if secret.chars().count() < MIN_SECRET_LEN {
            return Err(format!(
                "the secret key ({}) must be at least {MIN_SECRET_LEN} characters",
                self.describe()
            ));
        }
        Ok(secret)
    }

    /// Where it is, for messages.
    pub fn describe(&self) -> String {
        match self {
            Self::Env(name) => format!("from {name}"),
            Self::File(path) => format!("from the file {}", path.display()),
        }
    }
}

/// An environment variable, when set and not empty.
pub(crate) fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The keys `args` set, from the flags, the environment (`env`) or MinIO's variables;
/// `None` when nothing sets them (the drive's own are used).
pub(crate) fn keys(
    args: &ServeArgs,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<Keys>, String> {
    let secret = match (&args.secret_key_file, env("TEIFS_SECRET_KEY").is_some()) {
        (Some(_), true) => {
            return Err(
                "the secret key is set twice, by TEIFS_SECRET_KEY and secret-key-file; keep one"
                    .into(),
            );
        }
        (Some(path), false) => Some(Secret::File(path.clone())),
        (None, true) => Some(Secret::Env("TEIFS_SECRET_KEY")),
        (None, false) => None,
    };
    match (&args.access_key, secret) {
        (Some(access), Some(secret)) => Ok(Some(Keys {
            access: access.clone(),
            secret,
            from_minio: false,
        })),
        (Some(_), None) => Err(
            "set the secret key along with the access key: TEIFS_SECRET_KEY, or a file named by --secret-key-file".into(),
        ),
        (None, Some(_)) => {
            Err("set the access key along with the secret key (--access-key or TEIFS_ACCESS_KEY)".into())
        }
        (None, None) => match (env("MINIO_ROOT_USER"), env("MINIO_ROOT_PASSWORD").is_some()) {
            (Some(access), true) => Ok(Some(Keys {
                access,
                secret: Secret::Env("MINIO_ROOT_PASSWORD"),
                from_minio: true,
            })),
            (Some(_), false) | (None, true) => {
                Err("set both MINIO_ROOT_USER and MINIO_ROOT_PASSWORD, or neither".into())
            }
            (None, false) => Ok(None),
        },
    }
}

/// `teifs config show`: the effective settings as TOML, each with where it came from.
pub(crate) fn show(args: &ServeArgs, sources: &Sources) -> Result<(), String> {
    let matches = sources.matches.as_ref().ok_or("no settings were parsed")?;
    let mut out = String::from("# The settings `teifs serve` would use: flags, then environment");
    match &sources.file {
        Some(path) => {
            let _ = write!(out, ", then {}", path.display());
        }
        None => out.push_str(" (no settings file)"),
    }
    out.push_str(", then defaults.\n");
    let serve = serve_command();
    let json = crate::ui::json();
    for arg in settings(&serve) {
        let id = arg.get_id().as_str();
        let name = key_name(arg);
        let Some(values) = matches.get_raw(id) else {
            if json {
                crate::ui::emit(&serde_json::json!({
                    "type": "setting", "name": name, "value": null, "source": null,
                }));
            } else {
                let _ = writeln!(out, "# {name}: not set");
            }
            continue;
        };
        let values: Vec<String> = values.map(|v| v.to_string_lossy().into_owned()).collect();
        let value = match arg.get_action() {
            ArgAction::SetTrue | ArgAction::SetFalse => {
                toml::Value::Boolean(values.join("") == "true")
            }
            ArgAction::Append => {
                toml::Value::Array(values.into_iter().map(toml::Value::String).collect())
            }
            _ => toml::Value::String(values.join("")),
        };
        let source = match matches.value_source(id) {
            Some(ValueSource::CommandLine) => "flag",
            Some(ValueSource::EnvVariable) => "environment",
            Some(ValueSource::DefaultValue) if sources.from_file.contains(id) => "file",
            _ => "default",
        };
        if json {
            crate::ui::emit(&serde_json::json!({
                "type": "setting", "name": name, "value": value, "source": source,
            }));
        } else {
            let _ = writeln!(out, "{name} = {value}  # {source}");
        }
    }
    if json {
        // Where the keys come from; never the secret itself.
        let record = match keys(args, env)? {
            Some(keys) => serde_json::json!({
                "type": "keys",
                "from": if keys.from_minio { "minio" } else { "settings" },
                "secret": keys.secret.describe(),
            }),
            None => serde_json::json!({"type": "keys", "from": "drive", "secret": null}),
        };
        crate::ui::emit(&record);
        return Ok(());
    }
    match keys(args, env)? {
        Some(keys) => {
            let _ = writeln!(
                out,
                "# access key {}; secret key {} (never shown)",
                if keys.from_minio {
                    "from MINIO_ROOT_USER"
                } else {
                    "as above"
                },
                keys.secret.describe()
            );
        }
        None => out.push_str("# keys: the drive's own (`teifs credentials`)\n"),
    }
    print!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(access_key: Option<&str>, secret_key_file: Option<&str>) -> ServeArgs {
        let mut argv = vec!["teifs", "serve"];
        if let Some(key) = access_key {
            argv.extend(["--access-key", key]);
        }
        if let Some(file) = secret_key_file {
            argv.extend(["--secret-key-file", file]);
        }
        let matches = Cli::command().get_matches_from(argv);
        match Cli::from_arg_matches(&matches).unwrap().command {
            crate::Command::Serve(serve) => serve,
            _ => unreachable!(),
        }
    }

    fn vars<'a>(pairs: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn path_settings_exist() {
        let serve = serve_command();
        for id in PATHS {
            assert!(settings(&serve).any(|arg| arg.get_id() == id), "{id}");
        }
    }

    #[test]
    fn keys_come_in_pairs_from_one_place() {
        let none = keys(&args(None, None), vars(&[])).unwrap();
        assert!(none.is_none());

        let env = keys(&args(Some("ak"), None), vars(&[("TEIFS_SECRET_KEY", "s")])).unwrap();
        assert!(matches!(
            env,
            Some(Keys {
                secret: Secret::Env("TEIFS_SECRET_KEY"),
                from_minio: false,
                ..
            })
        ));

        let file = keys(&args(Some("ak"), Some("/run/secrets/s")), vars(&[])).unwrap();
        assert!(matches!(
            file,
            Some(Keys {
                secret: Secret::File(_),
                ..
            })
        ));

        for (access, file, env) in [
            (Some("ak"), None, &[][..]),
            (None, None, &[("TEIFS_SECRET_KEY", "s")][..]),
            (Some("ak"), Some("/f"), &[("TEIFS_SECRET_KEY", "s")][..]),
            (None, None, &[("MINIO_ROOT_USER", "u")][..]),
            (None, None, &[("MINIO_ROOT_PASSWORD", "p")][..]),
        ] {
            assert!(
                keys(&args(access, file), vars(env)).is_err(),
                "{access:?} {file:?} {env:?}"
            );
        }
    }

    #[test]
    fn minio_variables_are_a_fallback() {
        let minio = [("MINIO_ROOT_USER", "u"), ("MINIO_ROOT_PASSWORD", "p")];
        let keys_ = keys(&args(None, None), vars(&minio)).unwrap().unwrap();
        assert_eq!(keys_.access, "u");
        assert!(keys_.from_minio);
        // TeiFS's own win.
        let both = [minio[0], minio[1], ("TEIFS_SECRET_KEY", "s")];
        let own = keys(&args(Some("ak"), None), vars(&both)).unwrap().unwrap();
        assert_eq!(own.access, "ak");
        assert!(!own.from_minio);
    }

    #[test]
    fn secret_files_lose_one_trailing_line_break() {
        let dir = tempfile::tempdir().unwrap();
        for (written, read) in [
            ("s3cr3t-key\n", Ok("s3cr3t-key")),
            ("s3cr3t-key\r\n", Ok("s3cr3t-key")),
            ("s3cr3t-key", Ok("s3cr3t-key")),
            (" spaced key \n\n", Ok(" spaced key \n")),
            ("short\n", Err(())),
            ("", Err(())),
        ] {
            let path = dir.path().join("secret");
            fs::write(&path, written).unwrap();
            assert_eq!(
                Secret::File(path).read().map_err(|_| ()),
                read.map(str::to_owned),
                "{written:?}"
            );
        }
        let missing = Secret::File(dir.path().join("missing")).read().unwrap_err();
        assert!(missing.contains("can't read the secret key"), "{missing}");
    }
}
