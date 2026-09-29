//! `teifs init`: makes a drive ready to serve. It asks on a terminal (or takes flags),
//! creates the drive, its keys and its keyring, writes the drive's settings file, adds
//! an alias for `teifs ls` and `teifs cp`, and says what to run next.

use std::{
    fmt::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use teifs_server::credentials;
use teifs_store::LocalKms;

use crate::{
    LayoutArg, announce_address,
    client::alias::{self, Alias, Aliases},
    config,
    error::{Error, Kind},
    shell_word, ui,
};

/// `teifs init`'s flags; what isn't given is asked for on a terminal, or defaults.
#[derive(clap::Args)]
pub(crate) struct InitArgs {
    /// The drive's folder (created if missing). Default: the current folder.
    dir: Option<PathBuf>,
    /// The address `teifs serve` listens on. Default: 127.0.0.1:9000.
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// How new buckets store objects: `object` (any key S3 allows, encrypted at rest,
    /// as on AWS) or `folder` (plain files you can open anywhere). Default: object.
    #[arg(long, value_enum)]
    default_layout: Option<LayoutArg>,
    /// The KMS keyring. Default: `<config dir>/teifs/keys/<drive id>.json`, off the drive.
    #[arg(long)]
    kms_keyring: Option<PathBuf>,
    /// The alias to add for the drive (`teifs ls NAME`). Default: local.
    #[arg(long, conflicts_with = "no_alias")]
    alias: Option<String>,
    /// Don't add an alias.
    #[arg(long)]
    no_alias: bool,
    /// Replace the drive's settings file and the alias if they exist.
    #[arg(long)]
    force: bool,
}

const LAYOUTS: [&str; 2] = [
    "object: any key S3 allows, encrypted at rest (as on AWS)",
    "folder: plain files you can open anywhere",
];

const DEFAULT_LISTEN: &str = "127.0.0.1:9000";

pub(crate) fn init(args: &InitArgs) -> Result<(), Error> {
    let asking = ui::asking();
    let chosen = choose(args, asking)?;
    let settings = config::drive_settings(&chosen.root);
    // Before anything is created: an existing setup is replaced only when asked.
    if settings.exists()
        && !args.force
        && !ui::confirm(
            &format!("Replace the settings in {}?", settings.display()),
            "add --force to replace them",
        )?
    {
        return Err(Error::new(
            Kind::Conflict,
            format!(
                "{} is already set up; nothing was changed",
                chosen.root.display()
            ),
        )
        .with_hint("add --force to replace its settings"));
    }

    let (keys, created_keys) = credentials::load_or_create(&chosen.root)
        .map_err(|e| Error::general(format!("can't create the drive's keys: {e}")))?;
    let created_keyring = !chosen.keyring.exists();
    LocalKms::open(&chosen.keyring).map_err(|e| {
        Error::general(format!(
            "can't create the keyring {}: {e}",
            chosen.keyring.display()
        ))
    })?;
    write_settings(&settings, &chosen)?;

    let endpoint = format!("http://{}", announce_address(chosen.listen));
    let alias = if args.no_alias {
        None
    } else {
        add_alias(
            args.alias.as_deref(),
            &endpoint,
            keys.access_key.clone(),
            keys.secret_key,
            asking,
            args.force,
        )?
    };
    report(&Report {
        chosen: &chosen,
        endpoint,
        access_key: keys.access_key,
        settings,
        alias,
    });
    if created_keys {
        ui::note(
            "The secret key stays in its file (readable only by you); aliases read it from there.",
        );
    }
    if created_keyring {
        ui::warn(format!(
            "created the encryption keyring in {}; back it up: encrypted objects can't be read without it",
            chosen.keyring.display()
        ));
    }
    Ok(())
}

/// What the drive is set up with.
struct Chosen {
    /// The drive's folder, resolved.
    root: PathBuf,
    listen: SocketAddr,
    layout: LayoutArg,
    keyring: PathBuf,
    /// Whether `keyring` is where `teifs serve` looks anyway.
    default_keyring: bool,
}

/// The flags, else the answers (on a terminal), else the defaults. Creates the drive's
/// folder, whose id names the default keyring.
fn choose(args: &InitArgs, asking: bool) -> Result<Chosen, Error> {
    let dir = match &args.dir {
        Some(dir) => dir.clone(),
        None if asking => PathBuf::from(ui::ask_text("Drive folder:", ".", |text| {
            if text.is_empty() {
                Err("A folder is needed.".into())
            } else {
                Ok(())
            }
        })?),
        None => PathBuf::from("."),
    };
    let listen = match args.listen {
        Some(listen) => listen,
        None if asking => ui::ask_text("Listen on:", DEFAULT_LISTEN, |text| {
            text.parse::<SocketAddr>()
                .map(drop)
                .map_err(|_| "An address and port, like 127.0.0.1:9000.".into())
        })?
        .parse()
        .expect("checked"),
        None => DEFAULT_LISTEN.parse().expect("a valid address"),
    };
    let layout = match args.default_layout {
        Some(layout) => layout,
        None if asking => match ui::ask_choice("New buckets store objects as:", &LAYOUTS)? {
            0 => LayoutArg::Object,
            _ => LayoutArg::Folder,
        },
        None => LayoutArg::Object,
    };

    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::general(format!("can't create {}: {e}", dir.display())))?;
    let store = crate::open(&dir)?;
    let root = store.root().to_path_buf();
    let default = teifs_server::default_keyring(&store.format().drive)
        .map_err(|e| Error::general(e.to_string()))?;
    drop(store);

    let keyring = match &args.kms_keyring {
        Some(path) => absolute(path)?,
        None if asking => {
            let root = root.clone();
            let answer = ui::ask_text(
                "Keyring (keep it off the drive):",
                &default.display().to_string(),
                move |text| {
                    if resolved(Path::new(text)).starts_with(&root) {
                        Err(
                            "Keep it off the drive, so a copy of the drive can't be decrypted."
                                .into(),
                        )
                    } else {
                        Ok(())
                    }
                },
            )?;
            absolute(Path::new(&answer))?
        }
        None => default.clone(),
    };
    if resolved(&keyring).starts_with(&root) {
        return Err(
            Error::usage(format!("the keyring {} is on the drive", keyring.display()))
                .with_hint(ON_DRIVE),
        );
    }
    Ok(Chosen {
        root,
        listen,
        layout,
        default_keyring: keyring == default,
        keyring,
    })
}

const ON_DRIVE: &str = "keep it off the drive, so a copy of the drive can't be decrypted";

struct Report<'a> {
    chosen: &'a Chosen,
    endpoint: String,
    access_key: String,
    settings: PathBuf,
    alias: Option<String>,
}

/// Says what was set up and what to run next.
fn report(report: &Report<'_>) {
    let chosen = report.chosen;
    let drive = chosen.root.display().to_string();
    let secret_file = credentials::path(&chosen.root).display().to_string();
    let (keyring, settings) = (
        chosen.keyring.display().to_string(),
        report.settings.display().to_string(),
    );
    if ui::json() {
        ui::emit(&serde_json::json!({
            "type": "init",
            "drive": drive,
            "endpoint": report.endpoint,
            "listen": chosen.listen.to_string(),
            "defaultLayout": chosen.layout.name(),
            "accessKey": report.access_key,
            "secretKeyFile": secret_file,
            "keyring": keyring,
            "settings": settings,
            "alias": report.alias,
        }));
        return;
    }
    let next = [
        format!("teifs serve {}", shell_word(&drive)),
        match &report.alias {
            Some(name) => format!("teifs ls {name}"),
            None => format!(
                "teifs alias set local {} --drive {}",
                report.endpoint,
                shell_word(&drive)
            ),
        },
    ];
    let layout = LAYOUTS[usize::from(matches!(chosen.layout, LayoutArg::Folder))];
    ui::banner(
        format!("Drive ready at {drive}"),
        &[
            ("Endpoint", report.endpoint.clone()),
            ("New buckets", layout.to_owned()),
            ("Access key", report.access_key.clone()),
            ("Secret key", format!("in {secret_file}")),
            ("Keyring", keyring),
            ("Settings", settings),
            ("Alias", report.alias.clone().unwrap_or_default()),
        ],
        &next,
    );
}

/// Writes the drive's settings file (a whole new one, or none).
fn write_settings(path: &Path, chosen: &Chosen) -> Result<(), Error> {
    let keyring = (!chosen.default_keyring).then_some(&chosen.keyring);
    let text = settings_text(chosen.listen, chosen.layout, keyring);
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| Error::general(format!("can't write {}: {e}", path.display())))
}

/// The settings file's text: TOML, under `teifs serve`'s flag names.
fn settings_text(listen: SocketAddr, layout: LayoutArg, keyring: Option<&PathBuf>) -> String {
    let string = |text: &str| toml::Value::String(text.to_owned()).to_string();
    let mut text = String::from(
        "# `teifs serve` reads this for the drive it's in. Flags and environment variables win\n# over it; `teifs config show DIR` says where each setting comes from.\n",
    );
    let _ = writeln!(text, "listen = {}", string(&listen.to_string()));
    let _ = writeln!(text, "default-layout = {}", string(layout.name()));
    if let Some(keyring) = keyring {
        let _ = writeln!(
            text,
            "kms-keyring = {}",
            string(&keyring.display().to_string())
        );
    }
    text
}

/// Adds the alias for the drive; its name, or `None` when the person said not to.
fn add_alias(
    name: Option<&str>,
    endpoint: &str,
    access_key: String,
    secret_key: String,
    asking: bool,
    force: bool,
) -> Result<Option<String>, Error> {
    let name = match name {
        Some(name) => name.to_owned(),
        None if asking => {
            if !ui::ask_yes(
                "Add an alias, so `teifs ls local` reaches this drive?",
                true,
            )? {
                return Ok(None);
            }
            "local".to_owned()
        }
        None => "local".to_owned(),
    };
    alias::check_name(&name).map_err(Error::usage)?;
    let url = alias::check_url(endpoint).map_err(Error::usage)?;
    let mut aliases = Aliases::load()?;
    let alias = Alias {
        url,
        access_key,
        secret_key,
        region: alias::DEFAULT_REGION.to_owned(),
        path_style: true,
        session_token: None,
        expires: None,
        ca_cert: None,
        trust: crate::client::trust::Trust::default(),
    };
    if let Some((existing, _)) = aliases.get(&name)
        && *existing != alias
        && !force
        && !ui::confirm(
            &format!("Replace the alias {name} (for {})?", existing.url),
            "add --force to replace it, or choose another name with --alias",
        )?
    {
        ui::note(format!("Kept the alias {name} as it was."));
        return Ok(None);
    }
    aliases.set(&name, alias)?;
    Ok(Some(name))
}

/// `path` made absolute against the current folder (it needn't exist yet).
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    std::path::absolute(path)
        .map_err(|e| Error::general(format!("can't resolve {}: {e}", path.display())))
}

/// Where `path` really is: its nearest existing folder with links resolved, then the
/// rest, so `/var/x` and `/private/var/x` compare equal on macOS.
fn resolved(path: &Path) -> PathBuf {
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    for base in path.ancestors() {
        if let Ok(real) = base.canonicalize() {
            return real.join(path.strip_prefix(base).unwrap_or(Path::new("")));
        }
    }
    path
}
