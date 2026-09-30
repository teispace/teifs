//! `teifs sts`: temporary credentials, over AWS's STS API as `aws sts` speaks it — who an
//! alias signs as, a role's session (or, without a role, MinIO's session for the user's
//! own permissions), and a role's session for an OpenID Connect ID token (a CI job's).
//!
//! The credentials go into an alias (with their session token and when they expire), or
//! to an owner-only file or standard output in the AWS CLI's `credential_process` format,
//! so `aws` and the AWS SDKs can use them as they are.

use std::{path::PathBuf, time::Duration};

use aws_sdk_sts::{Client, config::Region, types::Credentials};
use clap::{Args, Subcommand};
use serde_json::json;
use teifs_client::Zeroizing;

use crate::{
    client::alias::{self, Alias, Aliases, check_name},
    error::{Error, Kind},
    ui,
    units::{datetime, parse_duration},
};

/// The session name when none is given.
const SESSION_NAME: &str = "teifs";

#[derive(Subcommand)]
pub enum StsAction {
    /// Show whom an alias signs as: its ARN, user id and account.
    Whoami {
        /// The alias.
        alias: String,
    },
    /// Get temporary credentials: a role's session, or without a role (as MinIO has
    /// it) a session with the user's own permissions, narrowed by `--policy`.
    Assume(AssumeArgs),
    /// Exchange an OpenID Connect ID token (a CI job's) for temporary credentials: a
    /// role's session, or without a role the policies the token names, where the
    /// server allows it. Needs no keys.
    AssumeWeb(WebArgs),
}

/// `sts assume`'s arguments.
#[derive(Args)]
pub struct AssumeArgs {
    /// The alias to ask with.
    alias: String,
    /// The role: its name in the alias's account, or its ARN.
    role: Option<String>,
    /// The session's name, as the role's sessions show it.
    #[arg(long, default_value = SESSION_NAME)]
    session_name: String,
    /// The external id the role's trust policy asks for.
    #[arg(long)]
    external_id: Option<String>,
    /// A session tag, `KEY=VALUE` (repeatable).
    #[arg(long = "tag", value_name = "KEY=VALUE", value_parser = tag)]
    tags: Vec<(String, String)>,
    /// The source identity to set, kept along a chain of roles.
    #[arg(long)]
    source_identity: Option<String>,
    #[command(flatten)]
    session: SessionArgs,
}

/// `sts assume-web`'s arguments.
#[derive(Args)]
pub struct WebArgs {
    /// The server, like `https://s3.example.com`, or an alias for it.
    server: String,
    /// The role's ARN (or `AWS_ROLE_ARN`).
    #[arg(long, env = "AWS_ROLE_ARN")]
    role: Option<String>,
    /// The file with the token (or `AWS_WEB_IDENTITY_TOKEN_FILE`).
    #[arg(long, env = "AWS_WEB_IDENTITY_TOKEN_FILE")]
    token_file: PathBuf,
    /// The session's name (or `AWS_ROLE_SESSION_NAME`).
    #[arg(long, env = "AWS_ROLE_SESSION_NAME", default_value = SESSION_NAME)]
    session_name: String,
    /// The region to sign for.
    #[arg(long, default_value = alias::DEFAULT_REGION)]
    region: String,
    #[command(flatten)]
    session: SessionArgs,
}

/// What every new session takes, and where its credentials go.
#[derive(Args)]
pub struct SessionArgs {
    /// How long the credentials last, like `15m` or `12h` (the server's default
    /// otherwise: an hour for a role).
    #[arg(long, value_parser = parse_duration)]
    duration: Option<Duration>,
    /// A file with a session policy: the session may do only what it allows too.
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
    #[command(flatten)]
    output: Output,
}

/// Where temporary credentials go.
#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct Output {
    /// Save them as this alias, for the same server; an alias that already has
    /// temporary credentials is refreshed.
    #[arg(long, value_name = "ALIAS")]
    save_alias: Option<String>,
    /// Write them to this file (readable only by you), or to standard output with `-`,
    /// in the AWS CLI's `credential_process` format.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn tag(text: &str) -> Result<(String, String), String> {
    text.split_once('=')
        .filter(|(key, _)| !key.is_empty())
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .ok_or_else(|| format!("`{text}` isn't KEY=VALUE"))
}

pub async fn run(action: StsAction) -> Result<(), Error> {
    let mut aliases = Aliases::load()?;
    match action {
        StsAction::Whoami { alias } => {
            let server = signing(&aliases, &alias)?;
            whoami(&client(&server, true)).await
        }
        StsAction::Assume(args) => assume(args, &mut aliases).await,
        StsAction::AssumeWeb(args) => assume_web(args, &mut aliases).await,
    }
}

async fn assume(args: AssumeArgs, aliases: &mut Aliases) -> Result<(), Error> {
    let server = signing(aliases, &args.alias)?;
    args.session.output.check(aliases)?;
    let policy = args.session.policy()?;
    let seconds = args.session.seconds()?;
    let sts = client(&server, true);
    let request = sts
        .assume_role()
        .set_policy(policy)
        .set_duration_seconds(seconds);
    let answer = if let Some(role) = &args.role {
        let arn = role_arn(&sts, role).await?;
        let mut request = request
            .role_arn(&arn)
            .role_session_name(&args.session_name)
            .set_external_id(args.external_id)
            .set_source_identity(args.source_identity);
        for (key, value) in args.tags {
            request = request.tags(
                aws_sdk_sts::types::Tag::builder()
                    .key(key)
                    .value(value)
                    .build()
                    .map_err(|e| Error::usage(e.to_string()))?,
            );
        }
        request
            .send()
            .await
            .map_err(|e| Error::s3(format_args!("can't assume {arn}"), &e))?
    } else {
        if args.external_id.is_some() || !args.tags.is_empty() || args.source_identity.is_some() {
            return Err(
                Error::usage("--external-id, --tag and --source-identity are for a role")
                    .with_hint("name the role to assume"),
            );
        }
        // MinIO's AssumeRole: no role ARN.
        request
            .send()
            .await
            .map_err(|e| Error::s3("can't get temporary credentials for the alias's user", &e))?
    };
    let credentials = answer
        .credentials
        .ok_or_else(|| Error::general("the server answered without credentials"))?;
    deliver(&server, &credentials, &args.session.output, aliases)
}

async fn assume_web(args: WebArgs, aliases: &mut Aliases) -> Result<(), Error> {
    // Only the server: an alias's keys have no part.
    let server = if let Some((found, _)) = aliases.get(&args.server) {
        found.clone()
    } else {
        let mut server = Alias {
            url: alias::check_url(&args.server).map_err(Error::usage)?,
            access_key: String::new(),
            secret_key: String::new(),
            region: args.region,
            path_style: true,
            session_token: None,
            expires: None,
            ca_cert: None,
            trust: crate::client::trust::Trust::default(),
        };
        server.load_trust();
        server
    };
    server
        .trust
        .check()
        .map_err(|e| Error::usage(e).with_hint("fix the file TEIFS_CA_CERT or the alias names"))?;
    args.session.output.check(aliases)?;
    let policy = args.session.policy()?;
    let path = &args.token_file;
    let token = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| {
                Error::new(
                    Kind::NotFound,
                    format!("can't read the token file {}: {e}", path.display()),
                )
            })?
            .trim()
            .to_owned(),
    );
    let answer = client(&server, false)
        .assume_role_with_web_identity()
        .set_role_arn(args.role)
        .role_session_name(&args.session_name)
        .web_identity_token(token.as_str())
        .set_policy(policy)
        .set_duration_seconds(args.session.seconds()?)
        .send()
        .await
        .map_err(|e| Error::s3("the server didn't take the token", &e))?;
    let credentials = answer
        .credentials
        .ok_or_else(|| Error::general("the server answered without credentials"))?;
    deliver(&server, &credentials, &args.session.output, aliases)
}

/// The alias `name`, to sign with.
fn signing(aliases: &Aliases, name: &str) -> Result<Alias, Error> {
    let (found, _) = aliases.get(name).ok_or_else(|| {
        Error::new(Kind::NotFound, format!("there's no alias `{name}`"))
            .with_hint("see `teifs alias ls`, or add one with `teifs alias set`")
    })?;
    found.check_usable(name)?;
    Ok(found.clone())
}

/// An STS client for the alias's server, signing with its keys if `signed`.
pub(crate) fn client(alias: &Alias, signed: bool) -> Client {
    let mut config = aws_sdk_sts::Config::builder()
        .behavior_version_latest()
        .region(Region::new(alias.region.clone()))
        .endpoint_url(&alias.url);
    config.set_http_client(alias.trust.sdk_client());
    if signed {
        config = config.credentials_provider(alias.credentials());
    }
    Client::from_conf(config.build())
}

async fn whoami(sts: &Client) -> Result<(), Error> {
    let caller = sts
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| Error::s3("can't tell whom the alias signs as", &e))?;
    let (arn, user_id, account) = (
        caller.arn().unwrap_or_default(),
        caller.user_id().unwrap_or_default(),
        caller.account().unwrap_or_default(),
    );
    ui::details(
        &[
            ("ARN", arn.to_owned()),
            ("User id", user_id.to_owned()),
            ("Account", account.to_owned()),
        ],
        || json!({"type": "caller", "arn": arn, "userId": user_id, "account": account}),
    );
    Ok(())
}

/// A role's ARN: `role` if it is one, else the role of that name in the caller's
/// account.
async fn role_arn(sts: &Client, role: &str) -> Result<String, Error> {
    if role.starts_with("arn:") {
        return Ok(role.to_owned());
    }
    let account = caller_account(sts).await?;
    Ok(format!("arn:aws:iam::{account}:role/{role}"))
}

/// The account the alias's keys belong to.
pub(crate) async fn account(alias: &Alias) -> Result<String, Error> {
    caller_account(&client(alias, true)).await
}

async fn caller_account(sts: &Client) -> Result<String, Error> {
    let caller = sts
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| Error::s3("can't tell the alias's account", &e))?;
    caller
        .account()
        .map(str::to_owned)
        .ok_or_else(|| Error::general("the server didn't say the alias's account"))
}

impl SessionArgs {
    fn policy(&self) -> Result<Option<String>, Error> {
        self.policy
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path).map_err(|e| {
                    Error::new(
                        Kind::NotFound,
                        format!("can't read the policy file {}: {e}", path.display()),
                    )
                })
            })
            .transpose()
    }

    fn seconds(&self) -> Result<Option<i32>, Error> {
        self.duration
            .map(|d| {
                i32::try_from(d.as_secs())
                    .map_err(|_| Error::usage("--duration is longer than any session"))
            })
            .transpose()
    }
}

impl Output {
    /// Refuses a place the credentials couldn't go, before asking for them.
    fn check(&self, aliases: &Aliases) -> Result<(), Error> {
        if let Some(name) = &self.save_alias {
            check_name(name).map_err(Error::usage)?;
            if let Some((existing, _)) = aliases.get(name)
                && existing.session_token.is_none()
            {
                return Err(Error::new(
                    Kind::Conflict,
                    format!("alias `{name}` has long-term keys, which this would replace"),
                )
                .with_hint("choose another name"));
            }
        }
        if let Some(path) = self.file()
            && path.exists()
        {
            return Err(
                Error::new(Kind::Conflict, format!("{} already exists", path.display()))
                    .with_hint("choose another file"),
            );
        }
        Ok(())
    }

    fn file(&self) -> Option<&std::path::Path> {
        self.output
            .as_deref()
            .filter(|p| *p != std::path::Path::new("-"))
    }
}

/// Puts temporary credentials where `output` says.
fn deliver(
    server: &Alias,
    credentials: &Credentials,
    output: &Output,
    aliases: &mut Aliases,
) -> Result<(), Error> {
    let expires_ms = credentials.expiration().to_millis().unwrap_or_default();
    let id = credentials.access_key_id();
    if let Some(name) = &output.save_alias {
        let alias = Alias {
            access_key: id.to_owned(),
            secret_key: credentials.secret_access_key().to_owned(),
            session_token: Some(credentials.session_token().to_owned()),
            expires: Some(datetime(expires_ms)),
            ..server.clone()
        };
        aliases.set(name, alias)?;
        let until = crate::units::date(crate::units::from_ms(expires_ms));
        ui::done(
            format!("Saved temporary credentials {id} as alias `{name}`, until {until} UTC"),
            || {
                json!({
                    "type": "credentials", "accessKey": id, "alias": name,
                    "expiresMs": expires_ms,
                })
            },
        );
        return Ok(());
    }
    // The AWS CLI's `credential_process` format, which the AWS SDKs read too.
    let record = Zeroizing::new(
        json!({
            "Version": 1,
            "AccessKeyId": id,
            "SecretAccessKey": credentials.secret_access_key(),
            "SessionToken": credentials.session_token(),
            "Expiration": crate::units::rfc3339(crate::units::from_ms(expires_ms)),
        })
        .to_string(),
    );
    match output.file() {
        // `--output -`: the one place the secret goes to standard output, as asked.
        None => ui::document(&record),
        Some(path) => {
            teifs_store::create_private(path, record.as_bytes())
                .map_err(|e| Error::general(format!("can't write {}: {e}", path.display())))?;
            ui::done(
                format!("Wrote temporary credentials {id} to {}", path.display()),
                || {
                    json!({
                        "type": "credentials", "accessKey": id,
                        "file": path.display().to_string(), "expiresMs": expires_ms,
                    })
                },
            );
        }
    }
    Ok(())
}
