//! Aliases: a name for an S3 endpoint and the keys to use there, so a path like
//! `home/photos/cat.jpg` means the object `cat.jpg` in the bucket `photos` at `home`.
//!
//! They're kept in `aliases.toml` in the user's configuration folder (or the file
//! `TEIFS_CLIENT_CONFIG` names), readable only by its owner as `~/.aws/credentials` is.
//! `TEIFS_ALIAS_<NAME>=https://ACCESS_KEY:SECRET_KEY@host` defines one for a single run
//! (in CI, say), and wins over the file; `https://ACCESS_KEY:SECRET_KEY:SESSION_TOKEN@host`
//! one with temporary credentials, as MinIO's `mc` takes them.
//!
//! An alias with temporary credentials (`teifs sts assume`) keeps their session token
//! and when they expire.

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};

use aws_sdk_s3::{
    Client,
    config::{Credentials, Region},
};
use serde::{Deserialize, Serialize};

use super::Error;

/// The environment variable that points at another aliases file.
pub const CONFIG_ENV: &str = "TEIFS_CLIENT_CONFIG";
/// The prefix of the environment variables that define an alias for one run.
pub const ENV_PREFIX: &str = "TEIFS_ALIAS_";
/// The region clients sign for when an alias doesn't name one.
pub const DEFAULT_REGION: &str = "us-east-1";

/// An endpoint and the keys to use there.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Alias {
    /// `http(s)://host[:port]`, without a path.
    pub url: String,
    pub access_key: String,
    /// Never printed: `Debug` leaves it out.
    pub secret_key: String,
    #[serde(default = "default_region")]
    pub region: String,
    /// Buckets as the first part of the path (`host/bucket/key`), as TeiFS, MinIO and
    /// most self-hosted servers expect, rather than as a host name (`bucket.host/key`).
    #[serde(default = "yes")]
    pub path_style: bool,
    /// Temporary credentials' session token. Never printed, as the secret key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    /// When temporary credentials expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<toml::value::Datetime>,
}

fn default_region() -> String {
    DEFAULT_REGION.to_owned()
}

const fn yes() -> bool {
    true
}

impl fmt::Debug for Alias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Alias")
            .field("url", &self.url)
            .field("access_key", &self.access_key)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .field("temporary", &self.session_token.is_some())
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

impl Alias {
    /// Its keys, as the AWS SDKs take them.
    pub fn credentials(&self) -> Credentials {
        Credentials::new(
            &self.access_key,
            &self.secret_key,
            self.session_token.clone(),
            None,
            "teifs-alias",
        )
    }

    /// An S3 client for this alias.
    pub fn client(&self) -> Client {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .region(Region::new(self.region.clone()))
            .endpoint_url(&self.url)
            .credentials_provider(self.credentials())
            .force_path_style(self.path_style)
            .build();
        Client::from_conf(config)
    }

    /// When its temporary credentials expire, in milliseconds since the Unix epoch.
    pub fn expires_ms(&self) -> Option<i64> {
        self.expires.as_ref().and_then(crate::units::datetime_ms)
    }

    /// Whether its temporary credentials have expired.
    pub fn expired(&self) -> bool {
        self.expires_ms()
            .is_some_and(|ms| ms <= crate::units::now_ms())
    }

    /// Refuses the alias `name` when its temporary credentials have expired, before a
    /// request fails with them.
    pub fn check_fresh(&self, name: &str) -> Result<(), Error> {
        match self.expires_ms() {
            Some(ms) if self.expired() => Err(Error::new(
                super::Kind::Auth,
                format!(
                    "the temporary credentials of alias `{name}` expired at {} UTC",
                    crate::units::date(crate::units::from_ms(ms))
                ),
            )
            .with_hint("get new ones with `teifs sts assume`")),
            _ => Ok(()),
        }
    }
}

/// The aliases file's contents.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    aliases: BTreeMap<String, Alias>,
}

/// Where an alias was defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    File,
    Env,
}

/// The aliases from the file and the environment.
#[derive(Debug)]
pub struct Aliases {
    path: PathBuf,
    file: File,
    env: BTreeMap<String, Alias>,
}

impl Aliases {
    /// Reads the aliases file (none yet is fine) and `TEIFS_ALIAS_*`.
    pub fn load() -> Result<Self, Error> {
        let path = path()?;
        let file = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|e| {
                Error::usage(format!(
                    "the aliases file {} isn't valid: {}",
                    path.display(),
                    e.message()
                ))
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => {
                return Err(Error::general(format!(
                    "can't read the aliases file {}: {e}",
                    path.display()
                )));
            }
        };
        let mut env = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            let Some(name) = name.to_str().and_then(|n| n.strip_prefix(ENV_PREFIX)) else {
                continue;
            };
            let name = name.to_ascii_lowercase();
            let value = value
                .to_str()
                .ok_or_else(|| Error::usage(format!("{ENV_PREFIX}{name} isn't valid Unicode")))?;
            let alias =
                from_env(value).map_err(|e| Error::usage(format!("{ENV_PREFIX}{name}: {e}")))?;
            env.insert(name, alias);
        }
        Ok(Self { path, file, env })
    }

    /// The file aliases are saved in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The alias called `name`.
    pub fn get(&self, name: &str) -> Option<(&Alias, Origin)> {
        self.env
            .get(name)
            .map(|a| (a, Origin::Env))
            .or_else(|| self.file.aliases.get(name).map(|a| (a, Origin::File)))
    }

    /// Every alias by name; one set in the environment hides the file's.
    pub fn all(&self) -> Vec<(&str, &Alias, Origin)> {
        let mut all: BTreeMap<&str, (&Alias, Origin)> = self
            .file
            .aliases
            .iter()
            .map(|(n, a)| (n.as_str(), (a, Origin::File)))
            .collect();
        all.extend(self.env.iter().map(|(n, a)| (n.as_str(), (a, Origin::Env))));
        all.into_iter().map(|(n, (a, o))| (n, a, o)).collect()
    }

    /// Adds or replaces `name` in the file, and saves it.
    pub fn set(&mut self, name: &str, alias: Alias) -> Result<(), Error> {
        self.file.aliases.insert(name.to_owned(), alias);
        self.save()
    }

    /// Removes `name` from the file and saves it; whether it was there.
    pub fn remove(&mut self, name: &str) -> Result<bool, Error> {
        let removed = self.file.aliases.remove(name).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<(), Error> {
        let failed = |e: &dyn fmt::Display| {
            Error::general(format!(
                "can't save the aliases file {}: {e}",
                self.path.display()
            ))
        };
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| failed(&e))?;
        }
        let text = toml::to_string_pretty(&self.file).map_err(|e| failed(&e))?;
        let text = format!(
            "# TeiFS aliases (`teifs alias`). Holds secret keys: keep it private.\n\n{text}"
        );
        teifs_store::replace_private(&self.path, text.as_bytes()).map_err(|e| failed(&e))
    }
}

fn path() -> Result<PathBuf, Error> {
    if let Some(path) = std::env::var_os(CONFIG_ENV).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    dirs::config_dir()
        .map(|dir| dir.join("teifs").join("aliases.toml"))
        .ok_or_else(|| {
            Error::general(format!(
                "can't find this user's configuration folder; set {CONFIG_ENV} to a file for the aliases"
            ))
        })
}

/// Checks an alias name: a lowercase letter or digit, then letters, digits, `-` or `_`,
/// at most 32. No dots or slashes, so it can't be mistaken for a file or a path.
pub fn check_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = name.len() <= 32
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "`{name}` can't be an alias: use up to 32 lowercase letters, digits, `-` and `_`, starting with a letter or digit"
        ))
    }
}

/// Checks an endpoint URL and returns it without a trailing `/`.
pub fn check_url(url: &str) -> Result<String, String> {
    let url = url.trim().trim_end_matches('/');
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!("`{url}` needs to start with http:// or https://"));
    };
    if !matches!(scheme, "http" | "https") {
        return Err(format!("`{url}` needs to start with http:// or https://"));
    }
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(format!(
            "`{url}` should be only the server's address, like https://s3.example.com or http://127.0.0.1:9000"
        ));
    }
    Ok(url.to_owned())
}

/// Parses `https://ACCESS_KEY:SECRET_KEY[:SESSION_TOKEN]@host[:port]` (each
/// percent-encoded if needed).
fn from_env(value: &str) -> Result<Alias, String> {
    let bad = || "expected https://ACCESS_KEY:SECRET_KEY@host".to_owned();
    let (scheme, rest) = value.split_once("://").ok_or_else(bad)?;
    let (keys, host) = rest.rsplit_once('@').ok_or_else(bad)?;
    let mut parts = keys.split(':');
    let (Some(access), Some(secret), token, None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let (access, secret) = (percent_decode(access)?, percent_decode(secret)?);
    let token = token.map(percent_decode).transpose()?;
    if access.is_empty() || secret.is_empty() || token.as_ref().is_some_and(String::is_empty) {
        return Err(bad());
    }
    Ok(Alias {
        url: check_url(&format!("{scheme}://{host}"))?,
        access_key: access,
        secret_key: secret,
        region: default_region(),
        path_style: true,
        session_token: token,
        expires: None,
    })
}

pub(crate) fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or("a `%` isn't followed by two hex digits")?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the keys aren't valid UTF-8 once decoded".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_short_lowercase_words() {
        for good in ["home", "s3", "my-nas", "backup_2", "0"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", "Home", "-x", "_x", "a.b", "a/b", "c:", &"a".repeat(33)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn urls_are_only_a_scheme_and_a_host() {
        assert_eq!(
            check_url("http://127.0.0.1:9000/").unwrap(),
            "http://127.0.0.1:9000"
        );
        assert_eq!(
            check_url("https://s3.example.com").unwrap(),
            "https://s3.example.com"
        );
        for bad in [
            "127.0.0.1:9000",
            "ftp://x",
            "https://",
            "https://x/bucket",
            "https://k:s@x",
            "https://x?a",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn environment_aliases_carry_their_keys_in_the_url() {
        let alias = from_env("https://AKID:se%2Fcr%40et@s3.example.com:9000").unwrap();
        assert_eq!(alias.url, "https://s3.example.com:9000");
        assert_eq!(alias.access_key, "AKID");
        assert_eq!(alias.secret_key, "se/cr@et");
        assert_eq!(alias.session_token, None);
        let temporary = from_env("https://TSIA:secret:to%2Bken%3D@h").unwrap();
        assert_eq!(temporary.session_token.as_deref(), Some("to+ken="));
        for bad in [
            "https://a:b:@h",
            "https://a:b:c:d@h",
            "https://s3.example.com",
            "https://:s@h",
            "https://a:@h",
            "a:b@h",
            "https://a:b%zz@h",
            "https://a:b@h/path",
        ] {
            assert!(from_env(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let alias = from_env("https://AKID:very-secret-key:session-token@h").unwrap();
        let debug = format!("{alias:?}");
        assert!(!debug.contains("very-secret-key") && !debug.contains("session-token"));
        assert!(debug.contains("temporary: true"), "{debug}");
    }
}
