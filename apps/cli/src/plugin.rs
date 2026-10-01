//! The identity plugin `teifs serve` checks custom tokens with (MinIO's
//! `AssumeRoleWithCustomToken`), and that `teifs doctor` checks. The `Authorization`
//! header it's sent never comes from a flag: `TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN`.
//!
//! MinIO's `MINIO_IDENTITY_PLUGIN_*` variables work as well when
//! `--identity-plugin-url` isn't given, so a MinIO deployment's environment carries over.

use std::path::PathBuf;

use teifs_client::Zeroizing;
use teifs_server::{PluginSettings, read_authorities};

use crate::error::{Error, Kind};

/// The plugin's settings.
#[derive(clap::Args, Clone, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "each field is a flag, named as clap names it"
)]
pub(crate) struct PluginArgs {
    /// Check custom tokens with this identity plugin (an `http(s)` URL), as MinIO's
    /// `AssumeRoleWithCustomToken`: it's sent each token and answers whom it's for. The
    /// `Authorization` header it's sent comes from `TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN`.
    #[arg(long, env = "TEIFS_IDENTITY_PLUGIN_URL", value_name = "URL")]
    pub identity_plugin_url: Option<String>,
    /// The managed policies its users' sessions get (repeatable, or comma-separated).
    #[arg(
        long,
        env = "TEIFS_IDENTITY_PLUGIN_ROLE_POLICY",
        requires = "identity_plugin_url",
        value_name = "NAMES",
        value_delimiter = ','
    )]
    pub identity_plugin_role_policy: Vec<String>,
    /// The id in the role ARN clients name, `arn:minio:iam:::role/idmp-<ID>` (default:
    /// derived from the URL, as MinIO derives it).
    #[arg(
        long,
        env = "TEIFS_IDENTITY_PLUGIN_ROLE_ID",
        requires = "identity_plugin_url",
        value_name = "ID"
    )]
    pub identity_plugin_role_id: Option<String>,
    /// Certificate authorities (PEM: a file, or a folder of them) its certificate may be
    /// issued by, besides the system's.
    #[arg(
        long,
        env = "TEIFS_IDENTITY_PLUGIN_CA",
        requires = "identity_plugin_url",
        value_name = "PATH"
    )]
    pub identity_plugin_ca: Option<PathBuf>,
}

/// The `Authorization` header it's sent.
const AUTH_TOKEN: &str = "TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN";
/// MinIO's variables.
const MINIO: &str = "MINIO_IDENTITY_PLUGIN_";

impl PluginArgs {
    /// The plugin these settings (or MinIO's variables) name, if any.
    pub(crate) fn settings(&self) -> Result<Option<PluginSettings>, Error> {
        self.settings_with(&|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
    }

    fn settings_with(
        &self,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<PluginSettings>, Error> {
        let minio = |name: &str| env(&format!("{MINIO}{name}"));
        let given = match &self.identity_plugin_url {
            Some(_) => self.clone(),
            None => match minio("URL") {
                Some(url) => Self {
                    identity_plugin_url: Some(url),
                    identity_plugin_role_policy: minio("ROLE_POLICY")
                        .map(|v| vec![v])
                        .unwrap_or_default(),
                    identity_plugin_role_id: minio("ROLE_ID"),
                    identity_plugin_ca: None,
                },
                None => return Ok(None),
            },
        };
        let ca = match &given.identity_plugin_ca {
            Some(path) => read_authorities(path).map_err(|e| {
                Error::new(
                    Kind::NotFound,
                    format!("can't read the identity plugin's CA certificates: {e}"),
                )
            })?,
            None => Vec::new(),
        };
        Ok(Some(PluginSettings {
            url: given.identity_plugin_url.unwrap_or_default(),
            auth_token: env(AUTH_TOKEN)
                .or_else(|| minio("AUTH_TOKEN"))
                .map(Zeroizing::new),
            role_policies: given.identity_plugin_role_policy,
            role_id: given.identity_plugin_role_id,
            ca,
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use std::collections::HashMap;

    use super::*;

    fn settings(args: &PluginArgs, vars: &[(&str, &str)]) -> Option<PluginSettings> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        args.settings_with(&|name| vars.get(name).cloned()).unwrap()
    }

    #[test]
    fn the_flags_or_minio_s_variables_name_the_plugin() {
        assert!(settings(&PluginArgs::default(), &[]).is_none());
        let flags = PluginArgs {
            identity_plugin_url: Some("https://idp.example/check".into()),
            identity_plugin_role_policy: vec!["readonly".into()],
            identity_plugin_role_id: Some("ci".into()),
            identity_plugin_ca: None,
        };
        let given = settings(
            &flags,
            &[
                (AUTH_TOKEN, "Bearer ours"),
                ("MINIO_IDENTITY_PLUGIN_URL", "https://theirs"),
            ],
        )
        .unwrap();
        assert_eq!(given.url, "https://idp.example/check");
        assert_eq!(given.role_policies, ["readonly"]);
        assert_eq!(given.role_id.as_deref(), Some("ci"));
        assert_eq!(
            given.auth_token.as_deref().map(String::as_str),
            Some("Bearer ours")
        );

        let minio = settings(
            &PluginArgs::default(),
            &[
                ("MINIO_IDENTITY_PLUGIN_URL", "https://theirs"),
                ("MINIO_IDENTITY_PLUGIN_ROLE_POLICY", "a,b"),
                ("MINIO_IDENTITY_PLUGIN_ROLE_ID", "x"),
                ("MINIO_IDENTITY_PLUGIN_AUTH_TOKEN", "Bearer theirs"),
            ],
        )
        .unwrap();
        assert_eq!(minio.url, "https://theirs");
        assert_eq!(minio.role_policies, ["a,b"]);
        assert_eq!(minio.role_id.as_deref(), Some("x"));
        assert_eq!(
            minio.auth_token.as_deref().map(String::as_str),
            Some("Bearer theirs")
        );

        let missing = PluginArgs {
            identity_plugin_ca: Some("/nonexistent/ca.pem".into()),
            ..flags
        };
        let err = missing.settings_with(&|_| None).unwrap_err();
        assert!(err.to_string().contains("CA certificates"), "{err}");
    }
}
