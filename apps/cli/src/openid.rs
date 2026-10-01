//! The OpenID Connect provider `teifs serve` makes, or keeps in line with its settings,
//! when it starts, as MinIO's `identity_openid` configuration has it: tokens it issues
//! for the client then get credentials from `AssumeRoleWithWebIdentity`.
//!
//! MinIO's `MINIO_IDENTITY_OPENID_*` variables work as well when `--openid-config-url`
//! isn't given, each provider's with its own suffix (`MINIO_IDENTITY_OPENID_CONFIG_URL`,
//! `MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK`…), so a MinIO deployment's environment
//! carries over.

use std::collections::BTreeMap;

use teifs_server::ConfiguredOidcProvider;

use crate::error::Error;

/// The provider's settings.
#[derive(clap::Args, Clone, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "each field is a flag, named as clap names it"
)]
pub(crate) struct OpenIdArgs {
    /// Make an OpenID Connect provider, or keep it in line with these settings, when the
    /// server starts: its discovery URL (`https://…/.well-known/openid-configuration`) or
    /// its issuer, as MinIO's `config_url`.
    #[arg(long, env = "TEIFS_OPENID_CONFIG_URL", value_name = "URL")]
    pub openid_config_url: Option<String>,
    /// The client its tokens are for (their `aud` or `azp`).
    #[arg(long, env = "TEIFS_OPENID_CLIENT_ID", value_name = "ID")]
    pub openid_client_id: Option<String>,
    /// Give every token for the client these managed policies when it names the client's
    /// role (`arn:minio:iam:::role/…`), as MinIO's `role_policy` (repeatable, or
    /// comma-separated).
    #[arg(
        long,
        env = "TEIFS_OPENID_ROLE_POLICY",
        value_name = "NAMES",
        value_delimiter = ','
    )]
    pub openid_role_policy: Vec<String>,
    /// Without role policies, the claim that names a token's managed policies (default:
    /// `policy`), as MinIO's `claim_name`.
    #[arg(long, env = "TEIFS_OPENID_CLAIM_NAME", value_name = "CLAIM")]
    pub openid_claim_name: Option<String>,
    /// Complete tokens' claims from the provider's userinfo endpoint, with the access
    /// token a request gives, as MinIO's `claim_userinfo`.
    #[arg(long, env = "TEIFS_OPENID_CLAIM_USERINFO")]
    pub openid_claim_userinfo: bool,
}

/// MinIO's variables.
const MINIO: &str = "MINIO_IDENTITY_OPENID_";
/// The end of a discovery URL; what's before it is the issuer.
const DISCOVERY: &str = "/.well-known/openid-configuration";

impl OpenIdArgs {
    /// The providers these settings (or MinIO's variables, `env`) name.
    pub(crate) fn providers_with(
        &self,
        env: &BTreeMap<String, String>,
    ) -> Result<Vec<ConfiguredOidcProvider>, Error> {
        if let Some(url) = &self.openid_config_url {
            let Some(client_id) = &self.openid_client_id else {
                return Err(Error::usage(
                    "--openid-config-url needs --openid-client-id, the client its tokens are for",
                ));
            };
            return Ok(vec![provider(
                url,
                client_id,
                &self.openid_role_policy,
                self.openid_claim_name.as_deref(),
                self.openid_claim_userinfo,
            )?]);
        }
        if self.openid_client_id.is_some()
            || !self.openid_role_policy.is_empty()
            || self.openid_claim_name.is_some()
            || self.openid_claim_userinfo
        {
            return Err(Error::usage(
                "the --openid-* settings need --openid-config-url, the provider's URL",
            ));
        }
        let urls = env
            .iter()
            .filter_map(|(name, url)| Some((name.strip_prefix(MINIO)?, url)))
            .filter_map(|(name, url)| Some((name.strip_prefix("CONFIG_URL")?, url)))
            .filter(|(suffix, _)| suffix.is_empty() || suffix.starts_with('_'));
        let mut providers = Vec::new();
        for (suffix, url) in urls {
            let get = |key: &str| {
                env.get(&format!("{MINIO}{key}{suffix}"))
                    .map(String::as_str)
            };
            let name = format!("{MINIO}CONFIG_URL{suffix}");
            if !switch(&format!("{MINIO}ENABLE{suffix}"), get("ENABLE"), true)? {
                continue;
            }
            let Some(client_id) = get("CLIENT_ID") else {
                return Err(Error::usage(format!(
                    "{name} needs {MINIO}CLIENT_ID{suffix}, the client its tokens are for"
                )));
            };
            let role_policies: Vec<String> = get("ROLE_POLICY")
                .unwrap_or_default()
                .split(',')
                .map(str::to_owned)
                .collect();
            providers.push(provider(
                url,
                client_id,
                &role_policies,
                get("CLAIM_NAME"),
                switch(
                    &format!("{MINIO}CLAIM_USERINFO{suffix}"),
                    get("CLAIM_USERINFO"),
                    false,
                )?,
            )?);
        }
        Ok(providers)
    }
}

/// The provider at `url` (a discovery URL or an issuer), for `client_id`.
fn provider(
    url: &str,
    client_id: &str,
    role_policies: &[String],
    claim_name: Option<&str>,
    claim_userinfo: bool,
) -> Result<ConfiguredOidcProvider, Error> {
    let url = url.trim();
    let role_policies: Vec<String> = role_policies
        .iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let claim_name = claim_name.map(str::trim).filter(|c| !c.is_empty());
    if !role_policies.is_empty() && claim_name.is_some() {
        return Err(Error::usage(format!(
            "the OpenID Connect provider {url} can't have both role policies and a claim \
             name: tokens for a role get the role's policies"
        )));
    }
    Ok(ConfiguredOidcProvider {
        url: url.strip_suffix(DISCOVERY).unwrap_or(url).to_owned(),
        client_id: client_id.trim().to_owned(),
        role_policies,
        claim_name: claim_name.map(str::to_owned),
        claim_userinfo,
    })
}

/// An on or off setting of MinIO's, `default` if it isn't given.
fn switch(name: &str, value: Option<&str>, default: bool) -> Result<bool, Error> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "enable" | "enabled" | "1" => Ok(true),
        "off" | "false" | "disable" | "disabled" | "0" => Ok(false),
        _ => Err(Error::usage(format!("{name} is on or off, not {value}"))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    fn providers(
        args: &OpenIdArgs,
        vars: &[(&str, &str)],
    ) -> Result<Vec<ConfiguredOidcProvider>, Error> {
        let vars = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        args.providers_with(&vars)
    }

    #[test]
    fn the_flags_name_a_provider_by_its_discovery_url_or_issuer() {
        assert!(providers(&OpenIdArgs::default(), &[]).unwrap().is_empty());
        let flags = OpenIdArgs {
            openid_config_url: Some(
                "https://sso.example.com/realms/a/.well-known/openid-configuration".into(),
            ),
            openid_client_id: Some("teifs".into()),
            openid_role_policy: vec!["readonly".into(), " ".into(), "diagnostics".into()],
            openid_claim_name: None,
            openid_claim_userinfo: true,
        };
        // The flags win over MinIO's variables.
        let given = providers(
            &flags,
            &[("MINIO_IDENTITY_OPENID_CONFIG_URL", "https://theirs")],
        )
        .unwrap();
        assert_eq!(
            given,
            [ConfiguredOidcProvider {
                url: "https://sso.example.com/realms/a".into(),
                client_id: "teifs".into(),
                role_policies: vec!["readonly".into(), "diagnostics".into()],
                claim_name: None,
                claim_userinfo: true,
            }]
        );
        let issuer = OpenIdArgs {
            openid_config_url: Some("https://sso.example.com".into()),
            openid_role_policy: Vec::new(),
            openid_claim_name: Some("groups".into()),
            ..flags.clone()
        };
        let given = providers(&issuer, &[]).unwrap();
        assert_eq!(given[0].url, "https://sso.example.com");
        assert_eq!(given[0].claim_name.as_deref(), Some("groups"));

        for (args, words) in [
            (
                OpenIdArgs {
                    openid_client_id: None,
                    ..flags.clone()
                },
                "needs --openid-client-id",
            ),
            (
                OpenIdArgs {
                    openid_config_url: None,
                    ..flags.clone()
                },
                "need --openid-config-url",
            ),
            (
                OpenIdArgs {
                    openid_claim_name: Some("groups".into()),
                    ..flags
                },
                "both role policies and a claim name",
            ),
        ] {
            let err = providers(&args, &[]).unwrap_err().to_string();
            assert!(err.contains(words), "{err}");
        }
    }

    #[test]
    fn minio_s_variables_name_a_provider_for_each_suffix() {
        let given = providers(
            &OpenIdArgs::default(),
            &[
                (
                    "MINIO_IDENTITY_OPENID_CONFIG_URL",
                    "https://a.example.com/.well-known/openid-configuration",
                ),
                ("MINIO_IDENTITY_OPENID_CLIENT_ID", "app"),
                ("MINIO_IDENTITY_OPENID_CLAIM_NAME", "groups"),
                (
                    "MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK",
                    "https://kc.example.com/realms/r/.well-known/openid-configuration",
                ),
                ("MINIO_IDENTITY_OPENID_CLIENT_ID_KEYCLOAK", "minio"),
                (
                    "MINIO_IDENTITY_OPENID_ROLE_POLICY_KEYCLOAK",
                    "readonly,writeonly",
                ),
                ("MINIO_IDENTITY_OPENID_CLAIM_USERINFO_KEYCLOAK", "on"),
                (
                    "MINIO_IDENTITY_OPENID_CONFIG_URL_OFF",
                    "https://off.example.com",
                ),
                ("MINIO_IDENTITY_OPENID_CLIENT_ID_OFF", "x"),
                ("MINIO_IDENTITY_OPENID_ENABLE_OFF", "off"),
                // Not a suffix of CONFIG_URL's.
                ("MINIO_IDENTITY_OPENID_CONFIG_URLX", "https://x.example.com"),
            ],
        )
        .unwrap();
        assert_eq!(
            given,
            [
                ConfiguredOidcProvider {
                    url: "https://a.example.com".into(),
                    client_id: "app".into(),
                    role_policies: Vec::new(),
                    claim_name: Some("groups".into()),
                    claim_userinfo: false,
                },
                ConfiguredOidcProvider {
                    url: "https://kc.example.com/realms/r".into(),
                    client_id: "minio".into(),
                    role_policies: vec!["readonly".into(), "writeonly".into()],
                    claim_name: None,
                    claim_userinfo: true,
                },
            ]
        );

        for (vars, words) in [
            (
                &[(
                    "MINIO_IDENTITY_OPENID_CONFIG_URL_A",
                    "https://a.example.com",
                )][..],
                "MINIO_IDENTITY_OPENID_CONFIG_URL_A needs MINIO_IDENTITY_OPENID_CLIENT_ID_A",
            ),
            (
                &[
                    ("MINIO_IDENTITY_OPENID_CONFIG_URL", "https://a.example.com"),
                    ("MINIO_IDENTITY_OPENID_CLIENT_ID", "app"),
                    ("MINIO_IDENTITY_OPENID_CLAIM_USERINFO", "maybe"),
                ][..],
                "MINIO_IDENTITY_OPENID_CLAIM_USERINFO is on or off, not maybe",
            ),
        ] {
            let err = providers(&OpenIdArgs::default(), vars)
                .unwrap_err()
                .to_string();
            assert!(err.contains(words), "{err}");
        }
    }
}
