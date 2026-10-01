//! The drive's `MinIO` key-value configuration (`.teifs/config.kv`, which `mc admin
//! config set` changes) under `serve`'s other settings: each value stands for the `MinIO`
//! variable that names it, read only when the environment doesn't set that variable, and
//! `MinIO`'s variables are only read when no flag, `TEIFS_*` variable or settings file
//! names the setting. So it's the last word on nothing, as `MinIO`'s environment wins over
//! its stored configuration.

use std::{collections::BTreeMap, path::Path, sync::Arc};

use teifs_server::{ConfiguredOidcProvider, LdapSettings, PluginSettings};
use teifs_store::ConfigFiles;
use teifs_types::config_kv::{ConfigKv, VARIABLE_PREFIX};

use crate::{
    ServeArgs,
    error::Error,
    ldap::LdapArgs,
    minio_targets::{MinioTargets, minio_targets},
    openid::OpenIdArgs,
    plugin::PluginArgs,
};

/// TeiFS's own variables, which name secrets the settings don't
/// (`TEIFS_LDAP_LOOKUP_BIND_PASSWORD`).
const TEIFS_PREFIX: &str = "TEIFS_";

/// How clients sign in, as `serve` starts with it.
pub(crate) struct Identity {
    pub(crate) ldap: Option<LdapSettings>,
    pub(crate) plugin: Option<PluginSettings>,
    pub(crate) openid: Vec<ConfiguredOidcProvider>,
}

/// `serve`'s settings for how clients sign in.
#[derive(Clone)]
pub(crate) struct IdentityArgs {
    ldap: LdapArgs,
    plugin: PluginArgs,
    openid: OpenIdArgs,
}

impl IdentityArgs {
    pub(crate) fn of(args: &ServeArgs) -> Self {
        Self {
            ldap: args.ldap.clone(),
            plugin: args.identity_plugin.clone(),
            openid: args.openid.clone(),
        }
    }

    /// The settings, with `stored` (the drive's configuration's variables) under the
    /// environment's: `MinIO`'s variables and TeiFS's own secrets (`TEIFS_*`).
    pub(crate) fn settings(&self, stored: &BTreeMap<String, String>) -> Result<Identity, Error> {
        self.settings_with(stored, &env())
    }

    fn settings_with(
        &self,
        stored: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
    ) -> Result<Identity, Error> {
        let set = |value: &&String| !value.trim().is_empty();
        let lookup = |name: &str| {
            env.get(name)
                .filter(set)
                .or_else(|| stored.get(name).filter(set))
                .cloned()
        };
        // OpenID's providers are found by their variables' names: the stored ones,
        // with the environment's over them.
        let mut variables = stored.clone();
        variables.extend(env.iter().map(|(k, v)| (k.clone(), v.clone())));
        variables.retain(|name, value| name.starts_with(VARIABLE_PREFIX) && set(&&*value));
        Ok(Identity {
            ldap: self.ldap.settings_with(&lookup)?,
            plugin: self.plugin.settings_with(&lookup)?,
            openid: self.openid.providers_with(&variables)?,
        })
    }

    /// The check a change to the drive's configuration gets: `serve` must still start.
    pub(crate) fn check(self) -> teifs_server::ConfigCheck {
        teifs_server::ConfigCheck(Arc::new(move |config: &ConfigKv| {
            let env = env();
            self.settings_with(&config.variables(), &env)
                .map_err(|err| err.to_string())
                .and_then(|_| targets(config, &env).map(|_| ()))
                .map_err(|err| format!("TeiFS wouldn't start with it: {err}"))
        }))
    }
}

/// `MinIO`'s variables and TeiFS's own.
fn env() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(name, _)| name.starts_with(VARIABLE_PREFIX) || name.starts_with(TEIFS_PREFIX))
        .collect()
}

/// The targets `MinIO`'s settings name, checked as `serve` checks them, with their
/// secrets.
fn targets(config: &ConfigKv, env: &BTreeMap<String, String>) -> Result<MinioTargets, String> {
    let mut targets = minio_targets(config, env)?;
    targets.notify = crate::notify_targets(std::mem::take(&mut targets.notify), |name| {
        targets.secret(env.get(name).cloned(), name)
    })?;
    Ok(targets)
}

/// The variables the drive's configuration stands for.
pub(crate) fn stored(drive: &Path) -> Result<BTreeMap<String, String>, String> {
    ConfigFiles::new(drive)
        .load()
        .map(|config| config.variables())
        .map_err(|err| format!("can't read the drive's MinIO configuration: {err}"))
}

/// How clients sign in to the drive's server.
pub(crate) fn identity(args: &ServeArgs) -> Result<Identity, String> {
    IdentityArgs::of(args)
        .settings(&stored(&args.dir)?)
        .map_err(|err| err.to_string())
}

/// What the drive's configuration and `MinIO`'s variables start `serve` with.
pub(crate) struct Started {
    pub(crate) identity: Identity,
    /// The targets they name, with their secrets read.
    pub(crate) targets: MinioTargets,
    /// `MinIO`'s variables: the environment's, else the configuration's.
    pub(crate) variables: BTreeMap<String, String>,
    /// The check the configuration's changes get.
    pub(crate) check: teifs_server::ConfigCheck,
}

/// What `serve` starts with from the drive's configuration and `MinIO`'s variables.
pub(crate) fn started(args: &ServeArgs) -> Result<Started, String> {
    let config = ConfigFiles::new(&args.dir)
        .load()
        .map_err(|err| format!("can't read the drive's MinIO configuration: {err}"))?;
    let stored = config.variables();
    let env = env();
    let identity_args = IdentityArgs::of(args);
    let identity = identity_args
        .settings_with(&stored, &env)
        .map_err(|err| err.to_string())?;
    let targets = minio_targets(&config, &env)?;
    let mut variables = stored;
    variables.extend(
        env.into_iter()
            .filter(|(name, value)| name.starts_with(VARIABLE_PREFIX) && !value.trim().is_empty()),
    );
    Ok(Started {
        identity,
        targets,
        variables,
        check: identity_args.check(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn args() -> IdentityArgs {
        IdentityArgs {
            ldap: LdapArgs::default(),
            plugin: PluginArgs::default(),
            openid: OpenIdArgs::default(),
        }
    }

    #[test]
    fn the_stored_configuration_is_read_after_the_environment() {
        let stored = ConfigKv::parse(
            "identity_ldap server_addr=stored.example.com:636 lookup_bind_dn=cn=stored\n\
             identity_openid:k config_url=https://k.example.com client_id=k\n\
             identity_plugin url=https://plugin.example.com role_policy=readonly role_id=r",
        )
        .unwrap()
        .variables();
        let env = map(&[
            ("MINIO_IDENTITY_LDAP_SERVER_ADDR", "env.example.com:636"),
            ("MINIO_IDENTITY_OPENID_CLIENT_ID_K", "from-env"),
            ("MINIO_IDENTITY_PLUGIN_ROLE_ID", " "),
            ("TEIFS_IDENTITY_PLUGIN_AUTH_TOKEN", "Bearer t"),
        ]);
        let identity = args().settings_with(&stored, &env).unwrap();
        let ldap = identity.ldap.unwrap();
        assert_eq!(ldap.server, "env.example.com:636");
        assert_eq!(ldap.lookup_dn, "cn=stored");
        assert_eq!(identity.openid.len(), 1);
        assert_eq!(identity.openid[0].client_id, "from-env");
        let plugin = identity.plugin.unwrap();
        // A variable that's set but blank leaves the stored value.
        assert_eq!(plugin.role_id.as_deref(), Some("r"));
        assert_eq!(
            plugin.auth_token.as_deref().map(String::as_str),
            Some("Bearer t")
        );

        // Nothing stored, nothing set.
        let none = args()
            .settings_with(&BTreeMap::new(), &BTreeMap::new())
            .unwrap();
        assert!(none.ldap.is_none() && none.plugin.is_none() && none.openid.is_empty());
    }

    #[test]
    fn a_change_serve_would_refuse_is_refused() {
        let check = args().check();
        let fine = ConfigKv::parse("identity_ldap server_addr=a.example.com:636").unwrap();
        assert!((check.0)(&fine).is_ok());
        // An OpenID provider with role policies can't name a claim too.
        let both = ConfigKv::parse(
            "identity_openid config_url=https://a.example.com client_id=a role_policy=r \
             claim_name=groups",
        )
        .unwrap();
        let err = (check.0)(&both).unwrap_err();
        assert!(err.contains("both role policies and a claim name"), "{err}");
    }
}
