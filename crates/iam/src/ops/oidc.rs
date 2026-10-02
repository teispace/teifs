//! OpenID Connect providers: the identity providers whose tokens
//! `AssumeRoleWithWebIdentity` exchanges for a role's session, each with the audiences
//! it's trusted for and the certificates it may be pinned to.

use std::sync::Arc;

use teifs_meta::IamWrite;

use super::{TagKeys, checked_tags, merged, removed};
use crate::{
    Draft, Iam, IamError, Result, ids,
    oidc::{POLICY_CLAIM_TAG, ROLE_POLICY_TAG, USERINFO_TAG},
    rules::{self, MAX_CLIENT_IDS, MAX_OIDC_PROVIDERS, MAX_THUMBPRINTS},
    state::{OidcProvider, State},
};

/// An OpenID Connect provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProviderInfo {
    /// Its ARN (`arn:aws:iam::…:oidc-provider/idp.example.com`).
    pub arn: String,
    /// Its URL, as given: the issuer its tokens name.
    pub url: String,
    /// The audiences its tokens may be for.
    pub client_ids: Vec<String>,
    /// The thumbprints of the certificates it's pinned to.
    pub thumbprints: Vec<String>,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its tags.
    pub tags: Vec<(String, String)>,
}

fn info(state: &State, provider: &OidcProvider) -> OidcProviderInfo {
    OidcProviderInfo {
        arn: state.oidc_provider_arn(provider),
        url: provider.url.clone(),
        client_ids: provider.client_ids.clone(),
        thumbprints: provider.thumbprints.clone(),
        created_ms: provider.created_ms,
        tags: provider.tags.clone(),
    }
}

/// What an OpenID Connect provider is made with (`CreateOpenIDConnectProvider`'s
/// parameters).
#[derive(Debug, Clone, Copy, Default)]
pub struct NewOidcProvider<'a> {
    /// Its URL: the issuer its tokens name.
    pub url: &'a str,
    /// The audiences its tokens may be for.
    pub client_ids: &'a [String],
    /// The thumbprints of the certificates it's pinned to.
    pub thumbprints: &'a [String],
    /// Its tags.
    pub tags: &'a [(String, String)],
}

/// An OpenID Connect provider the server's settings name, as MinIO's `identity_openid`
/// configuration does: made, or brought in line with them, when the server starts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfiguredOidcProvider {
    /// Its URL: the issuer its tokens name.
    pub url: String,
    /// The client its tokens are for (an audience it keeps).
    pub client_id: String,
    /// MinIO's `role_policy`: the managed policies every token for the client gets when
    /// it names the client's role. None makes its tokens name their policies instead.
    pub role_policies: Vec<String>,
    /// MinIO's `claim_name`: the claim that names the policies (`policy` if not given).
    pub claim_name: Option<String>,
    /// MinIO's `claim_userinfo`: its tokens' claims are completed from its userinfo
    /// endpoint.
    pub claim_userinfo: bool,
}

impl ConfiguredOidcProvider {
    /// The tags that make it work as MinIO's would, each with its value, or `None` for
    /// the ones it mustn't have.
    fn tags(&self) -> Result<[(&'static str, Option<String>); 3]> {
        let role_policy = self.role_policies.join(" ");
        if !role_policy.is_empty() && self.claim_name.is_some() {
            return Err(IamError::InvalidInput(format!(
                "The OpenID Connect provider {} can't have both role policies and a policy \
                 claim: tokens for a role get the role's policies.",
                self.url
            )));
        }
        let claim = role_policy
            .is_empty()
            .then(|| self.claim_name.clone().unwrap_or_default());
        Ok([
            (POLICY_CLAIM_TAG, claim),
            (
                ROLE_POLICY_TAG,
                (!role_policy.is_empty()).then_some(role_policy),
            ),
            (USERINFO_TAG, self.claim_userinfo.then(|| "on".to_owned())),
        ])
    }
}

/// What starting the server did to a provider its settings name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ensured {
    /// It was made.
    Created,
    /// It was brought in line with the settings.
    Updated,
    /// It was as they say.
    Unchanged,
}

/// Checked client ids, each once, in the order given.
fn client_ids(ids: &[String]) -> Result<Vec<String>> {
    let mut unique: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        rules::client_id(id)?;
        if !unique.contains(id) {
            unique.push(id.clone());
        }
    }
    if unique.len() > MAX_CLIENT_IDS {
        return Err(too_many_client_ids());
    }
    Ok(unique)
}

fn too_many_client_ids() -> IamError {
    IamError::LimitExceeded(format!(
        "Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: {MAX_CLIENT_IDS}"
    ))
}

/// Checked thumbprints, each once (hex compares without case), in the order given.
fn thumbprints(given: &[String]) -> Result<Vec<String>> {
    let mut unique: Vec<String> = Vec::with_capacity(given.len());
    for thumbprint in given {
        rules::thumbprint(thumbprint)?;
        if !unique.iter().any(|t| t.eq_ignore_ascii_case(thumbprint)) {
            unique.push(thumbprint.clone());
        }
    }
    if unique.len() > MAX_THUMBPRINTS {
        return Err(IamError::LimitExceeded(format!(
            "Thumbprint list must contain fewer than {} entries",
            MAX_THUMBPRINTS + 1
        )));
    }
    Ok(unique)
}

impl Draft<'_> {
    fn oidc_provider(&self, arn: &str) -> Result<Arc<OidcProvider>> {
        self.state.oidc_provider_by_arn(arn).cloned()
    }

    fn save_oidc_provider(&mut self, provider: OidcProvider) {
        self.write(IamWrite::PutOidcProvider(provider.row()));
        self.state
            .oidc_providers
            .insert(provider.id.clone(), Arc::new(provider));
    }

    /// [`Iam::create_oidc_provider`], as part of a change.
    pub(crate) fn create_oidc_provider(
        &mut self,
        new: &NewOidcProvider<'_>,
    ) -> Result<OidcProviderInfo> {
        let name = rules::oidc_url(new.url)?;
        let client_ids = client_ids(new.client_ids)?;
        let thumbprints = thumbprints(new.thumbprints)?;
        checked_tags(TagKeys::OidcProvider, new.tags)?;
        let tags = merged(TagKeys::OidcProvider, &[], new.tags)?;
        if self
            .state
            .oidc_providers
            .values()
            .any(|p| p.name().eq_ignore_ascii_case(name))
        {
            return Err(IamError::EntityAlreadyExists(format!(
                "Provider with url {} already exists.",
                new.url
            )));
        }
        if self.state.oidc_providers.len() >= MAX_OIDC_PROVIDERS {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for OpenIdConnectProvidersPerAccount: {MAX_OIDC_PROVIDERS}"
            )));
        }
        let provider = OidcProvider {
            id: self.new_id(ids::Kind::OidcProvider),
            url: new.url.to_owned(),
            client_ids,
            thumbprints,
            created_ms: self.now,
            tags: tags.clone(),
        };
        let id = provider.id.clone();
        self.save_oidc_provider(provider);
        for (key, value) in tags {
            self.write(IamWrite::PutOidcProviderTag(id.clone(), key, value));
        }
        Ok(info(&self.state, &self.state.oidc_providers[&id]))
    }

    /// Changes the provider with this ARN with `f`.
    /// Makes `wanted`, or brings the provider of its URL in line with it: the client is
    /// added (others stay) and the tags that decide how its tokens get policies are set.
    /// Its thumbprints and other tags stay as they are.
    fn ensure_oidc_provider(
        &mut self,
        wanted: &ConfiguredOidcProvider,
    ) -> Result<(String, Ensured)> {
        let tags = wanted.tags()?;
        let name = rules::oidc_url(&wanted.url)?;
        rules::client_id(&wanted.client_id)?;
        let existing = self
            .state
            .oidc_providers
            .values()
            .find(|p| p.name().eq_ignore_ascii_case(name))
            .cloned();
        let Some(existing) = existing else {
            let tags: Vec<(String, String)> = tags
                .into_iter()
                .filter_map(|(key, value)| Some((key.to_owned(), value?)))
                .collect();
            let created = self.create_oidc_provider(&NewOidcProvider {
                url: &wanted.url,
                client_ids: std::slice::from_ref(&wanted.client_id),
                thumbprints: &[],
                tags: &tags,
            })?;
            return Ok((created.arn, Ensured::Created));
        };
        let mut provider = Arc::unwrap_or_clone(existing);
        let mut changed = false;
        if !provider.client_ids.contains(&wanted.client_id) {
            if provider.client_ids.len() >= MAX_CLIENT_IDS {
                return Err(too_many_client_ids());
            }
            provider.client_ids.push(wanted.client_id.clone());
            changed = true;
        }
        for (key, value) in tags {
            let has = provider
                .tags
                .iter()
                .find(|(k, _)| TagKeys::OidcProvider.same(k, key))
                .map(|(_, v)| v);
            if has == value.as_ref() {
                continue;
            }
            changed = true;
            let key = key.to_owned();
            if let Some(value) = value {
                let new = [(key.clone(), value.clone())];
                provider.tags = merged(TagKeys::OidcProvider, &provider.tags, &new)?;
                self.write(IamWrite::PutOidcProviderTag(
                    provider.id.clone(),
                    key,
                    value,
                ));
            } else {
                removed(
                    TagKeys::OidcProvider,
                    &mut provider.tags,
                    std::slice::from_ref(&key),
                );
                self.write(IamWrite::DeleteOidcProviderTag(provider.id.clone(), key));
            }
        }
        let arn = self.state.oidc_provider_arn(&provider);
        if !changed {
            return Ok((arn, Ensured::Unchanged));
        }
        self.save_oidc_provider(provider);
        Ok((arn, Ensured::Updated))
    }

    fn change_oidc_provider(
        &mut self,
        arn: &str,
        f: impl FnOnce(&mut OidcProvider) -> Result<()>,
    ) -> Result<()> {
        let mut provider = Arc::unwrap_or_clone(self.oidc_provider(arn)?);
        f(&mut provider)?;
        self.save_oidc_provider(provider);
        Ok(())
    }
}

/// OpenID Connect providers.
impl Iam {
    /// Creates an OpenID Connect provider (`CreateOpenIDConnectProvider`).
    pub fn create_oidc_provider(&self, new: &NewOidcProvider<'_>) -> Result<OidcProviderInfo> {
        self.change(|d| d.create_oidc_provider(new))
    }

    /// Makes the providers the server's settings name, or brings them in line with them,
    /// all at once: their ARNs, with what was done to each.
    pub fn ensure_oidc_providers(
        &self,
        wanted: &[ConfiguredOidcProvider],
    ) -> Result<Vec<(String, Ensured)>> {
        self.change(|d| {
            wanted
                .iter()
                .map(|wanted| d.ensure_oidc_provider(wanted))
                .collect()
        })
    }

    /// An OpenID Connect provider (`GetOpenIDConnectProvider`).
    pub fn oidc_provider(&self, arn: &str) -> Result<OidcProviderInfo> {
        self.read(|s| Ok(info(s, s.oidc_provider_by_arn(arn)?)))
    }

    /// Every OpenID Connect provider, by ARN (`ListOpenIDConnectProviders`).
    pub fn oidc_providers(&self) -> Result<Vec<OidcProviderInfo>> {
        self.read(|s| {
            let mut providers: Vec<OidcProviderInfo> =
                s.oidc_providers.values().map(|p| info(s, p)).collect();
            providers.sort_by_cached_key(|p| p.arn.to_ascii_lowercase());
            Ok(providers)
        })
    }

    /// Deletes an OpenID Connect provider; one that doesn't exist is already gone, as on
    /// AWS (`DeleteOpenIDConnectProvider`). Roles that trust it stay as they are, and
    /// no one can assume them through it any more; its users' service accounts go
    /// with it.
    pub fn delete_oidc_provider(&self, arn: &str) -> Result<()> {
        self.change(|d| match d.oidc_provider(arn) {
            Ok(provider) => {
                d.remove_openid_service_accounts_of(&provider.id);
                d.state.oidc_providers.remove(&provider.id);
                d.write(IamWrite::DeleteOidcProvider(provider.id.clone()));
                Ok(())
            }
            Err(IamError::NoSuchEntity(_)) => Ok(()),
            Err(err) => Err(err),
        })
    }

    /// Adds an audience to a provider; one it has already is left as it is
    /// (`AddClientIDToOpenIDConnectProvider`).
    pub fn add_client_id(&self, arn: &str, client_id: &str) -> Result<()> {
        rules::client_id(client_id)?;
        self.change(|d| {
            d.change_oidc_provider(arn, |p| {
                if !p.client_ids.iter().any(|c| c == client_id) {
                    if p.client_ids.len() >= MAX_CLIENT_IDS {
                        return Err(too_many_client_ids());
                    }
                    p.client_ids.push(client_id.to_owned());
                }
                Ok(())
            })
        })
    }

    /// Removes an audience from a provider; one it doesn't have is ignored
    /// (`RemoveClientIDFromOpenIDConnectProvider`).
    pub fn remove_client_id(&self, arn: &str, client_id: &str) -> Result<()> {
        rules::client_id(client_id)?;
        self.change(|d| {
            d.change_oidc_provider(arn, |p| {
                p.client_ids.retain(|c| c != client_id);
                Ok(())
            })
        })
    }

    /// Replaces a provider's thumbprints (`UpdateOpenIDConnectProviderThumbprint`).
    pub fn set_thumbprints(&self, arn: &str, given: &[String]) -> Result<()> {
        let given = thumbprints(given)?;
        self.change(|d| {
            d.change_oidc_provider(arn, |p| {
                p.thumbprints = given;
                Ok(())
            })
        })
    }

    /// Adds or replaces a provider's tags; keys compare without case
    /// (`TagOpenIDConnectProvider`).
    pub fn tag_oidc_provider(&self, arn: &str, tags: &[(String, String)]) -> Result<()> {
        checked_tags(TagKeys::OidcProvider, tags)?;
        self.change(|d| {
            let mut provider = Arc::unwrap_or_clone(d.oidc_provider(arn)?);
            provider.tags = merged(TagKeys::OidcProvider, &provider.tags, tags)?;
            for (key, value) in tags {
                d.write(IamWrite::PutOidcProviderTag(
                    provider.id.clone(),
                    key.clone(),
                    value.clone(),
                ));
            }
            d.state
                .oidc_providers
                .insert(provider.id.clone(), Arc::new(provider));
            Ok(())
        })
    }

    /// Removes a provider's tags; absent keys are ignored (`UntagOpenIDConnectProvider`).
    pub fn untag_oidc_provider(&self, arn: &str, keys: &[String]) -> Result<()> {
        self.change(|d| {
            let mut provider = Arc::unwrap_or_clone(d.oidc_provider(arn)?);
            for key in removed(TagKeys::OidcProvider, &mut provider.tags, keys) {
                d.write(IamWrite::DeleteOidcProviderTag(
                    provider.id.clone(),
                    key.clone(),
                ));
            }
            d.state
                .oidc_providers
                .insert(provider.id.clone(), Arc::new(provider));
            Ok(())
        })
    }
}
