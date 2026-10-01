//! SAML providers: the identity providers whose signed responses `AssumeRoleWithSAML`
//! exchanges for a role's session, each with its metadata (the issuer and signing
//! certificates) and the private keys that decrypt its encrypted assertions.

use std::sync::Arc;

use teifs_meta::IamWrite;
use zeroize::Zeroizing;

use super::{TagKeys, checked_tags, merged, removed};
use crate::{
    Draft, Iam, IamError, Result, ids,
    rules::{MAX_SAML_KEYS, MAX_SAML_PROVIDERS},
    saml::{metadata, private_key},
    state::{Encryption, SamlKey, SamlProvider, State},
};

/// A provider's `ValidUntil`, as AWS sets it: a hundred years after its creation, the
/// same day and time (February 29th becoming the 28th).
fn valid_until(created_ms: i64) -> i64 {
    let Ok(created) =
        time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(created_ms) * 1_000_000)
    else {
        return created_ms;
    };
    let year = created.year() + 100;
    let later = created
        .replace_year(year)
        .or_else(|_| created.replace_day(28).and_then(|d| d.replace_year(year)))
        .unwrap_or(created);
    i64::try_from(later.unix_timestamp_nanos() / 1_000_000).unwrap_or(created_ms)
}

/// A SAML provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlProviderInfo {
    /// Its ARN (`arn:aws:iam::…:saml-provider/Name`).
    pub arn: String,
    /// Its `SAMLProviderUUID`.
    pub uuid: String,
    /// Its metadata document, as given.
    pub metadata: String,
    /// The issuer its metadata names.
    pub issuer: String,
    /// `Required` or `Allowed`, if set.
    pub encryption: Option<&'static str>,
    /// Its private keys' ids and when each was added (milliseconds), oldest first.
    pub keys: Vec<(String, i64)>,
    /// When it was created, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Its `ValidUntil`, in milliseconds since the Unix epoch.
    pub valid_until_ms: i64,
    /// Its tags.
    pub tags: Vec<(String, String)>,
}

fn info(state: &State, provider: &SamlProvider) -> SamlProviderInfo {
    SamlProviderInfo {
        arn: state.saml_provider_arn(provider),
        uuid: provider.uuid.clone(),
        metadata: provider.metadata.to_string(),
        issuer: provider.parsed.entity_id.clone(),
        encryption: provider.encryption.map(Encryption::as_str),
        keys: provider
            .keys
            .iter()
            .map(|k| (k.id.clone(), k.created_ms))
            .collect(),
        created_ms: provider.created_ms,
        valid_until_ms: provider.valid_until_ms,
        tags: provider.tags.clone(),
    }
}

/// What a SAML provider is made with (`CreateSAMLProvider`'s parameters).
#[derive(Debug, Clone, Copy, Default)]
pub struct NewSamlProvider<'a> {
    /// Its name: `[A-Za-z0-9_.-]`, 1 to 128 characters.
    pub name: &'a str,
    /// Its metadata document.
    pub metadata: &'a str,
    /// `Required` or `Allowed`.
    pub encryption: Option<&'a str>,
    /// A private key (PEM) that decrypts its assertions.
    pub private_key: Option<&'a str>,
    /// Its tags.
    pub tags: &'a [(String, String)],
}

/// What `UpdateSAMLProvider` changes.
#[derive(Debug, Clone, Copy, Default)]
pub struct SamlProviderUpdate<'a> {
    /// A new metadata document.
    pub metadata: Option<&'a str>,
    /// `Required` or `Allowed`.
    pub encryption: Option<&'a str>,
    /// A private key (PEM) to add.
    pub add_key: Option<&'a str>,
    /// The id of a private key to remove.
    pub remove_key: Option<&'a str>,
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(IamError::InvalidInput(message.into()))
}

/// A provider's name: 1 to 128 of `[A-Za-z0-9_.-]`, as AWS's pattern `[\w._-]+`.
fn checked_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    if ok {
        Ok(())
    } else {
        invalid(format!(
            "The SAML provider name `{name}` must be 1 to 128 letters, digits or `_.-`."
        ))
    }
}

fn checked_encryption(mode: Option<&str>) -> Result<Option<Encryption>> {
    mode.map(|mode| {
        Encryption::parse(mode).ok_or_else(|| {
            IamError::InvalidInput(format!(
                "The assertion encryption mode `{mode}` must be Required or Allowed."
            ))
        })
    })
    .transpose()
}

const REQUIRED_WITHOUT_KEY: &str = "Unable to set assertion encryption mode to Required because \
                                    no private key is provided.";

impl Draft<'_> {
    fn saml_provider(&self, arn: &str) -> Result<Arc<SamlProvider>> {
        self.state.saml_provider_by_arn(arn).cloned()
    }

    fn save_saml_provider(&mut self, provider: SamlProvider) {
        self.write(IamWrite::PutSamlProvider(provider.row()));
        self.state
            .saml_providers
            .insert(provider.id.clone(), Arc::new(provider));
    }

    /// A new private key for `provider`, sealed.
    fn new_saml_key(&self, pem: &str) -> Result<SamlKey> {
        let der: Zeroizing<Vec<u8>> = private_key::pkcs8(pem).or_else(invalid)?;
        let id = ids::saml();
        Ok(SamlKey {
            sealed: self.key.seal_secret(id.as_bytes(), &der),
            id,
            created_ms: self.now,
        })
    }

    /// [`Iam::create_saml_provider`], as part of a change.
    pub(crate) fn create_saml_provider(
        &mut self,
        new: &NewSamlProvider<'_>,
    ) -> Result<SamlProviderInfo> {
        checked_name(new.name)?;
        let parsed = metadata::parse(new.metadata).or_else(invalid)?;
        let encryption = checked_encryption(new.encryption)?;
        checked_tags(TagKeys::SamlProvider, new.tags)?;
        let tags = merged(TagKeys::SamlProvider, &[], new.tags)?;
        if encryption == Some(Encryption::Required) && new.private_key.is_none() {
            return invalid(REQUIRED_WITHOUT_KEY);
        }
        if self
            .state
            .saml_providers
            .values()
            .any(|p| p.name.eq_ignore_ascii_case(new.name))
        {
            return Err(IamError::EntityAlreadyExists(format!(
                "SAMLProvider {} already exists.",
                new.name
            )));
        }
        if self.state.saml_providers.len() >= MAX_SAML_PROVIDERS {
            return Err(IamError::LimitExceeded(format!(
                "Cannot exceed quota for SAMLProvidersPerAccount: {MAX_SAML_PROVIDERS}"
            )));
        }
        let keys = match new.private_key {
            Some(pem) => vec![self.new_saml_key(pem)?],
            None => Vec::new(),
        };
        let provider = SamlProvider {
            id: self.new_id(ids::Kind::SamlProvider),
            name: new.name.to_owned(),
            uuid: ids::saml(),
            metadata: new.metadata.into(),
            parsed: Arc::new(parsed),
            encryption,
            keys,
            created_ms: self.now,
            valid_until_ms: valid_until(self.now),
            tags: tags.clone(),
        };
        let id = provider.id.clone();
        let keys: Vec<_> = provider.keys.iter().map(|k| provider.key_row(k)).collect();
        // The provider's row first: its keys refer to it.
        self.save_saml_provider(provider);
        for key in keys {
            self.write(IamWrite::PutSamlKey(key));
        }
        for (key, value) in tags {
            self.write(IamWrite::PutSamlProviderTag(id.clone(), key, value));
        }
        Ok(info(&self.state, &self.state.saml_providers[&id]))
    }

    /// [`Iam::update_saml_provider`], as part of a change.
    pub(crate) fn update_saml_provider(
        &mut self,
        arn: &str,
        update: &SamlProviderUpdate<'_>,
    ) -> Result<()> {
        if update.metadata.is_none()
            && update.encryption.is_none()
            && update.add_key.is_none()
            && update.remove_key.is_none()
        {
            return invalid(
                "Unable to update identity provider. No updates are defined for metadata or \
                 encryption assertion.",
            );
        }
        if update.add_key.is_some() && update.remove_key.is_some() {
            return invalid(
                "Unable to add and remove private keys in the same request. Set a value for \
                 only one of the two parameters.",
            );
        }
        let parsed = update
            .metadata
            .map(|doc| metadata::parse(doc).or_else(invalid))
            .transpose()?;
        let encryption = checked_encryption(update.encryption)?;
        let mut provider = Arc::unwrap_or_clone(self.saml_provider(arn)?);
        if let (Some(doc), Some(parsed)) = (update.metadata, parsed) {
            provider.metadata = doc.into();
            provider.parsed = Arc::new(parsed);
        }
        if encryption.is_some() {
            provider.encryption = encryption;
        }
        if let Some(pem) = update.add_key {
            if provider.keys.len() >= MAX_SAML_KEYS {
                return Err(IamError::LimitExceeded(format!(
                    "Private key limit of {MAX_SAML_KEYS} is reached."
                )));
            }
            let key = self.new_saml_key(pem)?;
            self.write(IamWrite::PutSamlKey(provider.key_row(&key)));
            provider.keys.push(key);
        }
        if let Some(id) = update.remove_key {
            let Some(at) = provider.keys.iter().position(|k| k.id == id) else {
                return invalid(
                    "Failed to remove private key because the Key ID does not match a \
                     private key.",
                );
            };
            if provider.keys.len() == 1 && provider.encryption == Some(Encryption::Required) {
                return invalid("Failed to remove private key.");
            }
            provider.keys.remove(at);
            self.write(IamWrite::DeleteSamlKey(provider.id.clone(), id.to_owned()));
        }
        if provider.encryption == Some(Encryption::Required) && provider.keys.is_empty() {
            return invalid(REQUIRED_WITHOUT_KEY);
        }
        self.save_saml_provider(provider);
        Ok(())
    }
}

/// SAML providers.
impl Iam {
    /// Creates a SAML provider (`CreateSAMLProvider`).
    pub fn create_saml_provider(&self, new: &NewSamlProvider<'_>) -> Result<SamlProviderInfo> {
        self.change(|d| d.create_saml_provider(new))
    }

    /// A SAML provider (`GetSAMLProvider`).
    pub fn saml_provider(&self, arn: &str) -> Result<SamlProviderInfo> {
        self.read(|s| Ok(info(s, s.saml_provider_by_arn(arn)?)))
    }

    /// Every SAML provider, by ARN (`ListSAMLProviders`).
    pub fn saml_providers(&self) -> Result<Vec<SamlProviderInfo>> {
        self.read(|s| {
            let mut providers: Vec<SamlProviderInfo> =
                s.saml_providers.values().map(|p| info(s, p)).collect();
            providers.sort_by_cached_key(|p| p.arn.to_ascii_lowercase());
            Ok(providers)
        })
    }

    /// Changes a provider's metadata, encryption mode or private keys
    /// (`UpdateSAMLProvider`), with AWS's rules: something must change, a key is added
    /// or removed but not both, at most two keys, and `Required` needs a key.
    pub fn update_saml_provider(&self, arn: &str, update: &SamlProviderUpdate<'_>) -> Result<()> {
        self.change(|d| d.update_saml_provider(arn, update))
    }

    /// Deletes a SAML provider (`DeleteSAMLProvider`). Roles that trust it stay as they
    /// are, and no one can assume them through it any more.
    pub fn delete_saml_provider(&self, arn: &str) -> Result<()> {
        self.change(|d| {
            let provider = d.saml_provider(arn)?;
            d.state.saml_providers.remove(&provider.id);
            d.write(IamWrite::DeleteSamlProvider(provider.id.clone()));
            Ok(())
        })
    }

    /// Adds or replaces a provider's tags; keys compare without case
    /// (`TagSAMLProvider`).
    pub fn tag_saml_provider(&self, arn: &str, tags: &[(String, String)]) -> Result<()> {
        checked_tags(TagKeys::SamlProvider, tags)?;
        self.change(|d| {
            let mut provider = Arc::unwrap_or_clone(d.saml_provider(arn)?);
            provider.tags = merged(TagKeys::SamlProvider, &provider.tags, tags)?;
            for (key, value) in tags {
                d.write(IamWrite::PutSamlProviderTag(
                    provider.id.clone(),
                    key.clone(),
                    value.clone(),
                ));
            }
            d.state
                .saml_providers
                .insert(provider.id.clone(), Arc::new(provider));
            Ok(())
        })
    }

    /// Removes a provider's tags; absent keys are ignored (`UntagSAMLProvider`).
    pub fn untag_saml_provider(&self, arn: &str, keys: &[String]) -> Result<()> {
        self.change(|d| {
            let mut provider = Arc::unwrap_or_clone(d.saml_provider(arn)?);
            for key in removed(TagKeys::SamlProvider, &mut provider.tags, keys) {
                d.write(IamWrite::DeleteSamlProviderTag(
                    provider.id.clone(),
                    key.clone(),
                ));
            }
            d.state
                .saml_providers
                .insert(provider.id.clone(), Arc::new(provider));
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_are_valid_for_a_hundred_years() {
        // 2017-03-06T22:29:46.433Z, AWS's example; 2024-02-29T12:00:00Z, whose year
        // 2124 has a February 29th; and 2000-02-29T12:00:00Z, whose 2100 hasn't.
        assert_eq!(valid_until(1_488_839_386_433), 4_644_512_986_433);
        assert_eq!(valid_until(1_709_208_000_000), 4_864_881_600_000);
        assert_eq!(valid_until(951_825_600_000), 4_107_499_200_000);
    }
}
