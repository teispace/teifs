//! TeiFS's IAM, as AWS has it: users, their access keys and tags, groups, customer-managed
//! policies with versions, inline policies, attachments and permissions boundaries, in a
//! drive's `system.db`; and, for every request, who signed it and which policies apply.
//!
//! The drive's root credentials are the account's root user. Access keys' secrets are
//! sealed with an IAM key that the drive's KMS seals, so `system.db` alone doesn't reveal
//! them. The whole state is kept in memory; each change is checked against AWS's rules,
//! written in one transaction and then published as a new [`Credential`] lookup, so
//! authentication never touches the database.

mod api;
mod bearer;
pub mod certificate;
mod ids;
pub mod ldap;
mod oidc;
mod ops;
pub mod plugin;
mod rules;
mod saml;
/// SAML responses as identity providers sign them, for other crates' tests.
#[cfg(any(test, feature = "fake-saml"))]
pub use saml::fake as saml_fake;
mod sessions;
mod snapshot;
mod state;
mod transfer;

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use teifs_crypto::{Context, CryptoError, DEFAULT_KEY, DataKey, Kms, SealedKey};
use teifs_meta::{IamWrite, MetaError, System};

pub use api::{Call, Reply};
pub use bearer::metrics_token;
pub use ldap::{Directory, LdapError, LdapSettings, SignedIn, SrvRecord, Transport};
pub use ops::{
    AccessKeyInfo, AttachedPolicy, ConfiguredOidcProvider, Ensured, GroupInfo, LdapEntity,
    LdapPolicies, LdapPolicyChange, NewAccessKey, NewOidcProvider, NewRole, NewSamlProvider,
    OidcProviderInfo, Owner, PolicyInfo, PolicyVersionInfo, RoleInfo, SamlProviderInfo,
    SamlProviderUpdate, UserInfo,
};
pub use rustls::pki_types::CertificateDer;
pub use sessions::{AuthError, Issued};
pub use snapshot::{Credential, Identity, RootKey, Session, SessionKind};

use crate::{snapshot::Snapshot, state::State};

/// Why an IAM request failed; the variants are AWS's error codes.
#[derive(Debug, thiserror::Error)]
pub enum IamError {
    /// What was named doesn't exist.
    #[error("{0}")]
    NoSuchEntity(String),
    /// Something of that name exists.
    #[error("{0}")]
    EntityAlreadyExists(String),
    /// It can't be deleted while other things depend on it.
    #[error("{0}")]
    DeleteConflict(String),
    /// A quota would be exceeded.
    #[error("{0}")]
    LimitExceeded(String),
    /// A parameter is invalid.
    #[error("{0}")]
    InvalidInput(String),
    /// The LDAP directory couldn't be asked.
    #[error("{0}")]
    Directory(String),
    /// A policy document is invalid.
    #[error("{0}")]
    MalformedPolicyDocument(String),
    /// A session's policies and tags don't fit in its token.
    #[error("Packed size of session policies and tags exceeds the limit.")]
    PackedPolicyTooLarge,
    /// What's stored can't be read back (IAM refuses to start rather than guess).
    #[error("IAM's stored state is damaged: {0}")]
    Stored(String),
    /// The database failed.
    #[error("the IAM database failed: {0}")]
    Storage(#[from] MetaError),
    /// The KMS couldn't seal or unseal IAM's key.
    #[error("IAM's key couldn't be used: {0}")]
    Crypto(#[from] CryptoError),
    /// A new root key couldn't be kept where the server reads it.
    #[error("the new root key couldn't be saved: {0}")]
    Persist(std::io::Error),
}

impl IamError {
    /// AWS's error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSuchEntity(_) => "NoSuchEntity",
            Self::EntityAlreadyExists(_) => "EntityAlreadyExists",
            Self::DeleteConflict(_) => "DeleteConflict",
            Self::LimitExceeded(_) => "LimitExceeded",
            Self::InvalidInput(_) => "InvalidInput",
            Self::MalformedPolicyDocument(_) => "MalformedPolicyDocument",
            Self::PackedPolicyTooLarge => "PackedPolicyTooLarge",
            Self::Directory(_) => "ServiceUnavailable",
            Self::Stored(_) | Self::Storage(_) | Self::Crypto(_) | Self::Persist(_) => {
                "ServiceFailure"
            }
        }
    }

    /// The HTTP status AWS answers it with.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NoSuchEntity(_) => 404,
            Self::EntityAlreadyExists(_) | Self::DeleteConflict(_) | Self::LimitExceeded(_) => 409,
            Self::InvalidInput(_)
            | Self::MalformedPolicyDocument(_)
            | Self::PackedPolicyTooLarge => 400,
            Self::Directory(_) => 503,
            Self::Stored(_) | Self::Storage(_) | Self::Crypto(_) | Self::Persist(_) => 500,
        }
    }
}

/// An IAM result.
pub type Result<T, E = IamError> = std::result::Result<T, E>;

/// Settings in `iam_meta`.
const ACCOUNT: &str = "account";
const SEALED_KEY: &str = "key";

/// A drive's IAM.
pub struct Iam {
    inner: Mutex<Inner>,
    snapshot: RwLock<Arc<Snapshot>>,
    /// IAM's key, which seals session tokens and derives their secrets (and opens the
    /// SAML providers' private keys it sealed).
    tokens: DataKey,
    /// The OpenID Connect providers' signing keys.
    web_keys: oidc::KeyCache,
    /// The LDAP directory users sign in with, if there's one.
    ldap: Option<Arc<ldap::Directory>>,
    /// Whom client certificates are trusted from, if they sign in at all.
    certificates: Option<Arc<certificate::CertificateSignIn>>,
    /// The identity plugin custom tokens are checked with, if there's one.
    plugin: Option<Arc<plugin::IdentityPlugin>>,
}

struct Inner {
    db: System,
    state: State,
    key: DataKey,
    /// The root user's access key, if requests are signed at all.
    root: Option<RootKey>,
}

impl std::fmt::Debug for Iam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Iam").finish_non_exhaustive()
    }
}

impl Iam {
    /// Opens IAM in the system database at `path` of drive `drive`, creating its account
    /// id and key on first use. `root` is the account root's access key, if requests are
    /// signed at all.
    pub async fn open(
        path: &Path,
        drive: &str,
        kms: &dyn Kms,
        root: Option<RootKey>,
    ) -> Result<Self> {
        let mut db = System::open(path)?;
        let rows = db.iam_rows()?;
        let setting = |name: &str| {
            rows.meta
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let context = Context::iam(drive);
        let mut writes = Vec::new();
        let key = if let Some(sealed) = setting(SEALED_KEY) {
            let sealed: SealedKey = serde_json::from_str(&sealed)
                .map_err(|e| IamError::Stored(format!("the sealed IAM key: {e}")))?;
            kms.unseal(&sealed, &context).await?
        } else {
            let (key, sealed) = kms.generate(Some(DEFAULT_KEY), &context).await?;
            let sealed = serde_json::to_string(&sealed).expect("a sealed key serializes");
            writes.push(IamWrite::SetMeta(SEALED_KEY.into(), sealed));
            key
        };
        let account = setting(ACCOUNT).unwrap_or_else(|| {
            let account = ids::account();
            writes.push(IamWrite::SetMeta(ACCOUNT.into(), account.clone()));
            account
        });
        if !writes.is_empty() {
            db.iam_apply(&writes)?;
        }
        let state = State::load(&account, rows, &key)?;
        let snapshot = Snapshot::build(&state, root.as_ref());
        Ok(Self {
            tokens: key.clone(),
            inner: Mutex::new(Inner {
                db,
                state,
                key,
                root,
            }),
            snapshot: RwLock::new(Arc::new(snapshot)),
            web_keys: oidc::KeyCache::default(),
            ldap: None,
            certificates: None,
            plugin: None,
        })
    }

    /// Signs users in with `directory` (`AssumeRoleWithLDAPIdentity`).
    #[must_use]
    pub fn with_ldap(mut self, directory: ldap::Directory) -> Self {
        self.ldap = Some(Arc::new(directory));
        self
    }

    /// Checks custom tokens with `plugin` (`AssumeRoleWithCustomToken`).
    #[must_use]
    pub fn with_plugin(mut self, plugin: plugin::IdentityPlugin) -> Self {
        self.plugin = Some(Arc::new(plugin));
        self
    }

    /// The identity plugin custom tokens are checked with, if there's one.
    #[must_use]
    pub fn identity_plugin(&self) -> Option<&Arc<plugin::IdentityPlugin>> {
        self.plugin.as_ref()
    }

    /// Signs in whoever connects with a client certificate `sign_in` trusts
    /// (`AssumeRoleWithCertificate`).
    #[must_use]
    pub fn with_certificates(mut self, sign_in: certificate::CertificateSignIn) -> Self {
        self.certificates = Some(Arc::new(sign_in));
        self
    }

    /// Whom client certificates are trusted from, if they sign in at all.
    #[must_use]
    pub fn certificate_sign_in(&self) -> Option<&Arc<certificate::CertificateSignIn>> {
        self.certificates.as_ref()
    }

    /// The LDAP directory users sign in with, if there's one.
    #[must_use]
    pub fn ldap(&self) -> Option<&Arc<ldap::Directory>> {
        self.ldap.as_ref()
    }

    /// The account id: 12 digits, random per drive.
    #[must_use]
    pub fn account(&self) -> String {
        self.inner().state.account.to_string()
    }

    /// The secret and identity of an active long-term access key (the root's
    /// included).
    #[must_use]
    pub fn credential(&self, access_key: &str) -> Option<Credential> {
        self.snapshot().credential(access_key)
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reads the state.
    fn read<T>(&self, f: impl FnOnce(&State) -> Result<T>) -> Result<T> {
        f(&self.inner().state)
    }

    /// Makes a change: `f` changes a copy of the state and says what to write; only if
    /// the database takes all of it does the copy become the state.
    fn change<T>(&self, f: impl FnOnce(&mut Draft<'_>) -> Result<T>) -> Result<T> {
        let mut inner = self.inner();
        let Inner {
            db,
            state,
            key,
            root,
        } = &mut *inner;
        let mut draft = Draft {
            state: state.clone(),
            writes: Vec::new(),
            key,
            root: root.as_ref().map(|r| r.access_key.as_str()),
            now: now_ms(),
        };
        let out = f(&mut draft)?;
        if !draft.writes.is_empty() {
            db.iam_apply(&draft.writes)?;
            *state = draft.state;
            self.publish(state, root.as_ref());
        }
        Ok(out)
    }

    /// Makes `state` and `root` what authentication sees.
    fn publish(&self, state: &State, root: Option<&RootKey>) {
        let snapshot = Arc::new(Snapshot::build(state, root));
        *self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
    }

    /// Replaces the root user's access key. `persist` keeps the new key where the server
    /// reads it when it starts; only once it has does the old key stop working, so a
    /// failure leaves the old key in use everywhere.
    pub fn replace_root_key(
        &self,
        new: RootKey,
        persist: impl FnOnce(&RootKey) -> std::io::Result<()>,
    ) -> Result<()> {
        let mut inner = self.inner();
        if inner.root.is_none() {
            return Err(IamError::InvalidInput(
                "This server accepts unsigned requests: it has no root key to replace.".into(),
            ));
        }
        if inner.state.keys.contains_key(&new.access_key)
            || inner
                .root
                .as_ref()
                .is_some_and(|r| r.access_key == new.access_key)
        {
            return Err(IamError::EntityAlreadyExists(format!(
                "The access key {} is already in use.",
                new.access_key
            )));
        }
        persist(&new).map_err(IamError::Persist)?;
        let Inner { state, root, .. } = &mut *inner;
        *root = Some(new);
        self.publish(state, root.as_ref());
        Ok(())
    }
}

/// A change being made.
pub(crate) struct Draft<'a> {
    pub(crate) state: State,
    pub(crate) writes: Vec<IamWrite>,
    pub(crate) key: &'a DataKey,
    /// The root's access key id, which no user's key may take.
    pub(crate) root: Option<&'a str>,
    pub(crate) now: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The id MinIO derives a role's ARN from `seed` with (an identity plugin's URL, an
/// OpenID Connect client id): its SHA-1, base64url without padding.
#[must_use]
pub fn minio_role_id(seed: &str) -> String {
    use base64::Engine as _;
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        seed.as_bytes(),
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// The role ARN MinIO gives an OpenID Connect provider's client `client_id` whose
/// tokens get the provider's role policies: `arn:minio:iam:::role/<id>`, as a server
/// without a region names it.
#[must_use]
pub fn openid_role_arn(client_id: &str) -> String {
    format!("arn:minio:iam:::role/{}", minio_role_id(client_id))
}
