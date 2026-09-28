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
mod ids;
mod ops;
mod rules;
mod snapshot;
mod state;

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use teifs_crypto::{Context, CryptoError, DEFAULT_KEY, DataKey, Kms, SealedKey};
use teifs_meta::{IamWrite, MetaError, System};

pub use api::{Call, Reply};
pub use ops::{
    AccessKeyInfo, AttachedPolicy, GroupInfo, NewAccessKey, Owner, PolicyInfo, PolicyVersionInfo,
    UserInfo,
};
pub use snapshot::{Credential, Identity, RootKey};

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
    /// A policy document is invalid.
    #[error("{0}")]
    MalformedPolicyDocument(String),
    /// What's stored can't be read back (IAM refuses to start rather than guess).
    #[error("IAM's stored state is damaged: {0}")]
    Stored(String),
    /// The database failed.
    #[error("the IAM database failed: {0}")]
    Storage(#[from] MetaError),
    /// The KMS couldn't seal or unseal IAM's key.
    #[error("IAM's key couldn't be used: {0}")]
    Crypto(#[from] CryptoError),
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
            Self::Stored(_) | Self::Storage(_) | Self::Crypto(_) => "ServiceFailure",
        }
    }

    /// The HTTP status AWS answers it with.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NoSuchEntity(_) => 404,
            Self::EntityAlreadyExists(_) | Self::DeleteConflict(_) | Self::LimitExceeded(_) => 409,
            Self::InvalidInput(_) | Self::MalformedPolicyDocument(_) => 400,
            Self::Stored(_) | Self::Storage(_) | Self::Crypto(_) => 500,
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
    root: Option<RootKey>,
}

struct Inner {
    db: System,
    state: State,
    key: DataKey,
}

impl std::fmt::Debug for Iam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Iam")
            .field("root", &self.root)
            .finish_non_exhaustive()
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
            inner: Mutex::new(Inner { db, state, key }),
            snapshot: RwLock::new(Arc::new(snapshot)),
            root,
        })
    }

    /// The account id: 12 digits, random per drive.
    #[must_use]
    pub fn account(&self) -> String {
        self.inner().state.account.to_string()
    }

    /// The secret and identity of an active access key (the root's included).
    #[must_use]
    pub fn credential(&self, access_key: &str) -> Option<Credential> {
        self.snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .credential(access_key)
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
        let Inner { db, state, key } = &mut *inner;
        let mut draft = Draft {
            state: state.clone(),
            writes: Vec::new(),
            key,
            root: self.root.as_ref().map(|r| r.access_key.as_str()),
            now: now_ms(),
        };
        let out = f(&mut draft)?;
        if !draft.writes.is_empty() {
            db.iam_apply(&draft.writes)?;
            *state = draft.state;
            let snapshot = Arc::new(Snapshot::build(state, self.root.as_ref()));
            *self
                .snapshot
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
        }
        Ok(out)
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
