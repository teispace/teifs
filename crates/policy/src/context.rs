//! What a policy may know about a request: who makes it, when, from where, and the S3
//! facts the server chose to record. Built by the server, field by field; a policy's
//! condition keys and variables read only from here.

use std::{borrow::Cow, net::IpAddr};

use crate::{
    key::{GlobalKey, IamKey, Key, S3Key, StsKey, TagKind},
    value::{Date, Number},
};

/// What kind of principal makes a request (`aws:PrincipalType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    /// The account's root user.
    Account,
    /// An IAM user.
    User,
    /// A session of a role.
    AssumedRole,
    /// A session a user started for someone else (`GetFederationToken`).
    FederatedUser,
    /// Someone an OpenID Connect provider vouches for, asking for a role's session
    /// (`AssumeRoleWithWebIdentity`).
    WebIdentityUser,
    /// An unsigned request.
    Anonymous,
    /// A service acting for the account, such as S3's log delivery
    /// (`logging.s3.amazonaws.com`); AWS gives it no `aws:PrincipalType`.
    Service,
}

impl PrincipalKind {
    /// The name AWS gives it in `aws:PrincipalType`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Account => "Account",
            Self::User => "User",
            Self::AssumedRole => "AssumedRole",
            Self::FederatedUser => "FederatedUser",
            Self::WebIdentityUser => "WebIdentityUser",
            Self::Anonymous => "Anonymous",
            Self::Service => "Service",
        }
    }
}

/// Who makes a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    kind: PrincipalKind,
    /// The principal's own ARN (a user's, or the session's `assumed-role` ARN).
    arn: Option<String>,
    account: Option<String>,
    /// `aws:userid`.
    user_id: String,
    /// `aws:username`, for IAM users only.
    username: Option<String>,
    /// A session's role.
    role_arn: Option<String>,
    session_name: Option<String>,
    canonical_id: Option<String>,
    /// The identity provider that vouched for it (`aws:FederatedProvider`): the web
    /// identity itself, or a role session it started.
    federated_provider: Option<String>,
    /// The service it is (`aws:PrincipalServiceName`), for a service.
    service: Option<String>,
    /// Whether a policy naming the principal's ARN (or a session's role) means this
    /// principal; see [`Self::unbound`].
    bound: bool,
}

impl Principal {
    /// The account's root user.
    #[must_use]
    pub fn root(account: &str) -> Self {
        Self {
            kind: PrincipalKind::Account,
            arn: Some(format!("arn:aws:iam::{account}:root")),
            account: Some(account.to_owned()),
            user_id: account.to_owned(),
            username: None,
            role_arn: None,
            session_name: None,
            canonical_id: None,
            federated_provider: None,
            service: None,
            bound: true,
        }
    }

    /// An IAM user; `path` is `/` unless the user was made under another path
    /// (`/engineering/`). `unique_id` is the user's `AIDA…` id.
    #[must_use]
    pub fn user(account: &str, path: &str, name: &str, unique_id: &str) -> Self {
        Self {
            kind: PrincipalKind::User,
            arn: Some(format!("arn:aws:iam::{account}:user{path}{name}")),
            account: Some(account.to_owned()),
            user_id: unique_id.to_owned(),
            username: Some(name.to_owned()),
            role_arn: None,
            session_name: None,
            canonical_id: None,
            federated_provider: None,
            service: None,
            bound: true,
        }
    }

    /// A session of the role `role_path` + `role_name`, whose `AROA…` id is `role_id`.
    #[must_use]
    pub fn session(
        account: &str,
        role_path: &str,
        role_name: &str,
        role_id: &str,
        session_name: &str,
    ) -> Self {
        Self {
            kind: PrincipalKind::AssumedRole,
            arn: Some(format!(
                "arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"
            )),
            account: Some(account.to_owned()),
            user_id: format!("{role_id}:{session_name}"),
            username: None,
            role_arn: Some(format!("arn:aws:iam::{account}:role{role_path}{role_name}")),
            session_name: Some(session_name.to_owned()),
            canonical_id: None,
            federated_provider: None,
            service: None,
            bound: true,
        }
    }

    /// A federated user called `name`, whom a user of `account` started a session for.
    #[must_use]
    pub fn federated(account: &str, name: &str) -> Self {
        Self {
            kind: PrincipalKind::FederatedUser,
            arn: Some(format!("arn:aws:sts::{account}:federated-user/{name}")),
            account: Some(account.to_owned()),
            user_id: format!("{account}:{name}"),
            username: None,
            role_arn: None,
            session_name: None,
            canonical_id: None,
            federated_provider: None,
            service: None,
            bound: true,
        }
    }

    /// Someone the OpenID Connect provider `provider` (its ARN) vouches for as
    /// `subject`, before they have a session: whom a trust policy's `Federated`
    /// principal names.
    #[must_use]
    pub fn web_identity(provider: &str, subject: &str) -> Self {
        Self {
            kind: PrincipalKind::WebIdentityUser,
            arn: None,
            account: None,
            user_id: format!("{provider}:{subject}"),
            username: None,
            role_arn: None,
            session_name: None,
            canonical_id: None,
            federated_provider: Some(provider.to_owned()),
            service: None,
            bound: true,
        }
    }

    /// The same web identity, with a session in `account`: MinIO's
    /// `AssumeRoleWithWebIdentity` without a role, whose session acts as the web
    /// identity itself (`aws:PrincipalAccount`).
    #[must_use]
    pub fn in_account(mut self, account: &str) -> Self {
        self.account = Some(account.to_owned());
        self
    }

    /// The same principal, started by someone the identity provider `provider` vouched
    /// for (`aws:FederatedProvider`): a role session from `AssumeRoleWithWebIdentity`.
    #[must_use]
    pub fn with_federated_provider(mut self, provider: &str) -> Self {
        self.federated_provider = Some(provider.to_owned());
        self
    }

    /// Whoever sends an unsigned request.
    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            kind: PrincipalKind::Anonymous,
            arn: None,
            account: None,
            user_id: "anonymous".to_owned(),
            username: None,
            role_arn: None,
            session_name: None,
            canonical_id: None,
            federated_provider: None,
            service: None,
            bound: true,
        }
    }

    /// The service `name` (`logging.s3.amazonaws.com`), acting for a resource's owner:
    /// whom a `Service` principal names. Say what it acts for with
    /// [`Context::with_source`].
    #[must_use]
    pub fn service(name: &str) -> Self {
        Self {
            kind: PrincipalKind::Service,
            arn: None,
            account: None,
            user_id: name.to_owned(),
            username: None,
            role_arn: None,
            session_name: None,
            canonical_id: None,
            federated_provider: None,
            service: Some(name.to_owned()),
            bound: true,
        }
    }

    /// The same principal, for a policy that names its ARN (or its session's role) as
    /// someone else's: one bound to a user or role since deleted and made again under
    /// the same name. Statements naming the ARN don't reach it, as on AWS, where the
    /// policy then names the old entity's unique id; its account and conditions still
    /// do.
    #[must_use]
    pub const fn unbound(mut self) -> Self {
        self.bound = false;
        self
    }

    /// The same principal, with the canonical user id that ACLs and `CanonicalUser`
    /// principals name.
    #[must_use]
    pub fn with_canonical_id(mut self, id: &str) -> Self {
        self.canonical_id = Some(id.to_owned());
        self
    }

    /// What kind of principal this is.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// The principal's ARN (a session's `assumed-role` ARN); none for anonymous.
    #[must_use]
    pub fn arn(&self) -> Option<&str> {
        self.arn.as_deref()
    }

    /// `aws:userid`: the account id for the root user, a user's unique id, `role-id:session`
    /// for a session, `anonymous`.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// `aws:username`: an IAM user's name; none for others.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The principal's account; none for anonymous.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub(crate) fn role_arn(&self) -> Option<&str> {
        self.role_arn.as_deref()
    }

    pub(crate) fn canonical_id(&self) -> Option<&str> {
        self.canonical_id.as_deref()
    }

    /// The service it is, if it's one.
    #[must_use]
    pub fn service_name(&self) -> Option<&str> {
        self.service.as_deref()
    }

    /// The identity provider a web identity comes from, if this is one (not a session
    /// it started): what a `Federated` principal names.
    pub(crate) fn web_identity_provider(&self) -> Option<&str> {
        (self.kind == PrincipalKind::WebIdentityUser)
            .then_some(self.federated_provider.as_deref())
            .flatten()
    }

    pub(crate) const fn is_bound(&self) -> bool {
        self.bound
    }
}

/// Sets `key` in a list of key values, replacing its earlier value.
fn set<K: PartialEq>(list: &mut Vec<(K, Value)>, key: K, value: Value) {
    match list.iter_mut().find(|(k, _)| *k == key) {
        Some((_, old)) => *old = value,
        None => list.push((key, value)),
    }
}

/// The values of `key` in a list of key values.
fn get<'a, K: PartialEq>(list: &'a [(K, Value)], key: &K) -> Values<'a> {
    list.iter()
        .find(|(k, _)| k == key)
        .map_or(Values::None, |(_, value)| value.values())
}

/// A value the server records for a condition key.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Text.
    String(String),
    /// Several texts: a multivalued key such as `aws:TagKeys`.
    Strings(Vec<String>),
    /// A number.
    Number(Number),
    /// `true` or `false`.
    Bool(bool),
    /// An instant.
    Date(Date),
    /// An address.
    Ip(IpAddr),
}

impl Value {
    fn values(&self) -> Values<'_> {
        match self {
            Self::String(text) => Values::One(Item::Str(text)),
            Self::Strings(texts) => Values::Many(texts),
            Self::Number(n) => Values::One(Item::Number(*n)),
            Self::Bool(b) => Values::One(Item::Bool(*b)),
            Self::Date(d) => Values::One(Item::Date(*d)),
            Self::Ip(ip) => Values::One(Item::Ip(*ip)),
        }
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::String(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::String(text)
    }
}

impl From<Vec<String>> for Value {
    fn from(texts: Vec<String>) -> Self {
        Self::Strings(texts)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Self::Number(Number::from_int(n))
    }
}

impl From<Number> for Value {
    fn from(n: Number) -> Self {
        Self::Number(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<Date> for Value {
    fn from(d: Date) -> Self {
        Self::Date(d)
    }
}

impl From<IpAddr> for Value {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

/// A request, as policies see it.
#[derive(Debug, Clone)]
pub struct Context {
    principal: Principal,
    now: Date,
    secure_transport: bool,
    source_ip: Option<IpAddr>,
    user_agent: Option<String>,
    referer: Option<String>,
    region: Option<String>,
    resource_account: Option<String>,
    token_issue_time: Option<Date>,
    source_identity: Option<String>,
    /// `aws:SourceArn` and `aws:SourceAccount`: what a service acts for.
    source: Option<(String, String)>,
    s3: Vec<(S3Key, Value)>,
    iam: Vec<(IamKey, Value)>,
    sts: Vec<(StsKey, Value)>,
    /// Kind, tag key, tag value.
    tags: Vec<(TagKind, String, String)>,
    /// `aws:TagKeys`: the keys of the `aws:RequestTag`s.
    request_tag_keys: Vec<String>,
    /// `s3:RequestObjectTagKeys`: the keys of the `s3:RequestObjectTag`s.
    request_object_tag_keys: Vec<String>,
    /// An identity provider's keys (`idp.example.com:sub`): the claims of a web
    /// identity token, by the names policies give them.
    claims: Vec<(Box<str>, Value)>,
}

impl Context {
    /// A request by `principal` at `now`, over plain HTTP from an unknown address until
    /// said otherwise.
    #[must_use]
    pub fn new(principal: Principal, now: Date) -> Self {
        Self {
            principal,
            now,
            secure_transport: false,
            source_ip: None,
            user_agent: None,
            referer: None,
            region: None,
            resource_account: None,
            token_issue_time: None,
            source_identity: None,
            source: None,
            s3: Vec::new(),
            iam: Vec::new(),
            sts: Vec::new(),
            tags: Vec::new(),
            request_tag_keys: Vec::new(),
            request_object_tag_keys: Vec::new(),
            claims: Vec::new(),
        }
    }

    /// Who makes the request.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The same request, as `principal` makes it.
    #[must_use]
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = principal;
        self
    }

    /// `aws:SecureTransport`: whether the request came over TLS.
    #[must_use]
    pub const fn with_secure_transport(mut self, secure: bool) -> Self {
        self.secure_transport = secure;
        self
    }

    /// `aws:SourceIp`: the client's address.
    #[must_use]
    pub const fn with_source_ip(mut self, address: IpAddr) -> Self {
        self.source_ip = Some(address);
        self
    }

    /// `aws:UserAgent`.
    #[must_use]
    pub fn with_user_agent(mut self, agent: &str) -> Self {
        self.user_agent = Some(agent.to_owned());
        self
    }

    /// `aws:referer`.
    #[must_use]
    pub fn with_referer(mut self, referer: &str) -> Self {
        self.referer = Some(referer.to_owned());
        self
    }

    /// `aws:RequestedRegion`.
    #[must_use]
    pub fn with_region(mut self, region: &str) -> Self {
        self.region = Some(region.to_owned());
        self
    }

    /// `aws:ResourceAccount` and `s3:ResourceAccount`: the account that owns the resource.
    #[must_use]
    pub fn with_resource_account(mut self, account: &str) -> Self {
        self.resource_account = Some(account.to_owned());
        self
    }

    /// `aws:TokenIssueTime`: when a session's credentials were issued.
    #[must_use]
    pub const fn with_token_issue_time(mut self, issued: Date) -> Self {
        self.token_issue_time = Some(issued);
        self
    }

    /// `aws:SourceIdentity`: who a session says started it (`SourceIdentity`).
    #[must_use]
    pub fn with_source_identity(mut self, identity: &str) -> Self {
        self.source_identity = Some(identity.to_owned());
        self
    }

    /// `aws:SourceArn` and `aws:SourceAccount`: the resource (`arn:aws:s3:::logged`) and
    /// account a service acts for.
    #[must_use]
    pub fn with_source(mut self, arn: &str, account: &str) -> Self {
        self.source = Some((arn.to_owned(), account.to_owned()));
        self
    }

    /// An STS key's value (`sts:ExternalId` of an `AssumeRole` request), replacing any
    /// earlier one.
    #[must_use]
    pub fn with_sts(mut self, key: StsKey, value: impl Into<Value>) -> Self {
        set(&mut self.sts, key, value.into());
        self
    }

    /// An S3 key's value, replacing any earlier one. `s3:RequestObjectTagKeys` and
    /// `s3:ResourceAccount` follow from other settings and can't be set here.
    #[must_use]
    pub fn with(mut self, key: S3Key, value: impl Into<Value>) -> Self {
        debug_assert!(
            !matches!(key, S3Key::RequestObjectTagKeys | S3Key::ResourceAccount),
            "{} is derived",
            key.name()
        );
        set(&mut self.s3, key, value.into());
        self
    }

    /// An IAM key's value (`iam:PolicyARN` of an attach request), replacing any earlier
    /// one.
    #[must_use]
    pub fn with_iam(mut self, key: IamKey, value: impl Into<Value>) -> Self {
        set(&mut self.iam, key, value.into());
        self
    }

    /// A tag: of the principal, of the resource, or one the request sets.
    #[must_use]
    pub fn with_tag(mut self, kind: TagKind, key: &str, value: &str) -> Self {
        match kind {
            TagKind::Request => self.request_tag_keys.push(key.to_owned()),
            TagKind::RequestObject => self.request_object_tag_keys.push(key.to_owned()),
            _ => {}
        }
        self.tags.push((kind, key.to_owned(), value.to_owned()));
        self
    }

    /// `aws:TagKeys` for a request that names tag keys without values (`UntagUser`).
    #[must_use]
    pub fn with_tag_keys<'k>(mut self, keys: impl IntoIterator<Item = &'k str>) -> Self {
        self.request_tag_keys
            .extend(keys.into_iter().map(str::to_owned));
        self
    }

    /// An identity provider's key (`idp.example.com:sub`), replacing any earlier value.
    /// Its name compares without case, as condition keys' names do.
    #[must_use]
    pub fn with_claim(mut self, name: &str, value: impl Into<Value>) -> Self {
        let value = value.into();
        match self
            .claims
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            Some((_, old)) => *old = value,
            None => self.claims.push((name.into(), value)),
        }
        self
    }

    /// The values the request has for `key`; none when it doesn't have the key.
    pub(crate) fn lookup(&self, key: &Key) -> Values<'_> {
        match key {
            Key::Global(key) => self.global(*key),
            Key::S3(S3Key::RequestObjectTagKeys) => Values::Many(&self.request_object_tag_keys),
            Key::S3(S3Key::ResourceAccount) => Values::text(self.resource_account.as_deref()),
            Key::S3(key) => get(&self.s3, key),
            Key::Iam(key) => get(&self.iam, key),
            Key::Sts(key) => get(&self.sts, key),
            Key::Tag(kind, name) => self.tag(*kind, name),
            Key::Unknown(name) => self
                .claims
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map_or(Values::None, |(_, value)| value.values()),
        }
    }

    fn global(&self, key: GlobalKey) -> Values<'_> {
        let principal = &self.principal;
        match key {
            GlobalKey::CurrentTime => Values::One(Item::Date(self.now)),
            GlobalKey::EpochTime => Values::One(Item::Number(Number::from_int(
                i64::try_from(self.now.unix_seconds()).unwrap_or(i64::MAX),
            ))),
            GlobalKey::SecureTransport => Values::One(Item::Bool(self.secure_transport)),
            GlobalKey::SourceIp => self
                .source_ip
                .map_or(Values::None, |ip| Values::One(Item::Ip(ip))),
            GlobalKey::UserAgent => Values::text(self.user_agent.as_deref()),
            GlobalKey::Referer => Values::text(self.referer.as_deref()),
            GlobalKey::RequestedRegion => Values::text(self.region.as_deref()),
            GlobalKey::ResourceAccount => Values::text(self.resource_account.as_deref()),
            GlobalKey::TokenIssueTime => self
                .token_issue_time
                .map_or(Values::None, |d| Values::One(Item::Date(d))),
            GlobalKey::PrincipalAccount => Values::text(principal.account.as_deref()),
            GlobalKey::PrincipalArn => {
                Values::text(principal.role_arn.as_deref().or(principal.arn.as_deref()))
            }
            GlobalKey::PrincipalType if principal.kind == PrincipalKind::Service => Values::None,
            GlobalKey::PrincipalType => Values::One(Item::Str(principal.kind.name())),
            GlobalKey::UserId => Values::One(Item::Str(&principal.user_id)),
            GlobalKey::Username => Values::text(principal.username.as_deref()),
            GlobalKey::RoleSessionName => Values::text(principal.session_name.as_deref()),
            GlobalKey::SourceIdentity => Values::text(self.source_identity.as_deref()),
            GlobalKey::PrincipalIsAwsService => {
                Values::One(Item::Bool(principal.service.is_some()))
            }
            GlobalKey::ViaAwsService => Values::One(Item::Bool(false)),
            GlobalKey::PrincipalServiceName => Values::text(principal.service.as_deref()),
            GlobalKey::SourceArn => Values::text(self.source.as_ref().map(|(arn, _)| arn.as_str())),
            GlobalKey::SourceAccount => {
                Values::text(self.source.as_ref().map(|(_, account)| account.as_str()))
            }
            GlobalKey::TagKeys => Values::Many(&self.request_tag_keys),
            GlobalKey::FederatedProvider => Values::text(principal.federated_provider.as_deref()),
            GlobalKey::CalledVia
            | GlobalKey::CalledViaFirst
            | GlobalKey::CalledViaLast
            | GlobalKey::MultiFactorAuthAge
            | GlobalKey::MultiFactorAuthPresent
            | GlobalKey::PrincipalOrgId
            | GlobalKey::PrincipalOrgPaths
            | GlobalKey::PrincipalServiceNamesList
            | GlobalKey::ResourceOrgId
            | GlobalKey::ResourceOrgPaths
            | GlobalKey::SourceOrgId
            | GlobalKey::SourceOrgPaths
            | GlobalKey::SourceOwner
            | GlobalKey::SourceVpc
            | GlobalKey::SourceVpce
            | GlobalKey::VpcSourceIp => Values::None,
        }
    }

    /// A tag's value, its key compared without case; a key given in exactly that case
    /// wins over one that differs only in case.
    fn tag(&self, kind: TagKind, name: &str) -> Values<'_> {
        let mut found = None;
        for (k, key, value) in &self.tags {
            if *k == kind && key.eq_ignore_ascii_case(name) {
                if key == name {
                    return Values::One(Item::Str(value));
                }
                found.get_or_insert(value.as_str());
            }
        }
        Values::text(found)
    }
}

/// The values a request has for one key.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Values<'a> {
    None,
    One(Item<'a>),
    Many(&'a [String]),
}

impl<'a> Values<'a> {
    fn text(text: Option<&'a str>) -> Self {
        text.map_or(Self::None, |text| Self::One(Item::Str(text)))
    }

    /// No values: the key is absent (or an empty list).
    pub(crate) fn is_empty(self) -> bool {
        match self {
            Self::None => true,
            Self::One(_) => false,
            Self::Many(items) => items.is_empty(),
        }
    }

    /// The value, when there's exactly one (policy variables take only those).
    pub(crate) fn single(self) -> Option<Item<'a>> {
        match self {
            Self::One(item) => Some(item),
            Self::None | Self::Many(_) => None,
        }
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = Item<'a>> {
        let (one, many): (Option<Item<'a>>, &'a [String]) = match self {
            Self::None => (None, &[]),
            Self::One(item) => (Some(item), &[]),
            Self::Many(items) => (None, items),
        };
        one.into_iter().chain(many.iter().map(|s| Item::Str(s)))
    }
}

/// One value, seen as whatever type the operator compares.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Item<'a> {
    Str(&'a str),
    Number(Number),
    Bool(bool),
    Date(Date),
    Ip(IpAddr),
}

impl<'a> Item<'a> {
    pub(crate) fn text(self) -> Cow<'a, str> {
        match self {
            Self::Str(text) => Cow::Borrowed(text),
            Self::Number(n) => Cow::Owned(n.to_string()),
            Self::Bool(b) => Cow::Borrowed(if b { "true" } else { "false" }),
            Self::Date(d) => Cow::Owned(d.to_string()),
            Self::Ip(ip) => Cow::Owned(ip.to_string()),
        }
    }

    pub(crate) fn number(self) -> Option<Number> {
        match self {
            Self::Str(text) => Number::parse(text),
            Self::Number(n) => Some(n),
            Self::Date(d) => i64::try_from(d.unix_seconds()).ok().map(Number::from_int),
            Self::Bool(_) | Self::Ip(_) => None,
        }
    }

    pub(crate) fn date(self) -> Option<Date> {
        match self {
            Self::Str(text) => Date::parse(text),
            Self::Date(d) => Some(d),
            Self::Number(n) => n.whole().map(Date::from_unix_seconds),
            Self::Bool(_) | Self::Ip(_) => None,
        }
    }

    pub(crate) fn bool(self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(b),
            Self::Str(text) => parse_bool(text),
            Self::Number(_) | Self::Date(_) | Self::Ip(_) => None,
        }
    }

    pub(crate) fn ip(self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(ip),
            Self::Str(text) => text.parse().ok(),
            Self::Number(_) | Self::Bool(_) | Self::Date(_) => None,
        }
    }
}

/// `true` or `false`, in any case.
pub(crate) fn parse_bool(text: &str) -> Option<bool> {
    if text.eq_ignore_ascii_case("true") {
        Some(true)
    } else if text.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(context: &Context, name: &str) -> Option<String> {
        let key = Key::parse(name).unwrap();
        context
            .lookup(&key)
            .iter()
            .next()
            .map(|item| item.text().into_owned())
    }

    #[test]
    fn web_identities_answer_their_providers_keys() {
        let at = Date::from_unix_seconds(1_800_000_000);
        let provider = "arn:aws:iam::123456789012:oidc-provider/idp.example.com";
        let web = Context::new(Principal::web_identity(provider, "alice"), at)
            .with_claim("idp.example.com:aud", "app");
        assert_eq!(
            first(&web, "aws:PrincipalType").as_deref(),
            Some("WebIdentityUser")
        );
        assert_eq!(
            first(&web, "aws:FederatedProvider").as_deref(),
            Some(provider)
        );
        assert_eq!(first(&web, "aws:PrincipalArn"), None);
        assert_eq!(first(&web, "aws:PrincipalAccount"), None);
        assert_eq!(first(&web, "IDP.example.com:AUD").as_deref(), Some("app"));
        assert_eq!(first(&web, "idp.example.com:sub"), None);
        let session = Context::new(
            Principal::session("123456789012", "/", "web", "AROAX", "s1")
                .with_federated_provider(provider),
            at,
        );
        assert_eq!(
            first(&session, "aws:FederatedProvider").as_deref(),
            Some(provider)
        );
    }

    #[test]
    fn principals_answer_the_principal_keys() {
        let at = Date::from_unix_seconds(1_800_000_000);
        let user = Context::new(
            Principal::user("123456789012", "/eng/", "alice", "AIDAX"),
            at,
        );
        assert_eq!(first(&user, "aws:username").as_deref(), Some("alice"));
        assert_eq!(first(&user, "aws:userid").as_deref(), Some("AIDAX"));
        assert_eq!(first(&user, "aws:PrincipalType").as_deref(), Some("User"));
        assert_eq!(
            first(&user, "aws:PrincipalArn").as_deref(),
            Some("arn:aws:iam::123456789012:user/eng/alice")
        );
        assert_eq!(
            first(&user, "aws:PrincipalAccount").as_deref(),
            Some("123456789012")
        );

        let session = Context::new(
            Principal::session("123456789012", "/", "reader", "AROAR", "job-7"),
            at,
        );
        assert_eq!(
            first(&session, "aws:username"),
            None,
            "only IAM users have one"
        );
        assert_eq!(
            first(&session, "aws:userid").as_deref(),
            Some("AROAR:job-7")
        );
        assert_eq!(
            first(&session, "aws:PrincipalArn").as_deref(),
            Some("arn:aws:iam::123456789012:role/reader"),
            "a session's aws:PrincipalArn is its role"
        );
        assert_eq!(
            first(&session, "aws:RoleSessionName").as_deref(),
            Some("job-7")
        );

        let federated = Context::new(Principal::federated("123456789012", "bob"), at)
            .with_source_identity("alice@example.com")
            .with_sts(StsKey::ExternalId, "x-1")
            .with_sts(
                StsKey::TransitiveTagKeys,
                vec!["team".to_owned(), "cost".to_owned()],
            );
        assert_eq!(
            first(&federated, "aws:PrincipalType").as_deref(),
            Some("FederatedUser")
        );
        assert_eq!(
            first(&federated, "aws:PrincipalArn").as_deref(),
            Some("arn:aws:sts::123456789012:federated-user/bob")
        );
        assert_eq!(
            first(&federated, "aws:userid").as_deref(),
            Some("123456789012:bob")
        );
        assert_eq!(first(&federated, "aws:username"), None);
        assert_eq!(
            first(&federated, "aws:SourceIdentity").as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(first(&federated, "sts:ExternalId").as_deref(), Some("x-1"));
        assert_eq!(
            federated
                .lookup(&Key::parse("sts:TransitiveTagKeys").unwrap())
                .iter()
                .count(),
            2
        );
        assert_eq!(first(&session, "aws:SourceIdentity"), None);

        let anonymous = Context::new(Principal::anonymous(), at);
        assert_eq!(
            first(&anonymous, "aws:userid").as_deref(),
            Some("anonymous")
        );
        assert_eq!(first(&anonymous, "aws:PrincipalArn"), None);
        assert_eq!(first(&anonymous, "aws:PrincipalAccount"), None);

        let root = Context::new(Principal::root("123456789012"), at);
        assert_eq!(first(&root, "aws:userid").as_deref(), Some("123456789012"));
        assert_eq!(
            first(&root, "aws:PrincipalType").as_deref(),
            Some("Account")
        );
    }

    #[test]
    fn request_facts_and_derived_keys() {
        let context = Context::new(
            Principal::anonymous(),
            Date::from_unix_seconds(1_800_000_000),
        )
        .with_secure_transport(true)
        .with_source_ip("203.0.113.9".parse().unwrap())
        .with(S3Key::Prefix, "photos/")
        .with(S3Key::MaxKeys, 100)
        .with(S3Key::Prefix, "docs/")
        .with_tag(TagKind::Request, "Team", "blue")
        .with_tag(TagKind::Request, "cost", "7")
        .with_tag(TagKind::RequestObject, "k", "v")
        .with_resource_account("123456789012");
        assert_eq!(
            first(&context, "aws:CurrentTime").as_deref(),
            Some("2027-01-15T08:00:00Z")
        );
        assert_eq!(
            first(&context, "aws:EpochTime").as_deref(),
            Some("1800000000")
        );
        assert_eq!(
            first(&context, "aws:SecureTransport").as_deref(),
            Some("true")
        );
        assert_eq!(
            first(&context, "aws:SourceIp").as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            first(&context, "s3:prefix").as_deref(),
            Some("docs/"),
            "the last setting wins"
        );
        assert_eq!(first(&context, "s3:max-keys").as_deref(), Some("100"));
        let keys: Vec<String> = context
            .lookup(&Key::parse("aws:TagKeys").unwrap())
            .iter()
            .map(|i| i.text().into_owned())
            .collect();
        assert_eq!(keys, ["Team", "cost"]);
        assert_eq!(
            first(&context, "s3:RequestObjectTagKeys").as_deref(),
            Some("k")
        );
        assert_eq!(
            first(&context, "s3:ResourceAccount").as_deref(),
            Some("123456789012")
        );
        assert_eq!(
            first(&context, "aws:ResourceAccount").as_deref(),
            Some("123456789012")
        );
        assert_eq!(
            first(&context, "aws:ViaAWSService").as_deref(),
            Some("false")
        );
        assert_eq!(first(&context, "aws:SourceVpc"), None);
        assert_eq!(first(&context, "s3:x-amz-acl"), None);
        assert_eq!(
            first(&context, "x-amz-acl"),
            None,
            "an unknown key never has a value"
        );
    }

    #[test]
    fn tag_keys_compare_without_case_and_exact_case_wins() {
        let context = Context::new(Principal::anonymous(), Date::from_unix_seconds(0))
            .with_tag(TagKind::ExistingObject, "Team", "upper")
            .with_tag(TagKind::ExistingObject, "team", "lower")
            .with_tag(TagKind::Resource, "Owner", "ops");
        assert_eq!(
            first(&context, "s3:ExistingObjectTag/Team").as_deref(),
            Some("upper")
        );
        assert_eq!(
            first(&context, "s3:ExistingObjectTag/team").as_deref(),
            Some("lower")
        );
        assert_eq!(
            first(&context, "s3:ExistingObjectTag/TEAM").as_deref(),
            Some("upper")
        );
        assert_eq!(
            first(&context, "aws:ResourceTag/owner").as_deref(),
            Some("ops")
        );
        assert_eq!(
            first(&context, "aws:RequestTag/owner"),
            None,
            "another family"
        );
    }

    #[test]
    fn items_convert_as_operators_need() {
        assert_eq!(Item::Str("1.5").number(), Number::parse("1.5"));
        assert_eq!(Item::Str("TRUE").bool(), Some(true));
        assert_eq!(Item::Str("yes").bool(), None);
        assert_eq!(
            Item::Number(Number::from_int(60)).date(),
            Some(Date::from_unix_seconds(60))
        );
        assert_eq!(Item::Number(Number::parse("1.5").unwrap()).date(), None);
        assert_eq!(
            Item::Date(Date::from_unix_seconds(60)).number(),
            Some(Number::from_int(60))
        );
        assert_eq!(Item::Str("10.0.0.1").ip(), "10.0.0.1".parse().ok());
        assert_eq!(Item::Bool(true).ip(), None);
    }
}
