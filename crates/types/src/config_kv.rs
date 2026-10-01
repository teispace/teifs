//! `MinIO`'s server configuration as key-value text (`mc admin config get|set|reset|
//! export|import`): one line per sub-system and target, `identity_ldap server_addr=…
//! lookup_bind_dn="cn=admin, dc=example"`, `identity_openid:keycloak config_url=…`.
//!
//! TeiFS keeps it for the sub-systems it has settings for. Each value stands for the
//! `MinIO` variable that names it (`MINIO_IDENTITY_LDAP_SERVER_ADDR`,
//! `MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK`), which `teifs serve` reads after its own
//! flags, environment and settings file, and after the real variable; see
//! [`ConfigKv::variables`].

use std::{collections::BTreeMap, fmt::Write as _};

use serde::{Deserialize, Serialize};

/// The target of a sub-system that has one, or the first of one that has several.
pub const DEFAULT_TARGET: &str = "_";

/// The key every sub-system has for a note about its settings.
pub const COMMENT: &str = "comment";

/// The key that turns a sub-system's target on or off.
pub const ENABLE: &str = "enable";

/// The prefix of the variable each value stands for.
pub const VARIABLE_PREFIX: &str = "MINIO_";

/// What's wrong with a change to the configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// What it names isn't there (`XMinioConfigNotFoundError`, 404).
    #[error("{0}")]
    NotFound(String),
    /// It isn't a configuration TeiFS takes (`XMinioConfigError`, 400).
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// One of a sub-system's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// Its name, as `set` takes it.
    pub name: &'static str,
    /// What its value is, as `MinIO`'s help says it: `string`, `url`, `on|off`, `csv`…
    pub kind: &'static str,
    /// What it's for.
    pub description: &'static str,
    /// Whether it may be empty while the target is on.
    pub optional: bool,
    /// Whether its value is a secret: never in what `get` answers.
    pub secret: bool,
    /// Its value until one is set.
    pub default: &'static str,
    /// Left out of what's written while it's empty (keys `MinIO` deprecated).
    pub hidden_if_empty: bool,
}

impl Key {
    const fn new(name: &'static str, kind: &'static str, description: &'static str) -> Self {
        Self {
            name,
            kind,
            description,
            optional: true,
            secret: false,
            default: "",
            hidden_if_empty: false,
        }
    }

    const fn required(mut self) -> Self {
        self.optional = false;
        self
    }

    const fn secret(mut self) -> Self {
        self.secret = true;
        self
    }

    const fn default(mut self, value: &'static str) -> Self {
        self.default = value;
        self
    }

    const fn hidden_if_empty(mut self) -> Self {
        self.hidden_if_empty = true;
        self
    }
}

/// A part of the server's configuration, with its keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subsystem {
    /// Its name, as `MinIO` spells it.
    pub name: &'static str,
    /// What it configures.
    pub description: &'static str,
    /// Whether it has targets besides [`DEFAULT_TARGET`] (`identity_openid:NAME`).
    pub multiple_targets: bool,
    /// Whether it has an [`ENABLE`] key, which a change that doesn't name it sets `on`.
    pub enable: bool,
    /// Its keys, in the order they're written, without [`ENABLE`] and [`COMMENT`].
    pub keys: &'static [Key],
}

const UNUSED_OPENID: &str = "for MinIO's console, which TeiFS doesn't have: kept, not used";

const OPENID_KEYS: &[Key] = &[
    Key::new("display_name", "string", UNUSED_OPENID),
    Key::new(
        "config_url",
        "url",
        "the provider's discovery URL (…/.well-known/openid-configuration) or issuer",
    )
    .required(),
    Key::new(
        "client_id",
        "string",
        "the client the provider's tokens are for",
    )
    .required(),
    Key::new("client_secret", "string", UNUSED_OPENID).secret(),
    Key::new(
        "claim_name",
        "string",
        "the claim that names a token's policies, when it has no role policy",
    )
    .default("policy"),
    Key::new(
        "claim_userinfo",
        "on|off",
        "fill claims missing from an access token from the provider's userinfo endpoint",
    ),
    Key::new(
        "role_policy",
        "string",
        "policies, comma-separated, for every token of this provider (its role's ARN)",
    ),
    Key::new("claim_prefix", "string", UNUSED_OPENID).hidden_if_empty(),
    Key::new("redirect_uri", "string", UNUSED_OPENID).hidden_if_empty(),
    Key::new("redirect_uri_dynamic", "on|off", UNUSED_OPENID).default("off"),
    Key::new("scopes", "csv", UNUSED_OPENID),
    Key::new("vendor", "string", UNUSED_OPENID),
    Key::new("keycloak_realm", "string", UNUSED_OPENID),
    Key::new("keycloak_admin_url", "string", UNUSED_OPENID),
    Key::new("user_readable_claim", "string", UNUSED_OPENID),
    Key::new("user_id_claim", "string", UNUSED_OPENID),
];

const LDAP_KEYS: &[Key] = &[
    Key::new(
        "server_addr",
        "address",
        "the directory's host:port (636 for LDAPS)",
    )
    .required(),
    Key::new(
        "srv_record_name",
        "string",
        "find the directory by DNS SRV records: ldap or on (_ldap._tcp), or none",
    ),
    Key::new(
        "user_dn_search_base_dn",
        "list",
        "where users are looked up, semicolon-separated",
    ),
    Key::new(
        "user_dn_search_filter",
        "string",
        "the filter that finds a user, %s standing for the name they sign in with",
    ),
    Key::new(
        "user_dn_attributes",
        "list",
        "the user's attributes kept in their credentials, semicolon-separated",
    ),
    Key::new(
        "group_search_filter",
        "string",
        "the filter that finds a user's groups (%d their DN, %s their name)",
    ),
    Key::new(
        "group_search_base_dn",
        "list",
        "where groups are looked up, semicolon-separated",
    ),
    Key::new(
        "tls_skip_verify",
        "on|off",
        "trust any certificate the directory shows (testing only)",
    )
    .default("off"),
    Key::new("server_insecure", "on|off", "plain LDAP, without TLS").default("off"),
    Key::new(
        "server_starttls",
        "on|off",
        "plain LDAP upgraded with StartTLS",
    )
    .default("off"),
    Key::new(
        "lookup_bind_dn",
        "string",
        "the account TeiFS looks users and groups up as",
    ),
    Key::new("lookup_bind_password", "string", "that account's password").secret(),
];

const PLUGIN_KEYS: &[Key] = &[
    Key::new(
        "url",
        "url",
        "the identity plugin's URL, which says who a custom token is",
    )
    .required(),
    Key::new(
        "auth_token",
        "string",
        "the Authorization header TeiFS sends it",
    )
    .secret(),
    Key::new(
        "role_policy",
        "string",
        "policies, comma-separated, for the credentials it grants",
    )
    .required(),
    Key::new("role_id", "string", "the role's id in its ARN"),
];

const QUEUED: &str = "kept, not used: TeiFS keeps events waiting on the drive itself";
const UNUSED: &str = "kept, not used";
const NO_SKIP: &str = "must stay off: TeiFS always checks the server's certificate (give its CA)";
const FORMAT: &str =
    "namespace (one entry per object, replaced by each event) or access (one per event)";

const fn queue_keys() -> [Key; 2] {
    [
        Key::new("queue_dir", "path", QUEUED),
        Key::new("queue_limit", "number", QUEUED).default("0"),
    ]
}

const WEBHOOK_KEYS: &[Key] = &[
    Key::new(
        "endpoint",
        "url",
        "the webhook's URL, which each event is POSTed to",
    )
    .required(),
    Key::new(
        "auth_token",
        "string",
        "its Authorization header: a token, sent as Bearer, or SCHEME TOKEN",
    )
    .secret(),
    queue_keys()[0],
    queue_keys()[1],
    Key::new(
        "client_cert",
        "path",
        "a client certificate to show an https webhook that asks",
    ),
    Key::new("client_key", "path", "that certificate's private key"),
];

const AUDIT_WEBHOOK_KEYS: &[Key] = &[
    Key::new(
        "endpoint",
        "url",
        "the webhook's URL, which each audit entry is POSTed to",
    )
    .required(),
    Key::new(
        "auth_token",
        "string",
        "its Authorization header: a token, sent as Bearer, or SCHEME TOKEN",
    )
    .secret(),
    Key::new(
        "client_cert",
        "path",
        "a client certificate to show an https webhook that asks",
    ),
    Key::new("client_key", "path", "that certificate's private key"),
    Key::new("batch_size", "number", UNUSED).default("1"),
    Key::new("queue_size", "number", UNUSED).default("100000"),
    Key::new("queue_dir", "path", UNUSED),
    Key::new("max_retry", "number", UNUSED).default("0"),
    Key::new("retry_interval", "duration", UNUSED).default("3s"),
    Key::new("http_timeout", "duration", UNUSED).default("5s"),
];

const ELASTICSEARCH_KEYS: &[Key] = &[
    Key::new("url", "url", "the Elasticsearch server").required(),
    Key::new("format", "enum", FORMAT)
        .default("namespace")
        .required(),
    Key::new(
        "index",
        "string",
        "the index events go to; made when it's missing",
    )
    .required(),
    queue_keys()[0],
    queue_keys()[1],
    Key::new("username", "string", "the user TeiFS signs in as"),
    Key::new("password", "string", "that user's password").secret(),
];

const REDIS_KEYS: &[Key] = &[
    Key::new("address", "address", "the Redis server's host:port").required(),
    Key::new("format", "enum", FORMAT)
        .default("namespace")
        .required(),
    Key::new(
        "key",
        "string",
        "the hash (namespace) or list (access) events go to",
    )
    .required(),
    Key::new("password", "string", "the server's password").secret(),
    Key::new("user", "string", "the ACL user TeiFS signs in as"),
    queue_keys()[0],
    queue_keys()[1],
];

const NSQ_KEYS: &[Key] = &[
    Key::new("nsqd_address", "address", "the nsqd server's host:port").required(),
    Key::new("topic", "string", "the topic events are published to").required(),
    Key::new("tls", "on|off", "connect with TLS").default("off"),
    Key::new("tls_skip_verify", "on|off", NO_SKIP).default("off"),
    queue_keys()[0],
    queue_keys()[1],
];

const NATS_KEYS: &[Key] = &[
    Key::new("address", "address", "the NATS server's host:port").required(),
    Key::new("subject", "string", "the subject events are published to").required(),
    Key::new("username", "string", "the user TeiFS signs in as"),
    Key::new("password", "string", "that user's password").secret(),
    Key::new("token", "string", "a token to sign in with instead").secret(),
    Key::new("tls", "on|off", "connect with TLS").default("off"),
    Key::new("tls_skip_verify", "on|off", NO_SKIP).default("off"),
    Key::new(
        "cert_authority",
        "path",
        "the CA that signed the server's certificate",
    ),
    Key::new(
        "client_cert",
        "path",
        "a client certificate to show the server",
    ),
    Key::new("client_key", "path", "that certificate's private key"),
    Key::new("ping_interval", "duration", UNUSED).default("0"),
    Key::new(
        "jetstream",
        "on|off",
        "publish to a JetStream stream, waiting for its acknowledgement",
    )
    .default("off"),
    Key::new(
        "streaming",
        "on|off",
        "NATS Streaming, which NATS retired: must stay off",
    )
    .default("off"),
    Key::new("streaming_async", "on|off", UNUSED).default("off"),
    Key::new("streaming_max_pub_acks_in_flight", "number", UNUSED).default("0"),
    Key::new("streaming_cluster_id", "string", UNUSED),
    queue_keys()[0],
    queue_keys()[1],
    Key::new(
        "nkey_seed",
        "path",
        "a file with the NKey seed to sign in with",
    ),
    Key::new(
        "tls_handshake_first",
        "on|off",
        "start TLS before NATS's greeting",
    )
    .default("off"),
];

const MQTT_KEYS: &[Key] = &[
    Key::new(
        "broker",
        "uri",
        "the broker: tcp://, ssl://, ws:// or wss:// and host:port",
    )
    .required(),
    Key::new("topic", "string", "the topic events are published to").required(),
    Key::new("password", "string", "the user's password").secret(),
    Key::new("username", "string", "the user TeiFS signs in as"),
    Key::new("qos", "number", "quality of service: 0, 1 or 2").default("0"),
    Key::new(
        "keep_alive_interval",
        "duration",
        "how often TeiFS pings the broker, as 10s (0s: its default)",
    )
    .default("0s"),
    Key::new("reconnect_interval", "duration", UNUSED).default("0s"),
    queue_keys()[0],
    queue_keys()[1],
];

const KAFKA_KEYS: &[Key] = &[
    Key::new("topic", "string", "the topic events are produced to").required(),
    Key::new("brokers", "csv", "the brokers, host:port, comma-separated").required(),
    Key::new("sasl_username", "string", "the SASL user TeiFS signs in as"),
    Key::new("sasl_password", "string", "that user's password").secret(),
    Key::new("sasl_mechanism", "string", "plain, sha256 or sha512").default("plain"),
    Key::new(
        "client_tls_cert",
        "path",
        "a client certificate to show the brokers",
    ),
    Key::new("client_tls_key", "path", "that certificate's private key"),
    Key::new("tls_client_auth", "string", UNUSED).default("0"),
    Key::new("sasl", "on|off", "sign in with SASL").default("off"),
    Key::new("tls", "on|off", "connect with TLS").default("off"),
    Key::new("tls_skip_verify", "on|off", NO_SKIP).default("off"),
    queue_keys()[1],
    queue_keys()[0],
    Key::new("version", "string", UNUSED),
    Key::new("batch_size", "number", UNUSED).default("0"),
    Key::new("batch_commit_timeout", "duration", UNUSED).default("0s"),
    Key::new(
        "compression_codec",
        "string",
        "none, snappy, gzip, lz4 or zstd",
    ),
    Key::new("compression_level", "number", UNUSED),
];

const AMQP_KEYS: &[Key] = &[
    Key::new(
        "url",
        "url",
        "the server, amqp[s]://USER:PASSWORD@HOST:PORT/VHOST",
    )
    .required()
    .secret(),
    Key::new(
        "exchange",
        "string",
        "the exchange events are published to (the default one when empty)",
    ),
    Key::new(
        "exchange_type",
        "string",
        "the exchange's type, when TeiFS declares it: direct, fanout, topic or headers",
    ),
    Key::new(
        "routing_key",
        "string",
        "the routing key events are published with",
    ),
    Key::new(
        "mandatory",
        "on|off",
        "have the server return events no queue takes",
    )
    .default("off"),
    Key::new("durable", "on|off", "declare the exchange durable").default("off"),
    Key::new("no_wait", "on|off", UNUSED).default("off"),
    Key::new("internal", "on|off", "declare the exchange internal").default("off"),
    Key::new(
        "auto_deleted",
        "on|off",
        "declare the exchange deleted when unused",
    )
    .default("off"),
    Key::new(
        "delivery_mode",
        "number",
        "2 keeps events on disk (persistent), 1 doesn't",
    )
    .default("0"),
    Key::new(
        "publisher_confirms",
        "on|off",
        "kept: TeiFS always waits for the server's confirmation",
    )
    .default("off"),
    queue_keys()[1],
    queue_keys()[0],
];

const POSTGRES_KEYS: &[Key] = &[
    Key::new(
        "connection_string",
        "string",
        "host=… port=… user=… password=… dbname=… sslmode=…, or a postgres:// URL",
    )
    .secret(),
    Key::new(
        "table",
        "string",
        "the table events are written to; made when it's missing",
    )
    .required(),
    Key::new("format", "enum", FORMAT)
        .default("namespace")
        .required(),
    queue_keys()[0],
    queue_keys()[1],
    Key::new("max_open_connections", "number", UNUSED).default("2"),
];

const MYSQL_KEYS: &[Key] = &[
    Key::new("format", "enum", FORMAT)
        .default("namespace")
        .required(),
    Key::new(
        "dsn_string",
        "string",
        "USER:PASSWORD@tcp(HOST:PORT)/DATABASE",
    )
    .secret(),
    Key::new(
        "table",
        "string",
        "the table events are written to; made when it's missing",
    )
    .required(),
    queue_keys()[0],
    queue_keys()[1],
    Key::new("max_open_connections", "number", UNUSED).default("2"),
];

const IDENTITY_TLS_KEYS: &[Key] = &[Key::new(
    "skip_verify",
    "on|off",
    "take client certificates no trusted CA signed (testing only)",
)
.default("off")];

/// A notification sub-system: several targets, each with an `enable`.
const fn notify(name: &'static str, description: &'static str, keys: &'static [Key]) -> Subsystem {
    Subsystem {
        name,
        description,
        multiple_targets: true,
        enable: true,
        keys,
    }
}

/// The sub-systems TeiFS keeps, in the order they're written.
pub const SUBSYSTEMS: &[Subsystem] = &[
    Subsystem {
        name: "identity_openid",
        description: "OpenID Connect providers whose tokens AssumeRoleWithWebIdentity takes",
        multiple_targets: true,
        enable: true,
        keys: OPENID_KEYS,
    },
    Subsystem {
        name: "identity_ldap",
        description: "the LDAP or Active Directory server AssumeRoleWithLDAPIdentity asks",
        multiple_targets: false,
        enable: true,
        keys: LDAP_KEYS,
    },
    Subsystem {
        name: "identity_plugin",
        description: "the identity plugin AssumeRoleWithCustomToken asks",
        multiple_targets: false,
        enable: false,
        keys: PLUGIN_KEYS,
    },
    Subsystem {
        name: "identity_tls",
        description: "client certificates AssumeRoleWithCertificate takes (on with MINIO_IDENTITY_TLS_ENABLE or --identity-tls)",
        multiple_targets: false,
        enable: false,
        keys: IDENTITY_TLS_KEYS,
    },
    notify(
        "notify_webhook",
        "webhooks events are sent to",
        WEBHOOK_KEYS,
    ),
    notify(
        "notify_amqp",
        "AMQP exchanges events are published to",
        AMQP_KEYS,
    ),
    notify(
        "notify_kafka",
        "Kafka topics events are produced to",
        KAFKA_KEYS,
    ),
    notify(
        "notify_mqtt",
        "MQTT topics events are published to",
        MQTT_KEYS,
    ),
    notify(
        "notify_nats",
        "NATS subjects events are published to",
        NATS_KEYS,
    ),
    notify("notify_nsq", "NSQ topics events are published to", NSQ_KEYS),
    notify(
        "notify_mysql",
        "MySQL tables events are written to",
        MYSQL_KEYS,
    ),
    notify(
        "notify_postgres",
        "PostgreSQL tables events are written to",
        POSTGRES_KEYS,
    ),
    notify(
        "notify_elasticsearch",
        "Elasticsearch indexes events are written to",
        ELASTICSEARCH_KEYS,
    ),
    notify(
        "notify_redis",
        "Redis keys events are written to",
        REDIS_KEYS,
    ),
    Subsystem {
        name: "audit_webhook",
        description: "webhooks the audit log is sent to",
        multiple_targets: true,
        enable: true,
        keys: AUDIT_WEBHOOK_KEYS,
    },
];

/// The sub-system named `name`, if TeiFS has it.
#[must_use]
pub fn subsystem(name: &str) -> Option<&'static Subsystem> {
    SUBSYSTEMS.iter().find(|s| s.name == name)
}

fn known(name: &str) -> Result<&'static Subsystem, ConfigError> {
    subsystem(name).ok_or_else(|| {
        invalid(format!(
            "TeiFS has no sub-system {name}: it keeps {}",
            SUBSYSTEMS
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })
}

impl Subsystem {
    /// Its keys' names in the order they're written: [`ENABLE`] first when it has one.
    fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.enable
            .then_some(ENABLE)
            .into_iter()
            .chain(self.keys.iter().map(|k| k.name))
    }

    fn key(&self, name: &str) -> Option<&'static Key> {
        self.keys.iter().find(|k| k.name == name)
    }

    /// Its keys with their defaults, as a target starts.
    fn defaults(&self) -> Kvs {
        self.enable
            .then(|| (ENABLE.to_owned(), String::new()))
            .into_iter()
            .chain(
                self.keys
                    .iter()
                    .map(|k| (k.name.to_owned(), k.default.to_owned())),
            )
            .collect()
    }

    fn default_of(&self, name: &str) -> Option<&'static str> {
        if self.enable && name == ENABLE {
            return Some("");
        }
        self.key(name).map(|k| k.default)
    }

    /// Whether a target with these values is on: not turned off, and with every key
    /// it needs.
    fn is_on(&self, kvs: &Kvs) -> bool {
        (!self.enable || get(kvs, ENABLE).is_some_and(|v| switch(v) == Some(true)))
            && self
                .keys
                .iter()
                .filter(|k| !k.optional)
                .all(|k| get(kvs, k.name).is_some_and(|v| !v.is_empty()))
    }
}

/// A target's keys and values, in order.
type Kvs = Vec<(String, String)>;

fn get<'a>(kvs: &'a Kvs, key: &str) -> Option<&'a str> {
    kvs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

fn set(kvs: &mut Kvs, key: &str, value: String) {
    match kvs.iter_mut().find(|(k, _)| k == key) {
        Some((_, v)) => *v = value,
        None => kvs.push((key.to_owned(), value)),
    }
}

/// An on or off value as `MinIO` takes it.
#[must_use]
pub fn switch(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "enable" | "enabled" | "1" => Some(true),
        "off" | "false" | "disable" | "disabled" | "0" => Some(false),
        _ => None,
    }
}

/// A value without the spaces and quotes around it, as madmin's `SanitizeValue`.
fn sanitize(value: &str) -> String {
    let value = value.trim();
    let value = value.strip_prefix('"').unwrap_or(value);
    let value = value.strip_suffix('"').unwrap_or(value);
    let value = value.strip_prefix('\'').unwrap_or(value);
    value.strip_suffix('\'').unwrap_or(value).to_owned()
}

/// `key=value`, quoted when the value has a space.
fn pair(key: &str, value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("{key}=\"{value}\"")
    } else {
        format!("{key}={value}")
    }
}

/// The variable a value stands for: `MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK`.
#[must_use]
pub fn variable(subsystem: &str, target: &str, key: &str) -> String {
    let mut name = format!("{VARIABLE_PREFIX}{subsystem}_{key}").to_ascii_uppercase();
    if target != DEFAULT_TARGET {
        name.push('_');
        name.push_str(&target.to_ascii_uppercase());
    }
    name
}

/// What a line names: its sub-system, its target and the rest of the line.
struct Line<'a> {
    subsystem: &'static Subsystem,
    target: String,
    rest: Option<&'a str>,
}

/// Reads `subsys[:target] [rest]`, as `MinIO`'s `GetSubSys`.
fn line(text: &str) -> Result<Line<'_>, ConfigError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(invalid("Name a sub-system."));
    }
    let (head, rest) = match text.split_once(char::is_whitespace) {
        Some((head, rest)) => (head, Some(rest.trim()).filter(|r| !r.is_empty())),
        None => (text, None),
    };
    let (name, target) = match head.split_once(':') {
        Some((name, target)) => (name, Some(target)),
        None => (head, None),
    };
    let subsystem = known(name)?;
    let target = match target {
        None => DEFAULT_TARGET.to_owned(),
        Some(_) if !subsystem.multiple_targets => {
            return Err(invalid(format!("{name} has one target: name it without :")));
        }
        Some(target) => {
            if target.is_empty()
                || !target
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(invalid(format!(
                    "A target's name is letters, digits and _, not `{target}`."
                )));
            }
            target.to_owned()
        }
    };
    Ok(Line {
        subsystem,
        target,
        rest,
    })
}

/// Splits `k1=v1 k2="v 2"` at the keys the sub-system has, as `MinIO`'s `kvFields`: a
/// value runs to the next key, so it may hold spaces and `=`.
fn fields(subsystem: &Subsystem, text: &str) -> Result<Kvs, ConfigError> {
    let mut starts: Vec<(usize, &str)> = subsystem
        .names()
        .chain([COMMENT])
        .filter_map(|name| {
            let wanted = format!("{name}=");
            text.match_indices(&wanted)
                .map(|(at, _)| at)
                .find(|&at| at == 0 || text[..at].ends_with(char::is_whitespace))
                .map(|at| (at, name))
        })
        .collect();
    starts.sort_unstable();
    let first = starts.first().map_or(text.len(), |(at, _)| *at);
    if !text[..first].trim().is_empty() {
        let unknown = text[..first].split('=').next().unwrap_or_default().trim();
        return Err(invalid(format!(
            "{} has no key {unknown}: its keys are {}",
            subsystem.name,
            subsystem.names().collect::<Vec<_>>().join(", ")
        )));
    }
    let mut kvs = Kvs::new();
    for (i, (at, name)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(text.len(), |(next, _)| *next);
        let value = &text[at + name.len() + 1..end];
        set(&mut kvs, name, sanitize(value));
    }
    Ok(kvs)
}

/// The server's configuration: each sub-system's targets that were set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigKv {
    subsystems: BTreeMap<&'static str, BTreeMap<String, Kvs>>,
}

/// One target's configuration, as `get` and `export` write it.
struct Written<'a> {
    subsystem: &'static Subsystem,
    target: &'a str,
    kvs: Kvs,
}

impl ConfigKv {
    /// A configuration from its text: each line a change, as `set` takes them. Blank lines
    /// and lines starting with `#` are skipped.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        config.set(text)?;
        Ok(config)
    }

    /// Whether nothing was set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subsystems.is_empty()
    }

    /// Sets the values each line of `text` names, as `MinIO`'s `set-config-kv`: a line's
    /// target starts from its defaults, a target with an `enable` key is turned on unless
    /// the line says otherwise, and a target that's on needs every key it can't do without.
    /// Nothing changes unless every line can.
    pub fn set(&mut self, text: &str) -> Result<(), ConfigError> {
        let mut changed = self.clone();
        changed.set_lines(text)?;
        *self = changed;
        Ok(())
    }

    fn set_lines(&mut self, text: &str) -> Result<(), ConfigError> {
        for text in text.lines() {
            let text = text.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let line = line(text)?;
            let subsystem = line.subsystem;
            let Some(rest) = line.rest else {
                return Err(invalid(format!(
                    "Give {} a key to set: key=value.",
                    subsystem.name
                )));
            };
            let given = fields(subsystem, rest)?;
            let mut kvs = self
                .subsystems
                .get(subsystem.name)
                .and_then(|targets| targets.get(&line.target))
                .cloned()
                .unwrap_or_else(|| subsystem.defaults());
            for (key, value) in subsystem.defaults() {
                if get(&kvs, &key).is_none() {
                    kvs.push((key, value));
                }
            }
            if subsystem.enable && get(&given, ENABLE).is_none() {
                set(&mut kvs, ENABLE, "on".to_owned());
            }
            for (key, value) in given.iter().filter(|(k, _)| k != COMMENT) {
                let kind = if key == ENABLE {
                    "on|off"
                } else {
                    subsystem.key(key).map_or("string", |k| k.kind)
                };
                if kind == "on|off" && !value.is_empty() && switch(value).is_none() {
                    return Err(invalid(format!(
                        "{}'s {key} is on or off, not `{value}`.",
                        subsystem.name
                    )));
                }
                set(&mut kvs, key, value.clone());
            }
            if let Some(comment) = get(&given, COMMENT) {
                set(&mut kvs, COMMENT, comment.to_owned());
            }
            let on = !subsystem.enable || get(&kvs, ENABLE).and_then(switch) == Some(true);
            if on
                && let Some(missing) = subsystem
                    .keys
                    .iter()
                    .find(|k| !k.optional && get(&kvs, k.name).is_none_or(str::is_empty))
            {
                return Err(invalid(format!(
                    "{} needs {} while it's on.",
                    subsystem.name, missing.name
                )));
            }
            self.subsystems
                .entry(subsystem.name)
                .or_default()
                .insert(line.target, kvs);
        }
        Ok(())
    }

    /// Resets what each line of `text` names, as `MinIO`'s `del-config-kv`: a target
    /// (`identity_openid:keycloak`), or some of its keys (`identity_ldap
    /// lookup_bind_dn`), which get their defaults back. Nothing changes unless every
    /// line can.
    pub fn delete(&mut self, text: &str) -> Result<(), ConfigError> {
        let mut changed = self.clone();
        changed.delete_lines(text)?;
        *self = changed;
        Ok(())
    }

    fn delete_lines(&mut self, text: &str) -> Result<(), ConfigError> {
        for text in text.lines() {
            let text = text.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let line = line(text)?;
            let subsystem = line.subsystem;
            let Some(kvs) = self
                .subsystems
                .get_mut(subsystem.name)
                .and_then(|targets| targets.get_mut(&line.target))
            else {
                if line.target == DEFAULT_TARGET {
                    // Never set: it has its defaults already.
                    continue;
                }
                return Err(ConfigError::NotFound(format!(
                    "{}:{} isn't set.",
                    subsystem.name, line.target
                )));
            };
            match line.rest {
                None => {
                    if let Some(targets) = self.subsystems.get_mut(subsystem.name) {
                        targets.remove(&line.target);
                    }
                }
                Some(keys) => {
                    for key in keys.split_whitespace() {
                        if get(kvs, key).is_none() {
                            return Err(ConfigError::NotFound(format!(
                                "{} has no key {key} set.",
                                subsystem.name
                            )));
                        }
                        match subsystem.default_of(key) {
                            Some(default) => set(kvs, key, default.to_owned()),
                            None => kvs.retain(|(k, _)| k != key),
                        }
                    }
                }
            }
            self.subsystems.retain(|_, targets| !targets.is_empty());
        }
        Ok(())
    }

    /// A sub-system's targets: the default one and those set, in order.
    fn targets(&self, subsystem: &'static Subsystem) -> Vec<Written<'_>> {
        let set = self.subsystems.get(subsystem.name);
        let mut written = vec![Written {
            subsystem,
            target: DEFAULT_TARGET,
            kvs: set
                .and_then(|targets| targets.get(DEFAULT_TARGET))
                .cloned()
                .unwrap_or_else(|| subsystem.defaults()),
        }];
        if subsystem.multiple_targets {
            written.extend(
                set.into_iter()
                    .flatten()
                    .filter(|(target, _)| *target != DEFAULT_TARGET)
                    .map(|(target, kvs)| Written {
                        subsystem,
                        target,
                        kvs: kvs.clone(),
                    }),
            );
        }
        written
    }

    /// What `key` names, as `MinIO`'s `get-config-kv` writes it: `subsys` for all its
    /// targets, `subsys:` for the default one, `subsys:target` for one. Secrets are left
    /// out; the variables `env` has for these keys are listed first as comments.
    pub fn get(
        &self,
        key: &str,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<String, ConfigError> {
        let (name, target) = match key.split_once(':') {
            Some((name, "")) => (name, Some(DEFAULT_TARGET)),
            Some((name, target)) => (name, Some(target)),
            None => (key, None),
        };
        let subsystem = known(name)?;
        let mut targets = self.targets(subsystem);
        if let Some(target) = target {
            targets.retain(|w| w.target == target);
            if targets.is_empty() {
                return Err(invalid(format!("{name} has no target {target}.")));
            }
        }
        let mut text = String::new();
        for written in &targets {
            written.write(&mut text, true, env, false);
        }
        Ok(text)
    }

    /// The whole configuration, secrets included, as `MinIO`'s `GET config` writes it for
    /// `mc admin config export`: targets that are off as comments.
    #[must_use]
    pub fn export(&self, env: &dyn Fn(&str) -> Option<String>) -> String {
        let mut text = String::new();
        for subsystem in SUBSYSTEMS {
            for written in self.targets(subsystem) {
                let off = !subsystem.is_on(&written.kvs);
                written.write(&mut text, false, env, off);
            }
        }
        text
    }

    /// The configuration as kept on disk: every target set, each line one `set` takes.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        for subsystem in SUBSYSTEMS {
            for (target, kvs) in self.subsystems.get(subsystem.name).into_iter().flatten() {
                Written {
                    subsystem,
                    target,
                    kvs: kvs.clone(),
                }
                .write(&mut text, false, &|_| None, false);
            }
        }
        text
    }

    /// The `MinIO` variables the configuration stands for, by name: each value that isn't
    /// empty and isn't its key's default. `teifs serve` reads them after the real ones.
    #[must_use]
    pub fn variables(&self) -> BTreeMap<String, String> {
        let mut variables = BTreeMap::new();
        for (name, targets) in &self.subsystems {
            let Some(subsystem) = subsystem(name) else {
                continue;
            };
            for (target, kvs) in targets {
                for (key, value) in kvs {
                    if key == COMMENT
                        || value.is_empty()
                        || subsystem.default_of(key) == Some(value.as_str())
                    {
                        continue;
                    }
                    variables.insert(variable(name, target, key), value.clone());
                }
            }
        }
        variables
    }

    /// The targets set for the sub-system `name`, as they're spelled: [`DEFAULT_TARGET`]
    /// for its first.
    #[must_use]
    pub fn target_names(&self, name: &str) -> Vec<String> {
        self.subsystems
            .get(name)
            .into_iter()
            .flat_map(BTreeMap::keys)
            .cloned()
            .collect()
    }
}

impl Written<'_> {
    /// Writes the target as `MinIO`'s `SubsysInfo.WriteTo` does: the variables set for it
    /// as comments, then `subsys[:target] k=v … ` (an `on` enable left out).
    fn write(
        &self,
        text: &mut String,
        redact: bool,
        env: &dyn Fn(&str) -> Option<String>,
        off: bool,
    ) {
        let subsystem = self.subsystem;
        let secret = |key: &str| subsystem.key(key).is_some_and(|k| k.secret);
        for key in subsystem.names().chain([COMMENT]) {
            let name = variable(subsystem.name, self.target, key);
            if let Some(value) = env(&name)
                && !(redact && secret(key))
            {
                let _ = writeln!(text, "# {name}={value}");
            }
        }
        if off {
            text.push_str("# ");
        }
        text.push_str(subsystem.name);
        if self.target != DEFAULT_TARGET {
            text.push(':');
            text.push_str(self.target);
        }
        text.push(' ');
        for (key, value) in &self.kvs {
            let hidden = subsystem
                .key(key)
                .is_some_and(|k| k.hidden_if_empty && value.is_empty());
            let known = key == COMMENT || subsystem.default_of(key).is_some();
            if !known
                || hidden
                || (key == ENABLE && value == "on")
                || (redact && secret(key) && !value.is_empty())
            {
                continue;
            }
            text.push_str(&pair(key, value));
            text.push(' ');
        }
        text.push('\n');
    }
}

/// `MinIO`'s help for a sub-system or one of its keys (`help-config-kv`), as madmin's
/// `Help` reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Help {
    /// The sub-system; empty for the list of them.
    pub sub_sys: String,
    /// What it configures.
    pub description: String,
    /// Whether it has targets besides the default one.
    pub multiple_targets: bool,
    /// Its keys (or the sub-systems).
    pub keys_help: Vec<HelpKey>,
}

/// One key's help.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HelpKey {
    /// The key, its variable, or a sub-system.
    pub key: String,
    /// What it's for.
    pub description: String,
    /// Whether it may be empty while its target is on.
    pub optional: bool,
    /// What its value is.
    #[serde(rename = "type")]
    pub kind: String,
    /// For a sub-system, whether it has several targets.
    pub multiple_targets: bool,
}

/// The help for `subsystem` (all of them when empty) or one of its keys; with `env`,
/// keys are named by their variables.
pub fn help(subsystem: &str, key: &str, env: bool) -> Result<Help, ConfigError> {
    if subsystem.is_empty() {
        return Ok(Help {
            sub_sys: String::new(),
            description: String::new(),
            multiple_targets: false,
            keys_help: SUBSYSTEMS
                .iter()
                .map(|s| HelpKey {
                    key: s.name.to_owned(),
                    description: s.description.to_owned(),
                    optional: false,
                    kind: String::new(),
                    multiple_targets: s.multiple_targets,
                })
                .collect(),
        });
    }
    let name = subsystem.split(':').next().unwrap_or_default();
    let subsystem = known(name)?;
    let named = |key: &str| {
        if env {
            variable(name, DEFAULT_TARGET, key)
        } else {
            key.to_owned()
        }
    };
    let mut keys: Vec<HelpKey> = Vec::new();
    if subsystem.multiple_targets {
        keys.push(HelpKey {
            key: named(ENABLE),
            description: format!("turn this {name} target on or off"),
            optional: false,
            kind: "on|off".to_owned(),
            multiple_targets: false,
        });
    }
    let comment = Key::new(COMMENT, "sentence", "a note about these settings");
    let all = subsystem.keys.iter().chain([&comment]);
    for k in all.filter(|k| key.is_empty() || k.name == key) {
        keys.push(HelpKey {
            key: named(k.name),
            description: k.description.to_owned(),
            optional: k.optional,
            kind: k.kind.to_owned(),
            multiple_targets: false,
        });
    }
    if !key.is_empty() && keys.iter().all(|k| k.key != named(key)) {
        return Err(invalid(format!("{name} has no key {key}.")));
    }
    if !key.is_empty() {
        keys.retain(|k| k.key == named(key));
    }
    Ok(Help {
        sub_sys: name.to_owned(),
        description: subsystem.description.to_owned(),
        multiple_targets: subsystem.multiple_targets,
        keys_help: keys,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn values_run_to_the_next_key() {
        let mut config = ConfigKv::default();
        config
            .set(
                "identity_ldap server_addr=ldap.example.com:636 \
                 lookup_bind_dn=\"cn=admin, dc=example, dc=com\" \
                 user_dn_search_filter=(uid=%s) lookup_bind_password=s3cr3t pw",
            )
            .unwrap();
        let text = config.get("identity_ldap", &none).unwrap();
        assert_eq!(
            text,
            "identity_ldap server_addr=ldap.example.com:636 srv_record_name= \
             user_dn_search_base_dn= user_dn_search_filter=(uid=%s) user_dn_attributes= \
             group_search_filter= group_search_base_dn= tls_skip_verify=off \
             server_insecure=off server_starttls=off \
             lookup_bind_dn=\"cn=admin, dc=example, dc=com\" \n"
        );
        // The secret is kept, and stands for its variable.
        let variables = config.variables();
        assert_eq!(
            variables["MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD"],
            "s3cr3t pw"
        );
        assert_eq!(variables["MINIO_IDENTITY_LDAP_ENABLE"], "on");
        // Defaults aren't variables.
        assert!(!variables.contains_key("MINIO_IDENTITY_LDAP_TLS_SKIP_VERIFY"));
    }

    #[test]
    fn a_key_only_starts_after_a_space() {
        let config = ConfigKv::parse(
            "identity_plugin url=https://plugin.example.com/?x_url=1 role_policy=readonly",
        )
        .unwrap();
        assert_eq!(
            config.variables()["MINIO_IDENTITY_PLUGIN_URL"],
            "https://plugin.example.com/?x_url=1"
        );
    }

    #[test]
    fn targets_are_named_after_a_colon() {
        let mut config = ConfigKv::parse(
            "identity_openid config_url=https://a.example.com client_id=a\n\
             # a comment\n\n\
             identity_openid:keycloak config_url=https://k.example.com client_id=k \
             role_policy=readonly comment=\"our SSO\"",
        )
        .unwrap();
        let variables = config.variables();
        assert_eq!(
            variables["MINIO_IDENTITY_OPENID_CONFIG_URL_KEYCLOAK"],
            "https://k.example.com"
        );
        assert_eq!(
            variables["MINIO_IDENTITY_OPENID_CONFIG_URL"],
            "https://a.example.com"
        );
        assert!(!variables.contains_key("MINIO_IDENTITY_OPENID_CLAIM_NAME"));
        let keycloak = config.get("identity_openid:keycloak", &none).unwrap();
        assert!(keycloak.starts_with("identity_openid:keycloak display_name= "));
        assert!(keycloak.ends_with("comment=\"our SSO\" \n"), "{keycloak}");
        assert_eq!(
            config
                .get("identity_openid", &none)
                .unwrap()
                .lines()
                .count(),
            2
        );
        assert_eq!(
            config
                .get("identity_openid:", &none)
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert!(matches!(
            config.get("identity_openid:other", &none),
            Err(ConfigError::Invalid(_))
        ));

        config.delete("identity_openid:keycloak").unwrap();
        assert_eq!(
            config
                .get("identity_openid", &none)
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert!(matches!(
            config.delete("identity_openid:keycloak"),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn what_minio_refuses_is_refused() {
        let mut config = ConfigKv::default();
        for (text, says) in [
            ("api requests_max=10", "no sub-system api"),
            ("identity_ldap:x server_addr=a:1", "one target"),
            (
                "identity_openid:a-b config_url=x client_id=y",
                "letters, digits",
            ),
            ("identity_ldap", "a key to set"),
            ("identity_ldap nope=1 server_addr=a:1", "no key nope"),
            (
                "identity_ldap server_insecure=maybe server_addr=a:1",
                "on or off",
            ),
            ("identity_ldap lookup_bind_dn=x", "needs server_addr"),
            ("identity_plugin url=https://p", "needs role_policy"),
        ] {
            let err = config.set(text).unwrap_err();
            assert!(err.to_string().contains(says), "{text}: {err}");
        }
        assert!(config.is_empty(), "a refused change changes nothing");
        // Off, nothing is needed.
        config
            .set("identity_ldap enable=off lookup_bind_dn=x")
            .unwrap();
        assert_eq!(config.variables()["MINIO_IDENTITY_LDAP_ENABLE"], "off");
    }

    #[test]
    fn deleting_keys_gives_them_their_defaults() {
        let mut config =
            ConfigKv::parse("identity_ldap server_addr=a:636 server_insecure=on lookup_bind_dn=x")
                .unwrap();
        config
            .delete("identity_ldap server_insecure lookup_bind_dn")
            .unwrap();
        let variables = config.variables();
        assert!(!variables.contains_key("MINIO_IDENTITY_LDAP_SERVER_INSECURE"));
        assert!(!variables.contains_key("MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN"));
        assert!(matches!(
            config.delete("identity_ldap nope"),
            Err(ConfigError::NotFound(_))
        ));
        config.delete("identity_ldap").unwrap();
        assert!(config.is_empty());
        // A default target never set is already reset.
        config.delete("identity_plugin").unwrap();
    }

    #[test]
    fn exports_read_back_and_keep_what_is_off() {
        let config = ConfigKv::parse(
            "identity_ldap server_addr=a:636 lookup_bind_password=pw\n\
             identity_openid:k enable=off config_url=https://k client_id=k",
        )
        .unwrap();
        let export = config.export(&none);
        assert!(
            export.contains("identity_ldap server_addr=a:636 "),
            "{export}"
        );
        assert!(export.contains("lookup_bind_password=pw "), "{export}");
        assert!(
            export.contains("# identity_openid:k enable=off "),
            "{export}"
        );
        assert!(export.contains("# identity_plugin url= "), "{export}");
        // What's kept on disk keeps the target that's off.
        assert_eq!(ConfigKv::parse(&config.to_text()).unwrap(), config);
        // What `get` answers has no secrets.
        assert!(!config.get("identity_ldap", &none).unwrap().contains("pw"));
    }

    #[test]
    fn variables_set_are_listed_as_comments() {
        let env = |name: &str| {
            (name == "MINIO_IDENTITY_LDAP_SERVER_ADDR"
                || name == "MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD")
                .then(|| "from-env".to_owned())
        };
        let text = ConfigKv::default().get("identity_ldap", &env).unwrap();
        assert!(
            text.starts_with("# MINIO_IDENTITY_LDAP_SERVER_ADDR=from-env\nidentity_ldap enable= "),
            "{text}"
        );
        assert!(!text.contains("PASSWORD"), "{text}");
        assert!(
            ConfigKv::default()
                .export(&env)
                .contains("PASSWORD=from-env")
        );
    }

    #[test]
    fn help_names_keys_or_their_variables() {
        let all = help("", "", false).unwrap();
        assert_eq!(all.keys_help.len(), SUBSYSTEMS.len());
        let openid = help("identity_openid", "", false).unwrap();
        assert!(openid.multiple_targets);
        assert_eq!(openid.keys_help[0].key, ENABLE);
        assert_eq!(openid.keys_help.last().unwrap().key, COMMENT);
        let one = help("identity_ldap", "server_addr", true).unwrap();
        assert_eq!(one.keys_help.len(), 1);
        assert_eq!(one.keys_help[0].key, "MINIO_IDENTITY_LDAP_SERVER_ADDR");
        assert!(!one.keys_help[0].optional);
        let json = serde_json::to_value(&one).unwrap();
        assert_eq!(json["subSys"], "identity_ldap");
        assert_eq!(json["keysHelp"][0]["type"], "address");
        assert!(help("identity_ldap", "nope", false).is_err());
        assert!(help("api", "", false).is_err());
    }

    #[test]
    fn notification_targets_are_kept_by_name() {
        let config = ConfigKv::parse(
            "notify_webhook:Primary endpoint=https://hooks.example.com/in auth_token=t0k\n\
             notify_kafka brokers=a:9092,b:9092 topic=events\n\
             identity_tls skip_verify=on",
        )
        .unwrap();
        assert_eq!(config.target_names("notify_webhook"), ["Primary"]);
        assert_eq!(config.target_names("notify_kafka"), [DEFAULT_TARGET]);
        assert!(config.target_names("notify_redis").is_empty());
        let variables = config.variables();
        assert_eq!(
            variables["MINIO_NOTIFY_WEBHOOK_ENDPOINT_PRIMARY"],
            "https://hooks.example.com/in"
        );
        assert_eq!(variables["MINIO_NOTIFY_KAFKA_ENABLE"], "on");
        assert_eq!(variables["MINIO_IDENTITY_TLS_SKIP_VERIFY"], "on");
        // Its default isn't a variable.
        assert!(!variables.contains_key("MINIO_NOTIFY_KAFKA_SASL_MECHANISM"));
        let got = config.get("notify_webhook", &|_| None).unwrap();
        assert!(!got.contains("t0k"), "{got}");
        assert!(ConfigKv::parse("identity_tls:x skip_verify=on").is_err());
        assert_eq!(switch(" On "), Some(true));
        assert_eq!(switch("maybe"), None);
    }
}
