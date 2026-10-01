//! `MinIO`'s notification and audit targets (`mc admin config set ALIAS
//! notify_webhook:NAME endpoint=…`, `MINIO_NOTIFY_KAFKA_ENABLE_NAME=on`, …) as the targets
//! `teifs serve` starts with its flags' (`--notify-webhook`, `--audit-webhook`, …).
//!
//! Each target's values are `MinIO`'s: its variable when it's set, else what the drive's
//! configuration keeps, else the key's default. A target counts when it's on; one that
//! only the environment has is found by its `ENABLE` variable, as `MinIO` finds them. The
//! values become the spec its flag takes, so it's checked as one, and its secrets are read
//! where the flag's are (`TEIFS_NOTIFY_KIND_WHAT_ID`), the environment's first.

use std::{collections::BTreeMap, fmt::Write as _};

use teifs_server::{TargetConfig, Webhook};
use teifs_types::config_kv::{
    ConfigKv, DEFAULT_TARGET, ENABLE, Subsystem, subsystem, switch, variable,
};
use zeroize::Zeroizing;

use crate::units::parse_duration;

/// The targets `MinIO`'s settings name.
#[derive(Default)]
pub(crate) struct MinioTargets {
    /// Notification targets, without their secrets.
    pub(crate) notify: Vec<TargetConfig>,
    /// Their secrets, by the variable [`crate::notify_targets`] reads each from.
    pub(crate) secrets: BTreeMap<String, Zeroizing<String>>,
    /// Audit log webhooks, with their tokens.
    pub(crate) audit: Vec<Webhook>,
}

impl MinioTargets {
    /// A target's secret: the environment's variable, else the one its settings give.
    pub(crate) fn secret(&self, env: Option<String>, name: &str) -> Option<String> {
        env.filter(|v| !v.trim().is_empty())
            .or_else(|| self.secrets.get(name).map(|s| s.to_string()))
    }
}

/// A target's spec and its secrets, by what they are (`TOKEN`, `PASSWORD`).
type Translated = (String, Vec<(&'static str, String)>);

type Translate = fn(&Values<'_>) -> Result<Translated, String>;

/// A flag's parser.
type Parse = fn(&str) -> Result<TargetConfig, String>;

const NOTIFY: &[(&str, Translate, Parse)] = &[
    ("notify_webhook", webhook, crate::parse_notify_webhook),
    (
        "notify_elasticsearch",
        elasticsearch,
        crate::parse_notify_elasticsearch,
    ),
    ("notify_redis", redis, crate::parse_notify_redis),
    ("notify_nsq", nsq, crate::parse_notify_nsq),
    ("notify_nats", nats, crate::parse_notify_nats),
    ("notify_mqtt", mqtt, crate::parse_notify_mqtt),
    ("notify_kafka", kafka, crate::parse_notify_kafka),
    ("notify_amqp", amqp, crate::parse_notify_amqp),
    ("notify_postgres", postgres, crate::parse_notify_postgresql),
    ("notify_mysql", mysql, crate::parse_notify_mysql),
];

/// The targets `config` (the drive's configuration) and `env` (`MinIO`'s variables) name.
pub(crate) fn minio_targets(
    config: &ConfigKv,
    env: &BTreeMap<String, String>,
) -> Result<MinioTargets, String> {
    let stored = config.variables();
    let mut targets = MinioTargets::default();
    for &(name, translate, parse) in NOTIFY {
        for values in on(config, &stored, env, name)? {
            let (spec, secrets) = translate(&values).map_err(|e| values.failed(&e))?;
            let target = parse(&spec).map_err(|e| values.failed(&e))?;
            let arn = target.arn();
            for (what, value) in secrets {
                targets
                    .secrets
                    .insert(crate::secret_variable(&arn, what), Zeroizing::new(value));
            }
            targets.notify.push(target);
        }
    }
    for values in on(config, &stored, env, "audit_webhook")? {
        let mut spec = Spec::url(&values.get("endpoint"));
        spec.option("client_cert", &values.get("client_cert"))?;
        spec.option("client_key", &values.get("client_key"))?;
        let mut hook = crate::parse_audit_webhook(&spec.0).map_err(|e| values.failed(&e))?;
        hook.token = Some(values.get("auth_token"))
            .filter(|t| !t.trim().is_empty())
            .map(Zeroizing::new);
        targets.audit.push(hook);
    }
    Ok(targets)
}

/// The sub-system `name`'s targets that are on: the ones the drive keeps, then those
/// only the environment turns on (`MINIO_NOTIFY_WEBHOOK_ENABLE_NAME`).
fn on<'a>(
    config: &ConfigKv,
    stored: &'a BTreeMap<String, String>,
    env: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<Vec<Values<'a>>, String> {
    let Some(subsystem) = subsystem(name) else {
        return Ok(Vec::new());
    };
    let mut ids = config.target_names(name);
    let enable = variable(name, DEFAULT_TARGET, ENABLE);
    for variable in env.keys() {
        let id = if *variable == enable {
            DEFAULT_TARGET
        } else if let Some(id) = variable
            .strip_prefix(enable.as_str())
            .and_then(|rest| rest.strip_prefix('_'))
            .filter(|id| !id.is_empty())
        {
            id
        } else {
            continue;
        };
        if !ids.iter().any(|known| known.eq_ignore_ascii_case(id)) {
            ids.push(id.to_owned());
        }
    }
    let mut targets = Vec::new();
    for id in ids {
        let values = Values {
            subsystem,
            id,
            stored,
            env,
        };
        if values.on(ENABLE).map_err(|e| values.failed(&e))? {
            targets.push(values);
        }
    }
    Ok(targets)
}

/// One target's values.
struct Values<'a> {
    subsystem: &'static Subsystem,
    id: String,
    stored: &'a BTreeMap<String, String>,
    env: &'a BTreeMap<String, String>,
}

impl Values<'_> {
    /// The key's value: its variable's (with the target as it's spelled, as `MinIO` names
    /// it, or in capitals), else the stored one, else its default.
    fn get(&self, key: &str) -> String {
        let name = variable(self.subsystem.name, &self.id, key);
        let spelled = if self.id == DEFAULT_TARGET {
            name.clone()
        } else {
            format!(
                "{}_{}",
                variable(self.subsystem.name, DEFAULT_TARGET, key),
                self.id
            )
        };
        let set = |value: &&String| !value.trim().is_empty();
        self.env
            .get(&spelled)
            .filter(set)
            .or_else(|| self.env.get(&name).filter(set))
            .or_else(|| self.stored.get(&name).filter(set))
            .cloned()
            .unwrap_or_else(|| {
                self.subsystem
                    .keys
                    .iter()
                    .find(|k| k.name == key)
                    .map(|k| k.default.to_owned())
                    .unwrap_or_default()
            })
    }

    /// An on or off key.
    fn on(&self, key: &str) -> Result<bool, String> {
        let value = self.get(key);
        if value.trim().is_empty() {
            return Ok(false);
        }
        switch(&value).ok_or_else(|| format!("{key} is on or off, not `{value}`"))
    }

    /// A key that must stay off: TeiFS always checks a server's certificate.
    fn verified(&self, key: &str) -> Result<(), String> {
        if self.on(key)? {
            return Err(format!(
                "TeiFS always checks the server's certificate: turn {key} off, and give the \
                 CA that signed it"
            ));
        }
        Ok(())
    }

    /// A key that must be set.
    fn required(&self, key: &str) -> Result<String, String> {
        let value = self.get(key);
        if value.trim().is_empty() {
            return Err(format!("set its {key}"));
        }
        Ok(value.trim().to_owned())
    }

    fn failed(&self, err: &str) -> String {
        if self.id == DEFAULT_TARGET {
            format!("{} in MinIO's settings: {err}", self.subsystem.name)
        } else {
            format!(
                "{}:{} in MinIO's settings: {err}",
                self.subsystem.name, self.id
            )
        }
    }
}

/// A flag's spec: `ID=ADDRESS` and `,NAME=VALUE` options.
struct Spec(String);

impl Spec {
    fn new(values: &Values<'_>, address: &str) -> Result<Self, String> {
        if address.contains(',') {
            return Err(format!("`{address}` can't hold a comma"));
        }
        Ok(Self(format!("{}={}", values.id, address.trim())))
    }

    /// A URL, which may hold commas: the options are read from the end.
    fn url(url: &str) -> Self {
        Self(url.trim().to_owned())
    }

    /// The option `name`, when `value` isn't empty.
    fn option(&mut self, name: &str, value: &str) -> Result<(), String> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(());
        }
        if value.contains(',') {
            return Err(format!("`{value}` can't hold a comma"));
        }
        self.0.push(',');
        self.0.push_str(name);
        self.0.push('=');
        self.0.push_str(value);
        Ok(())
    }

    fn flag(&mut self, name: &str, on: bool) {
        let _ = write!(self.0, ",{name}={on}");
    }
}

/// The secrets that are set.
fn secrets(given: &[(&'static str, String)]) -> Vec<(&'static str, String)> {
    given
        .iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .cloned()
        .collect()
}

fn webhook(v: &Values<'_>) -> Result<Translated, String> {
    let mut spec = Spec::url(&format!("{}={}", v.id, v.required("endpoint")?));
    spec.option("client_cert", &v.get("client_cert"))?;
    spec.option("client_key", &v.get("client_key"))?;
    Ok((spec.0, secrets(&[("TOKEN", v.get("auth_token"))])))
}

fn elasticsearch(v: &Values<'_>) -> Result<Translated, String> {
    let mut spec = Spec::new(v, &v.required("url")?)?;
    spec.option("index", &v.required("index")?)?;
    spec.option("format", &v.get("format"))?;
    spec.option("user", &v.get("username"))?;
    Ok((spec.0, secrets(&[("PASSWORD", v.get("password"))])))
}

fn redis(v: &Values<'_>) -> Result<Translated, String> {
    let mut spec = Spec::new(v, &v.required("address")?)?;
    spec.option("key", &v.required("key")?)?;
    spec.option("format", &v.get("format"))?;
    spec.option("user", &v.get("user"))?;
    Ok((spec.0, secrets(&[("PASSWORD", v.get("password"))])))
}

fn nsq(v: &Values<'_>) -> Result<Translated, String> {
    v.verified("tls_skip_verify")?;
    let mut spec = Spec::new(v, &v.required("nsqd_address")?)?;
    spec.option("topic", &v.required("topic")?)?;
    if v.on("tls")? {
        spec.flag("tls", true);
    }
    Ok((spec.0, Vec::new()))
}

fn nats(v: &Values<'_>) -> Result<Translated, String> {
    v.verified("tls_skip_verify")?;
    if v.on("streaming")? {
        return Err(
            "NATS Streaming was retired: turn streaming off, and jetstream on for a stream"
                .to_owned(),
        );
    }
    let mut spec = Spec::new(v, &v.required("address")?)?;
    spec.option("subject", &v.required("subject")?)?;
    spec.option("user", &v.get("username"))?;
    if v.on("tls")? {
        spec.flag("tls", true);
    }
    spec.option("ca", &v.get("cert_authority"))?;
    spec.option("client_cert", &v.get("client_cert"))?;
    spec.option("client_key", &v.get("client_key"))?;
    if v.on("jetstream")? {
        spec.flag("jetstream", true);
    }
    spec.option("nkey", &v.get("nkey_seed"))?;
    if v.on("tls_handshake_first")? {
        spec.flag("tls_first", true);
    }
    Ok((
        spec.0,
        secrets(&[("PASSWORD", v.get("password")), ("TOKEN", v.get("token"))]),
    ))
}

fn mqtt(v: &Values<'_>) -> Result<Translated, String> {
    let mut spec = Spec::new(v, &v.required("broker")?)?;
    spec.option("topic", &v.required("topic")?)?;
    spec.option("qos", &v.get("qos"))?;
    spec.option("user", &v.get("username"))?;
    let keep_alive = v.get("keep_alive_interval");
    if !matches!(keep_alive.trim(), "" | "0" | "0s") {
        let seconds = parse_duration(&keep_alive)
            .map_err(|e| format!("keep_alive_interval: {e}"))?
            .as_secs();
        spec.option("keepalive", &seconds.to_string())?;
    }
    Ok((spec.0, secrets(&[("PASSWORD", v.get("password"))])))
}

fn kafka(v: &Values<'_>) -> Result<Translated, String> {
    v.verified("tls_skip_verify")?;
    let brokers = v
        .required("brokers")?
        .split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .collect::<Vec<_>>()
        .join(";");
    let mut spec = Spec::new(v, &brokers)?;
    spec.option("topic", &v.required("topic")?)?;
    let mut secret = Vec::new();
    if v.on("sasl")? {
        let mechanism = match v.get("sasl_mechanism").trim().to_ascii_lowercase().as_str() {
            "" | "plain" => "plain",
            "sha256" | "scram-sha-256" => "scram-sha-256",
            "sha512" | "scram-sha-512" => "scram-sha-512",
            other => {
                return Err(format!(
                    "sasl_mechanism is plain, sha256 or sha512, not `{other}`"
                ));
            }
        };
        spec.option("sasl", mechanism)?;
        spec.option("user", &v.required("sasl_username")?)?;
        secret = secrets(&[("PASSWORD", v.get("sasl_password"))]);
    }
    if v.on("tls")? {
        spec.flag("tls", true);
    }
    spec.option("client_cert", &v.get("client_tls_cert"))?;
    spec.option("client_key", &v.get("client_tls_key"))?;
    spec.option("compression", &v.get("compression_codec"))?;
    Ok((spec.0, secret))
}

fn amqp(v: &Values<'_>) -> Result<Translated, String> {
    let (url, user, password) = without_user(&v.required("url")?)?;
    let mut spec = Spec::new(v, &url)?;
    let exchange = v.get("exchange");
    spec.option("exchange", &exchange)?;
    spec.option("routing_key", &v.get("routing_key"))?;
    // The default exchange is the server's; others are declared, as MinIO does.
    if !exchange.trim().is_empty() {
        spec.option("exchange_type", &v.get("exchange_type"))?;
        spec.flag("durable", v.on("durable")?);
        spec.flag("auto_delete", v.on("auto_deleted")?);
        spec.flag("internal", v.on("internal")?);
    }
    spec.flag("mandatory", v.on("mandatory")?);
    spec.flag("persistent", v.get("delivery_mode").trim() == "2");
    spec.option("user", user.as_deref().unwrap_or_default())?;
    Ok((
        spec.0,
        secrets(&[(
            "PASSWORD",
            password.map(|p| p.to_string()).unwrap_or_default(),
        )]),
    ))
}

/// A URL, and the user and password it named.
type Login = (String, Option<String>, Option<Zeroizing<String>>);

/// A URL without its `USER:PASSWORD@`, and them.
fn without_user(url: &str) -> Result<Login, String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Ok((url.to_owned(), None, None));
    };
    let end = rest.find('/').unwrap_or(rest.len());
    let Some((info, host)) = rest[..end].rsplit_once('@') else {
        return Ok((url.to_owned(), None, None));
    };
    let (user, password) = match info.split_once(':') {
        Some((user, password)) => (user, Some(password)),
        None => (info, None),
    };
    let user = decode(user)?;
    let password = password.map(decode).transpose()?.map(Zeroizing::new);
    Ok((
        format!("{scheme}://{host}{}", &rest[end..]),
        Some(user).filter(|u| !u.is_empty()),
        password,
    ))
}

fn decode(text: &str) -> Result<String, String> {
    percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| "its URL's user or password isn't UTF-8".to_owned())
}

/// `HOST:PORT`, with an IPv6 host in brackets.
fn address(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A database target's spec from what its connection names.
#[allow(
    clippy::too_many_arguments,
    reason = "each is one of the connection's parts"
)]
fn database_spec(
    v: &Values<'_>,
    address: &str,
    database: &str,
    user: &str,
    tls: bool,
    ca: Option<&str>,
    client: (Option<&str>, Option<&str>),
) -> Result<String, String> {
    if user.is_empty() {
        return Err("its connection names no user".to_owned());
    }
    if database.is_empty() {
        return Err("its connection names no database".to_owned());
    }
    let mut spec = Spec::new(v, address)?;
    spec.option("database", database)?;
    spec.option("table", &v.required("table")?)?;
    spec.option("user", user)?;
    spec.option("format", &v.get("format"))?;
    if tls {
        spec.flag("tls", true);
        spec.option("ca", ca.unwrap_or_default())?;
        spec.option("client_cert", client.0.unwrap_or_default())?;
        spec.option("client_key", client.1.unwrap_or_default())?;
    }
    Ok(spec.0)
}

fn postgres(v: &Values<'_>) -> Result<Translated, String> {
    let parts = libpq(&v.required("connection_string")?)?;
    let part = |name: &str| {
        parts
            .get(name)
            .map(String::as_str)
            .filter(|p| !p.is_empty())
    };
    let host = part("host").unwrap_or("localhost");
    if host.starts_with('/') || host.contains(',') {
        return Err("TeiFS connects to one host over TCP: give its host=NAME".to_owned());
    }
    let user = part("user").unwrap_or_default();
    let tls = match part("sslmode").unwrap_or("prefer") {
        "disable" | "allow" | "prefer" => false,
        "require" | "verify-ca" | "verify-full" => true,
        other => return Err(format!("sslmode `{other}` isn't one PostgreSQL has")),
    };
    let spec = database_spec(
        v,
        &address(host, part("port").unwrap_or("5432")),
        part("dbname").unwrap_or(user),
        user,
        tls,
        part("sslrootcert"),
        (part("sslcert"), part("sslkey")),
    )?;
    let password = parts.get("password").cloned().unwrap_or_default();
    Ok((spec, secrets(&[("PASSWORD", password)])))
}

/// A libpq connection string's parts: `host=… port=… user=… password='a b' dbname=…`, or
/// a `postgres://USER:PASSWORD@HOST:PORT/DATABASE?sslmode=…` URL.
fn libpq(text: &str) -> Result<BTreeMap<String, String>, String> {
    let text = text.trim();
    let mut parts = BTreeMap::new();
    if let Some(rest) = text
        .strip_prefix("postgres://")
        .or_else(|| text.strip_prefix("postgresql://"))
    {
        let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (authority, database) = rest.split_once('/').unwrap_or((rest, ""));
        let (info, host) = authority.rsplit_once('@').unwrap_or(("", authority));
        if !info.is_empty() {
            let (user, password) = info.split_once(':').unwrap_or((info, ""));
            parts.insert("user".to_owned(), decode(user)?);
            parts.insert("password".to_owned(), decode(password)?);
        }
        let (host, port) = match host.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => (host, port),
            _ => (host, ""),
        };
        parts.insert(
            "host".to_owned(),
            decode(host.trim_start_matches('[').trim_end_matches(']'))?,
        );
        parts.insert("port".to_owned(), port.to_owned());
        parts.insert("dbname".to_owned(), decode(database)?);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            parts.insert(decode(key)?, decode(value)?);
        }
        return Ok(parts);
    }
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.peek().is_none() {
            return Ok(parts);
        }
        let mut key = String::new();
        while let Some(c) = chars.next_if(|&c| c != '=' && !c.is_whitespace()) {
            key.push(c);
        }
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        if chars.next() != Some('=') {
            return Err(format!(
                "its connection_string's `{key}` has no value: give KEY=VALUE"
            ));
        }
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let quoted = chars.next_if_eq(&'\'').is_some();
        let mut value = String::new();
        loop {
            match chars.next() {
                None if quoted => {
                    return Err("its connection_string has a quote that isn't closed".to_owned());
                }
                None => break,
                Some('\'') if quoted => break,
                Some(c) if c.is_whitespace() && !quoted => break,
                Some('\\') => value.extend(chars.next()),
                Some(c) => value.push(c),
            }
        }
        parts.insert(key, value);
    }
}

fn mysql(v: &Values<'_>) -> Result<Translated, String> {
    let dsn = v.required("dsn_string")?;
    let form = "give it as USER:PASSWORD@tcp(HOST:PORT)/DATABASE";
    let (left, right) = dsn
        .rsplit_once('/')
        .ok_or_else(|| format!("its dsn_string names no database: {form}"))?;
    let (database, params) = right.split_once('?').unwrap_or((right, ""));
    let (info, network) = left.rsplit_once('@').unwrap_or(("", left));
    let (user, password) = info.split_once(':').unwrap_or((info, ""));
    let address = match network {
        "" | "tcp" | "tcp()" => "127.0.0.1:3306".to_owned(),
        network => {
            let host = network
                .strip_prefix("tcp(")
                .and_then(|n| n.strip_suffix(')'))
                .ok_or_else(|| format!("TeiFS connects over TCP: {form}"))?;
            if host.starts_with('[') && host.ends_with(']') || !host.contains(':') {
                format!("{host}:3306")
            } else {
                host.to_owned()
            }
        }
    };
    let mut tls = false;
    for pair in params.split('&').filter(|p| !p.is_empty()) {
        if let Some(("tls", value)) = pair.split_once('=') {
            tls = match value {
                "true" => true,
                "false" | "preferred" => false,
                "skip-verify" => {
                    return Err(
                        "TeiFS always checks the server's certificate: use tls=true".to_owned()
                    );
                }
                other => return Err(format!("tls is true or false, not `{other}`")),
            };
        }
    }
    let spec = database_spec(v, &address, database, user, tls, None, (None, None))?;
    Ok((spec, secrets(&[("PASSWORD", password.to_owned())])))
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

    fn targets(stored: &str, env: &[(&str, &str)]) -> Result<MinioTargets, String> {
        minio_targets(&ConfigKv::parse(stored).unwrap(), &map(env))
    }

    fn arns(targets: &MinioTargets) -> Vec<String> {
        targets.notify.iter().map(|t| t.arn().to_string()).collect()
    }

    #[test]
    fn targets_on_are_found_where_minio_finds_them() {
        let found = targets(
            "notify_webhook:primary endpoint=https://hooks.example.com/in auth_token=t0k\n\
             notify_webhook:off endpoint=https://off.example.com enable=off\n\
             notify_redis address=localhost:6379 key=events enable=off",
            &[
                // The environment's value over the stored one, its target's case aside.
                (
                    "MINIO_NOTIFY_WEBHOOK_ENDPOINT_PRIMARY",
                    "https://env.example.com/in",
                ),
                // Turned on by the environment alone.
                ("MINIO_NOTIFY_REDIS_ENABLE", "on"),
                ("MINIO_NOTIFY_KAFKA_ENABLE_Stream", "on"),
                ("MINIO_NOTIFY_KAFKA_BROKERS_STREAM", "a:9092, b:9092"),
                ("MINIO_NOTIFY_KAFKA_TOPIC_STREAM", "events"),
                // Off, or not a target.
                ("MINIO_NOTIFY_NSQ_ENABLE_X", "off"),
                ("MINIO_NOTIFY_NSQ_ENABLEX", "on"),
            ],
        )
        .unwrap();
        assert_eq!(
            arns(&found),
            [
                "arn:teifs:sqs::primary:webhook",
                "arn:teifs:sqs::_:redis",
                "arn:teifs:sqs::Stream:kafka"
            ]
        );
        assert_eq!(
            found.notify[0].shown(),
            crate::parse_notify_webhook("x=https://env.example.com/in")
                .unwrap()
                .shown()
        );
        assert_eq!(
            found.secrets["TEIFS_NOTIFY_WEBHOOK_TOKEN_PRIMARY"].as_str(),
            "t0k"
        );
        assert_eq!(
            found
                .secret(None, "TEIFS_NOTIFY_WEBHOOK_TOKEN_PRIMARY")
                .as_deref(),
            Some("t0k")
        );
        assert_eq!(
            found
                .secret(Some("env".to_owned()), "TEIFS_NOTIFY_WEBHOOK_TOKEN_PRIMARY")
                .as_deref(),
            Some("env")
        );
        assert!(found.audit.is_empty());

        let wrong = targets("", &[("MINIO_NOTIFY_REDIS_ENABLE", "maybe")])
            .err()
            .unwrap();
        assert!(
            wrong.contains("notify_redis in MinIO's settings"),
            "{wrong}"
        );
        let missing = targets("", &[("MINIO_NOTIFY_NSQ_ENABLE_Q", "on")])
            .err()
            .unwrap();
        assert_eq!(
            missing,
            "notify_nsq:Q in MinIO's settings: set its nsqd_address"
        );
    }

    #[test]
    fn each_kind_becomes_its_flag_s_spec() {
        let v = |stored: &str| {
            let config = ConfigKv::parse(stored).unwrap();
            let name = stored.split([' ', ':']).next().unwrap();
            let id = config.target_names(name).remove(0);
            (config.variables(), subsystem(name).unwrap(), id)
        };
        let spec = |stored: &str, translate: Translate| {
            let (stored, subsystem, id) = v(stored);
            let env = BTreeMap::new();
            translate(&Values {
                subsystem,
                id,
                stored: &stored,
                env: &env,
            })
        };
        assert_eq!(
            spec(
                "notify_elasticsearch url=http://es:9200 index=ev username=u password=p",
                elasticsearch
            )
            .unwrap(),
            (
                "_=http://es:9200,index=ev,format=namespace,user=u".to_owned(),
                vec![("PASSWORD", "p".to_owned())]
            )
        );
        assert_eq!(
            spec(
                "notify_nats address=n:4222 subject=s token=t tls=on jetstream=on \
                 tls_handshake_first=on",
                nats
            )
            .unwrap()
            .0,
            "_=n:4222,subject=s,tls=true,jetstream=true,tls_first=true"
        );
        assert!(spec("notify_nats address=n:4222 subject=s streaming=on", nats).is_err());
        assert!(
            spec(
                "notify_nsq nsqd_address=n:4150 topic=t tls_skip_verify=on",
                nsq
            )
            .is_err()
        );
        assert_eq!(
            spec(
                "notify_mqtt broker=tcp://m:1883 topic=t username=u password=p \
                 keep_alive_interval=30s",
                mqtt
            )
            .unwrap()
            .0,
            "_=tcp://m:1883,topic=t,qos=0,user=u,keepalive=30"
        );
        assert_eq!(
            spec(
                "notify_kafka brokers=a:9092,b:9092 topic=t sasl=on sasl_username=u \
                 sasl_password=p sasl_mechanism=sha512 compression_codec=zstd",
                kafka
            )
            .unwrap(),
            (
                "_=a:9092;b:9092,topic=t,sasl=scram-sha-512,user=u,compression=zstd".to_owned(),
                vec![("PASSWORD", "p".to_owned())]
            )
        );
        // Without SASL its user and password aren't used.
        assert_eq!(
            spec("notify_kafka brokers=a:9092 topic=t sasl_password=p", kafka)
                .unwrap()
                .1,
            []
        );
        assert_eq!(
            spec(
                "notify_amqp url=amqp://us%40r:p%3Aw@rabbit:5672/v exchange=ev \
                 exchange_type=fanout durable=on delivery_mode=2",
                amqp
            )
            .unwrap(),
            (
                "_=amqp://rabbit:5672/v,exchange=ev,exchange_type=fanout,durable=true,\
                 auto_delete=false,internal=false,mandatory=false,persistent=true,user=us@r"
                    .to_owned(),
                vec![("PASSWORD", "p:w".to_owned())]
            )
        );
        assert_eq!(
            spec("notify_amqp url=amqp://rabbit", amqp).unwrap(),
            (
                "_=amqp://rabbit,mandatory=false,persistent=false".to_owned(),
                vec![]
            )
        );
        assert!(spec("notify_redis address=a,b:6379 key=k", redis).is_err());
    }

    #[test]
    fn databases_are_reached_as_their_connections_say() {
        let spec = |stored: &str, translate: Translate| {
            let config = ConfigKv::parse(stored).unwrap();
            let name = stored.split(' ').next().unwrap();
            let variables = config.variables();
            let env = BTreeMap::new();
            translate(&Values {
                subsystem: subsystem(name).unwrap(),
                id: DEFAULT_TARGET.to_owned(),
                stored: &variables,
                env: &env,
            })
        };
        assert_eq!(
            spec(
                "notify_postgres table=ev connection_string=\"host=db port=5433 user=u \
                 password='a b\\'c' dbname=d sslmode=verify-full sslrootcert=/ca.pem\"",
                postgres
            )
            .unwrap(),
            (
                "_=db:5433,database=d,table=ev,user=u,format=namespace,tls=true,ca=/ca.pem"
                    .to_owned(),
                vec![("PASSWORD", "a b'c".to_owned())]
            )
        );
        assert_eq!(
            spec(
                "notify_postgres table=ev connection_string=postgres://u:p%40@[::1]/d?sslmode=disable",
                postgres
            )
            .unwrap(),
            (
                "_=[::1]:5432,database=d,table=ev,user=u,format=namespace".to_owned(),
                vec![("PASSWORD", "p@".to_owned())]
            )
        );
        // The database is named after the user when it isn't named.
        assert_eq!(
            spec(
                "notify_postgres table=ev connection_string=user=u",
                postgres
            )
            .unwrap()
            .0,
            "_=localhost:5432,database=u,table=ev,user=u,format=namespace"
        );
        assert!(
            spec(
                "notify_postgres table=ev connection_string=host=/tmp user=u",
                postgres
            )
            .is_err()
        );
        assert!(
            spec(
                "notify_postgres table=ev connection_string=\"user='u\"",
                postgres
            )
            .is_err()
        );
        assert_eq!(
            spec(
                "notify_mysql table=ev dsn_string=u:p@ss@tcp(db:3307)/d?tls=true&charset=utf8",
                mysql
            )
            .unwrap(),
            (
                "_=db:3307,database=d,table=ev,user=u,format=namespace,tls=true".to_owned(),
                vec![("PASSWORD", "p@ss".to_owned())]
            )
        );
        assert_eq!(
            spec("notify_mysql table=ev dsn_string=u@/d", mysql).unwrap(),
            (
                "_=127.0.0.1:3306,database=d,table=ev,user=u,format=namespace".to_owned(),
                vec![]
            )
        );
        assert!(spec("notify_mysql table=ev dsn_string=u@unix(/s)/d", mysql).is_err());
        assert!(
            spec(
                "notify_mysql table=ev dsn_string=u@/d?tls=skip-verify",
                mysql
            )
            .is_err()
        );
    }

    #[test]
    fn audit_webhooks_carry_their_tokens() {
        let found = targets(
            "audit_webhook:siem endpoint=https://siem.example.com/in auth_token=\"Splunk t\"",
            &[],
        )
        .unwrap();
        assert_eq!(found.audit.len(), 1);
        assert_eq!(
            found.audit[0].token.as_deref().map(String::as_str),
            Some("Splunk t")
        );
        assert!(found.notify.is_empty());
    }
}
