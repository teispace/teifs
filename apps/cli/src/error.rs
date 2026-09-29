//! What went wrong, in words and as an exit code scripts can act on.

use std::fmt;

use aws_sdk_s3::{
    config::http::HttpResponse,
    error::{ProvideErrorMetadata, SdkError},
};

/// The kind of failure; `teifs` exits with its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Anything else.
    General = 1,
    /// The command line was wrong (clap also exits with 2).
    Usage = 2,
    /// The endpoint couldn't be reached, or stopped answering: retrying may help.
    Network = 3,
    /// The keys were refused, or don't allow this.
    Auth = 4,
    /// The bucket, object or alias isn't there.
    NotFound = 5,
    /// Something is in the way: the bucket exists, isn't empty, or changed meanwhile.
    Conflict = 6,
}

impl Kind {
    /// The exit code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Its name in `--json` output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Usage => "usage",
            Self::Network => "network",
            Self::Auth => "auth",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
        }
    }
}

/// A failure: what went wrong, and (when there's something to do about it) what to do.
#[derive(Debug)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
    pub hint: Option<String>,
    /// Already shown to the person as it happened; only the exit code is left.
    pub shown: bool,
}

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            shown: false,
        }
    }

    /// The same failure, marked as already shown.
    #[must_use]
    pub fn shown(mut self) -> Self {
        self.shown = true;
        self
    }

    /// The same failure, with what to do about it.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(Kind::General, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Kind::Usage, message)
    }

    /// An S3 request that failed, while doing `what` (`can't copy x`).
    pub fn s3<E>(what: impl fmt::Display, err: &SdkError<E, HttpResponse>) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + 'static,
    {
        let (kind, why, hint) = match err {
            SdkError::DispatchFailure(e) => (
                Kind::Network,
                format!(
                    "the endpoint can't be reached ({})",
                    source_chain(
                        e.as_connector_error()
                            .map(|e| e as &(dyn std::error::Error + 'static)),
                    )
                ),
                Some("check the address, and that the server is running".to_owned()),
            ),
            SdkError::TimeoutError(_) => (
                Kind::Network,
                "the endpoint didn't answer in time".into(),
                None,
            ),
            SdkError::ResponseError(_) => (
                Kind::Network,
                "the endpoint's answer couldn't be read".into(),
                Some("check that the address is an S3 service".to_owned()),
            ),
            SdkError::ServiceError(service) => {
                let status = service.raw().status().as_u16();
                let code = service.err().code().unwrap_or_default();
                let message = service.err().message().unwrap_or_default();
                (
                    kind_of(status, code),
                    describe(status, code, message),
                    hint_for(code).map(str::to_owned),
                )
            }
            _ => (Kind::General, source_chain(Some(err)), None),
        };
        Self {
            hint,
            ..Self::new(kind, format!("{what}: {why}"))
        }
    }

    /// An admin API request that failed, while doing `what`.
    pub fn admin(what: impl fmt::Display, err: &teifs_client::ClientError) -> Self {
        use teifs_client::ClientError;
        let (kind, why, hint) = match err {
            ClientError::Api {
                status,
                code,
                message,
                ..
            } => (
                kind_of(*status, code),
                describe(*status, code, message),
                hint_for(code).map(str::to_owned),
            ),
            ClientError::Transport(e) => (
                Kind::Network,
                format!("the endpoint can't be reached ({})", source_chain(Some(e))),
                Some("check the address, and that the server is running".to_owned()),
            ),
            ClientError::Endpoint(_) => (Kind::Usage, err.to_string(), None),
            ClientError::Answer(_) => (
                Kind::General,
                err.to_string(),
                Some("check that the alias points at a TeiFS server".to_owned()),
            ),
        };
        Self {
            hint,
            ..Self::new(kind, format!("{what}: {why}"))
        }
    }

    /// The same failure, said to have happened while doing `what`.
    #[must_use]
    pub fn within(self, what: impl fmt::Display) -> Self {
        Self {
            message: format!("{what}: {}", self.message),
            ..self
        }
    }

    /// Whether this failure means the thing isn't there.
    pub fn is_not_found(&self) -> bool {
        self.kind == Kind::NotFound
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::general(message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn kind_of(status: u16, code: &str) -> Kind {
    match (status, code) {
        (_, "NoSuchBucket" | "NoSuchKey" | "NoSuchUpload" | "NotFound" | "NoSuchEntity")
        | (404, _) => Kind::NotFound,
        (
            _,
            "AccessDenied"
            | "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "AuthorizationHeaderMalformed",
        )
        | (401 | 403, _) => Kind::Auth,
        (
            _,
            "BucketAlreadyExists"
            | "BucketAlreadyOwnedByYou"
            | "BucketNotEmpty"
            | "PreconditionFailed"
            | "EntityAlreadyExists"
            | "DeleteConflict"
            | "LimitExceeded",
        )
        | (409 | 412, _) => Kind::Conflict,
        (_, "MalformedPolicyDocument") => Kind::Usage,
        (500.., _) | (_, "SlowDown" | "RequestTimeout") => Kind::Network,
        _ => Kind::General,
    }
}

/// What to do about an S3 error code, when there's something.
fn hint_for(code: &str) -> Option<&'static str> {
    match code {
        "InvalidAccessKeyId" => Some("check the alias's access key: `teifs alias set`"),
        "SignatureDoesNotMatch" => Some("check the alias's secret key: `teifs alias set`"),
        "RequestTimeTooSkewed" => Some("this computer's clock is off: set it right"),
        "MalformedPolicyDocument" => {
            Some("check the policy file: it's an IAM policy document, as JSON")
        }
        "RootKeyManagedElsewhere" => Some(
            "the server was given its root key (TEIFS_ACCESS_KEY / TEIFS_SECRET_KEY, flags or \
             a secret key file): change it there and restart the server",
        ),
        _ => None,
    }
}

fn describe(status: u16, code: &str, message: &str) -> String {
    match (code, message) {
        ("", "") => match status {
            404 => "not found".to_owned(),
            403 => "access denied".to_owned(),
            412 => "it changed meanwhile".to_owned(),
            _ => format!("the endpoint answered {status}"),
        },
        ("", message) => message.to_owned(),
        (code, "") => code.to_owned(),
        (code, message) => format!("{message} ({code})"),
    }
}

fn source_chain(err: Option<&(dyn std::error::Error + 'static)>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for e in std::iter::successors(err, |e| e.source()) {
        let text = e.to_string();
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
    }
    if parts.is_empty() {
        "no reason given".to_owned()
    } else {
        parts.join(": ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_and_codes_become_kinds() {
        assert_eq!(kind_of(404, ""), Kind::NotFound);
        assert_eq!(kind_of(404, "NoSuchKey"), Kind::NotFound);
        assert_eq!(kind_of(403, "SignatureDoesNotMatch"), Kind::Auth);
        assert_eq!(kind_of(409, "BucketNotEmpty"), Kind::Conflict);
        assert_eq!(kind_of(412, ""), Kind::Conflict);
        assert_eq!(kind_of(503, "SlowDown"), Kind::Network);
        assert_eq!(kind_of(400, "InvalidArgument"), Kind::General);
    }

    #[test]
    fn descriptions_say_what_to_do() {
        assert_eq!(describe(404, "", ""), "not found");
        assert_eq!(
            describe(403, "InvalidAccessKeyId", "The key is unknown."),
            "The key is unknown. (InvalidAccessKeyId)"
        );
        assert!(
            hint_for("SignatureDoesNotMatch")
                .unwrap()
                .contains("teifs alias set")
        );
        assert_eq!(hint_for("NoSuchKey"), None);
        assert_eq!(describe(400, "Bad", ""), "Bad");
    }
}
