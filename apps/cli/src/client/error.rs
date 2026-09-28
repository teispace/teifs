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

/// A failure, with the message shown to the person.
#[derive(Debug)]
pub struct Error {
    pub kind: Kind,
    pub message: String,
}

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
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
        let (kind, why) = match err {
            SdkError::DispatchFailure(e) => (
                Kind::Network,
                format!(
                    "the endpoint can't be reached ({})",
                    source_chain(
                        e.as_connector_error()
                            .map(|e| e as &(dyn std::error::Error + 'static)),
                    )
                ),
            ),
            SdkError::TimeoutError(_) => {
                (Kind::Network, "the endpoint didn't answer in time".into())
            }
            SdkError::ResponseError(_) => (
                Kind::Network,
                "the endpoint's answer couldn't be read (is it an S3 service?)".into(),
            ),
            SdkError::ServiceError(service) => {
                let status = service.raw().status().as_u16();
                let code = service.err().code().unwrap_or_default();
                let message = service.err().message().unwrap_or_default();
                (kind_of(status, code), describe(status, code, message))
            }
            _ => (Kind::General, source_chain(Some(err))),
        };
        Self::new(kind, format!("{what}: {why}"))
    }

    /// The same failure, said to have happened while doing `what`.
    #[must_use]
    pub fn within(self, what: impl fmt::Display) -> Self {
        Self::new(self.kind, format!("{what}: {}", self.message))
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
        (_, "NoSuchBucket" | "NoSuchKey" | "NoSuchUpload" | "NotFound") | (404, _) => {
            Kind::NotFound
        }
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
            | "PreconditionFailed",
        )
        | (409 | 412, _) => Kind::Conflict,
        (500.., _) | (_, "SlowDown" | "RequestTimeout") => Kind::Network,
        _ => Kind::General,
    }
}

fn describe(status: u16, code: &str, message: &str) -> String {
    let hint = match code {
        "InvalidAccessKeyId" => " (check the alias's access key: `teifs alias set`)",
        "SignatureDoesNotMatch" => " (check the alias's secret key: `teifs alias set`)",
        "RequestTimeTooSkewed" => " (this computer's clock is off)",
        _ => "",
    };
    match (code, message) {
        ("", "") => match status {
            404 => "not found".to_owned(),
            403 => "access denied".to_owned(),
            412 => "it changed meanwhile".to_owned(),
            _ => format!("the endpoint answered {status}"),
        },
        ("", message) => message.to_owned(),
        (code, "") => format!("{code}{hint}"),
        (code, message) => format!("{message} ({code}){hint}"),
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
            "The key is unknown. (InvalidAccessKeyId) (check the alias's access key: `teifs alias set`)"
        );
        assert_eq!(describe(400, "Bad", ""), "Bad");
    }
}
