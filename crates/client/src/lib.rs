//! A typed client for TeiFS's admin API (`/.teifs/admin/v1/`): server info and
//! configuration, IAM export and import, and root key rotation. Requests are signed
//! with Signature V4 as S3 requests are, with the messages the server itself uses
//! ([`teifs_types::admin`]). Users, keys, groups and policies are AWS's IAM API, which
//! any AWS SDK calls.
//!
//! ```no_run
//! # async fn run() -> Result<(), teifs_client::ClientError> {
//! use teifs_client::{Client, Zeroizing};
//!
//! let secret = Zeroizing::new(std::env::var("TEIFS_SECRET_KEY").unwrap_or_default());
//! let client = Client::new("http://127.0.0.1:9000", "ACCESS_KEY", secret)?;
//! let info = client.info().await?;
//! println!("TeiFS {} serving drive {}", info.version, info.drive);
//! # Ok(())
//! # }
//! ```

use std::{fmt, sync::Arc, time::SystemTime};

use aws_sigv4::{
    http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign},
    sign::v4,
};
use reqwest::{Method, Url, header::CONTENT_TYPE};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use serde::de::DeserializeOwned;
pub use zeroize::Zeroizing;

use teifs_types::admin::{
    ADMIN_BUCKETS, ADMIN_CONFIG, ADMIN_IAM, ADMIN_IAM_SECRETS, ADMIN_INFO, ADMIN_ROOT_KEY,
    ADMIN_SNAPSHOTS, ADMIN_TRACE,
};
pub use teifs_types::admin::{
    AdminError, BucketImportItem, BucketsExport, BucketsImportReport, ExportedBucket,
    ExportedGroup, ExportedKey, ExportedPolicy, ExportedUser, ExportedVersion, IamExport,
    ImportReport, JobInfo, KmsConfig, RootKeyRotated, ServerConfig, ServerInfo, Snapshot, Tag,
};
pub use teifs_types::audit::{AuditEntry, TraceFilter};

/// The region requests are signed for when none is given (TeiFS accepts any).
pub const DEFAULT_REGION: &str = "us-east-1";

/// Why a request failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The server answered with an error.
    #[error("{message} ({code}, HTTP {status})")]
    Api {
        /// The HTTP status.
        status: u16,
        /// The error's code: `AccessDenied`, `NotFound`, ….
        code: String,
        /// What went wrong, for a person.
        message: String,
        /// The request's id, as the server logged it.
        request_id: Option<String>,
    },
    /// The endpoint isn't an `http(s)://host[:port]` URL.
    #[error("the endpoint {0:?} isn't an http:// or https:// URL")]
    Endpoint(String),
    /// The request couldn't be sent or its answer read.
    #[error("can't reach the server: {0}")]
    Transport(#[from] reqwest::Error),
    /// The answer isn't what the admin API answers.
    #[error("the server's answer isn't what TeiFS answers: {0}")]
    Answer(String),
    /// A certificate authority to trust isn't PEM certificates.
    #[error("the CA certificate isn't usable: {0}")]
    Certificate(String),
}

impl ClientError {
    /// The error's code when the server answered one.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// A client for one server, signing as one access key.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    endpoint: Url,
    access_key: String,
    secret: Zeroizing<String>,
    /// Temporary credentials' session token.
    session_token: Option<Zeroizing<String>>,
    region: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.endpoint.as_str())
            .field("access_key", &self.access_key)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the server at `endpoint` (`http(s)://host[:port]`), signing with this
    /// key for [`DEFAULT_REGION`].
    pub fn new(
        endpoint: &str,
        access_key: &str,
        secret: Zeroizing<String>,
    ) -> Result<Self, ClientError> {
        let invalid = || ClientError::Endpoint(endpoint.to_owned());
        let url = Url::parse(endpoint).map_err(|_| invalid())?;
        let plain = url.path() == "/" && url.query().is_none() && url.fragment().is_none();
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || !plain
        {
            return Err(invalid());
        }
        Ok(Self {
            http: reqwest::Client::new(),
            endpoint: url,
            access_key: access_key.to_owned(),
            secret,
            session_token: None,
            region: DEFAULT_REGION.to_owned(),
        })
    }

    /// Trusts the certificate authorities in `pem` (PEM certificates) for the server,
    /// besides the system's: for a server whose certificate a private CA signed.
    pub fn with_root_certificates(mut self, pem: &[u8]) -> Result<Self, ClientError> {
        let invalid = |e: &dyn std::fmt::Display| ClientError::Certificate(e.to_string());
        let certificates = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid(&e))?;
        if certificates.is_empty() {
            return Err(ClientError::Certificate("no certificate in it".into()));
        }
        // Checked as the AWS SDKs' clients check it (webpki, the system's authorities as
        // rustls-native-certs finds them), so an alias's servers pass or fail alike.
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        for certificate in certificates {
            roots.add(certificate).map_err(|e| invalid(&e))?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| invalid(&e))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        self.http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .build()
            .map_err(|e| invalid(&e))?;
        Ok(self)
    }

    /// Signs with temporary credentials: the key is theirs, and this their session
    /// token.
    #[must_use]
    pub fn with_session_token(mut self, token: Zeroizing<String>) -> Self {
        self.session_token = Some(token);
        self
    }

    /// Signs for `region` instead.
    #[must_use]
    pub fn with_region(mut self, region: &str) -> Self {
        region.clone_into(&mut self.region);
        self
    }

    /// What the server is and how it's doing (`teifs:GetServerInfo`).
    pub async fn info(&self) -> Result<ServerInfo, ClientError> {
        self.call(Method::GET, ADMIN_INFO, None, Vec::new()).await
    }

    /// How the server was started, without secrets (`teifs:GetServerConfig`).
    pub async fn config(&self) -> Result<ServerConfig, ClientError> {
        self.call(Method::GET, ADMIN_CONFIG, None, Vec::new()).await
    }

    /// The account's IAM; with the access keys' secrets only if `secrets` (root user
    /// only), else `teifs:ExportIAM`.
    pub async fn export_iam(&self, secrets: bool) -> Result<IamExport, ClientError> {
        let path = if secrets {
            ADMIN_IAM_SECRETS
        } else {
            ADMIN_IAM
        };
        self.call(Method::GET, path, None, Vec::new()).await
    }

    /// Imports `export` into the server's empty IAM, all or nothing; with
    /// `adopt_account`, the account takes the export's id (root user only).
    pub async fn import_iam(
        &self,
        export: &IamExport,
        adopt_account: bool,
    ) -> Result<ImportReport, ClientError> {
        let body = serde_json::to_vec(export).map_err(|e| ClientError::Answer(e.to_string()))?;
        let query = if adopt_account {
            "account=adopt"
        } else {
            "account=keep"
        };
        self.call(Method::PUT, ADMIN_IAM, Some(query), body).await
    }

    /// Replaces the root key the drive generated, answering the new one; the old one
    /// stops working at once (root user only).
    pub async fn rotate_root_key(&self) -> Result<RootKeyRotated, ClientError> {
        self.call(Method::POST, ADMIN_ROOT_KEY, None, Vec::new())
            .await
    }

    /// The drive's metadata snapshots, oldest first (`teifs:ListSnapshots`).
    pub async fn snapshots(&self) -> Result<Vec<Snapshot>, ClientError> {
        self.call(Method::GET, ADMIN_SNAPSHOTS, None, Vec::new())
            .await
    }

    /// Snapshots the drive's metadata now (`teifs:TakeSnapshot`).
    pub async fn take_snapshot(&self) -> Result<Snapshot, ClientError> {
        self.call(Method::POST, ADMIN_SNAPSHOTS, None, Vec::new())
            .await
    }

    /// The buckets and their settings, or only `bucket`'s (`teifs:ExportBucketMetadata`).
    /// Bucket names need no escaping: S3's rules allow only letters, digits, `.` and `-`.
    pub async fn export_buckets(&self, bucket: Option<&str>) -> Result<BucketsExport, ClientError> {
        let query = bucket.map(|name| format!("bucket={name}"));
        self.call(Method::GET, ADMIN_BUCKETS, query.as_deref(), Vec::new())
            .await
    }

    /// Imports `export`: missing buckets are created and the settings given applied,
    /// each reported (`teifs:ImportBucketMetadata`).
    pub async fn import_buckets(
        &self,
        export: &BucketsExport,
    ) -> Result<BucketsImportReport, ClientError> {
        let body = serde_json::to_vec(export).map_err(|e| ClientError::Answer(e.to_string()))?;
        self.call(Method::PUT, ADMIN_BUCKETS, None, body).await
    }

    /// Sends a signed request and reads its JSON answer.
    /// A live trace of the requests the server answers from now on, those `filter`
    /// shows (`teifs:ServerTrace`): read it with [`Trace::next`].
    pub async fn trace(&self, filter: &TraceFilter) -> Result<Trace, ClientError> {
        let query = filter.to_query();
        let query = (!query.is_empty()).then_some(query.as_str());
        let response = self
            .send(Method::GET, ADMIN_TRACE, query, Vec::new())
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(api_error(status, &response.bytes().await?));
        }
        Ok(Trace {
            response,
            pending: Vec::new(),
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        body: Vec<u8>,
    ) -> Result<T, ClientError> {
        let response = self.send(method, path, query, body).await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if status.is_success() {
            return serde_json::from_slice(&bytes).map_err(|e| ClientError::Answer(e.to_string()));
        }
        Err(api_error(status, &bytes))
    }

    /// Sends a signed request.
    async fn send(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, ClientError> {
        let mut url = self.endpoint.clone();
        url.set_path(path);
        url.set_query(query);
        let mut request = self
            .http
            .request(method.clone(), url.clone())
            .header(CONTENT_TYPE, "application/json");
        for (name, value) in self.signature(&method, &url, &body)? {
            request = request.header(name, value);
        }
        Ok(request.body(body).send().await?)
    }

    /// The headers that sign a request, its body's hash among them.
    fn signature(
        &self,
        method: &Method,
        url: &Url,
        body: &[u8],
    ) -> Result<Vec<(String, String)>, ClientError> {
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let identity = aws_credential_types::Credentials::new(
            &self.access_key,
            self.secret.as_str(),
            self.session_token.as_deref().cloned(),
            None,
            "teifs-client",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("s3")
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|e| ClientError::Answer(e.to_string()))?
            .into();
        let headers = [
            ("host", host.as_str()),
            ("content-type", "application/json"),
        ];
        let signable = SignableRequest::new(
            method.as_str(),
            url.as_str(),
            headers.into_iter(),
            SignableBody::Bytes(body),
        )
        .map_err(|e| ClientError::Answer(e.to_string()))?;
        let (instructions, _) = sign(signable, &params)
            .map_err(|e| ClientError::Answer(e.to_string()))?
            .into_parts();
        Ok(instructions
            .headers()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect())
    }
}

/// The error a server answered: the admin API's JSON, or S3's XML for what's refused
/// before the admin API sees the request (a signature that doesn't match, an unknown
/// key).
fn api_error(status: reqwest::StatusCode, body: &[u8]) -> ClientError {
    if let Ok(err) = serde_json::from_slice::<AdminError>(body) {
        return ClientError::Api {
            status: status.as_u16(),
            code: err.code,
            message: err.message,
            request_id: Some(err.request_id),
        };
    }
    let text = String::from_utf8_lossy(body);
    let element = |name: &str| {
        let start = text.find(&format!("<{name}>"))? + name.len() + 2;
        let end = start + text[start..].find(&format!("</{name}>"))?;
        Some(
            text[start..end]
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&"),
        )
    };
    ClientError::Api {
        status: status.as_u16(),
        code: element("Code").unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("Unknown")
                .replace(' ', "")
        }),
        message: element("Message").unwrap_or_default(),
        request_id: element("RequestId"),
    }
}

/// A live trace: the requests a server answers, as it answers them.
#[derive(Debug)]
pub struct Trace {
    response: reqwest::Response,
    /// What's been read of a line not yet whole.
    pending: Vec<u8>,
}

impl Trace {
    /// The next request's entry, waiting for one; `None` once the server ends the trace
    /// (it's stopping).
    ///
    /// # Errors
    ///
    /// The connection failed, or a line isn't an entry.
    pub async fn next(&mut self) -> Result<Option<AuditEntry>, ClientError> {
        loop {
            if let Some(end) = self.pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                let line = line.trim_ascii();
                // Empty lines keep a quiet trace open through proxies.
                if line.is_empty() {
                    continue;
                }
                return serde_json::from_slice(line)
                    .map(Some)
                    .map_err(|e| ClientError::Answer(e.to_string()));
            }
            match self.response.chunk().await? {
                Some(chunk) => self.pending.extend_from_slice(&chunk),
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_endpoints_are_taken() {
        let secret = || Zeroizing::new("s".to_owned());
        for good in [
            "http://127.0.0.1:9000",
            "https://s3.example.com/",
            "http://[::1]:9000",
        ] {
            assert!(Client::new(good, "a", secret()).is_ok(), "{good}");
        }
        for bad in [
            "127.0.0.1:9000",
            "ftp://host",
            "http://host/bucket",
            "http://key:secret@host",
            "http://host?x=1",
            "http://",
        ] {
            let err = Client::new(bad, "a", secret()).unwrap_err();
            assert!(matches!(err, ClientError::Endpoint(_)), "{bad}");
        }
    }

    #[test]
    fn root_certificates_must_be_pem_certificates() {
        let client = || {
            Client::new(
                "https://s3.example.com",
                "a",
                Zeroizing::new("s".to_owned()),
            )
        };
        for pem in [&b""[..], b"nonsense"] {
            let err = client().unwrap().with_root_certificates(pem).err();
            assert!(matches!(err, Some(ClientError::Certificate(_))), "{err:?}");
        }
    }

    #[test]
    fn errors_are_read_in_either_format() {
        let forbidden = reqwest::StatusCode::FORBIDDEN;
        let json = br#"{"code":"AccessDenied","message":"no","requestId":"r1"}"#;
        let xml = b"<?xml version=\"1.0\"?><Error><Code>SignatureDoesNotMatch</Code>\
            <Message>bad &amp; wrong</Message><RequestId>r2</RequestId></Error>";
        for (body, code, request_id) in [
            (&json[..], "AccessDenied", Some("r1")),
            (&xml[..], "SignatureDoesNotMatch", Some("r2")),
            (b"<html>proxy</html>", "Forbidden", None),
            (b"", "Forbidden", None),
        ] {
            let ClientError::Api {
                status,
                code: got,
                request_id: id,
                ..
            } = api_error(forbidden, body)
            else {
                panic!("not an API error");
            };
            assert_eq!(
                (status, got.as_str(), id.as_deref()),
                (403, code, request_id)
            );
        }
        let ClientError::Api { message, .. } = api_error(forbidden, xml) else {
            panic!("not an API error");
        };
        assert_eq!(message, "bad & wrong");
    }

    #[test]
    fn requests_are_signed_for_the_region_and_service_s3() {
        let client = Client::new("http://h:9000", "AKID", Zeroizing::new("s".into()))
            .unwrap()
            .with_region("eu-west-1");
        let url = Url::parse("http://h:9000/.teifs/admin/v1/info").unwrap();
        let headers = client.signature(&Method::GET, &url, b"").unwrap();
        let find = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert!(
            find("authorization").contains("/eu-west-1/s3/aws4_request"),
            "{headers:?}"
        );
        // The body's hash is signed, so the server checks the body it gets.
        assert_eq!(
            find("x-amz-content-sha256"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_secret_never_shows() {
        let client = Client::new("http://h", "AKID", Zeroizing::new("hidden".into())).unwrap();
        assert!(!format!("{client:?}").contains("hidden"));
    }
}
