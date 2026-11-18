//! The S3 service, as the gateways reach it: AWS SDK clients signed with the signed-in
//! person's key, whose requests go over an in-memory HTTP/1.1 connection to the same
//! service the S3 listener serves. Each is checked, audited and counted as any S3
//! client's request is; a gateway has no other way into the drive.

use std::sync::Arc;

use aws_sdk_s3::config::{
    AppName, BehaviorVersion, Credentials, Region, RequestChecksumCalculation,
    ResponseChecksumValidation, retry::RetryConfig,
};
use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
    },
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
    runtime_components::RuntimeComponents,
};
use aws_smithy_types::body::SdkBody;
use bytes::Bytes;
use http::{HeaderValue, header::HOST};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use zeroize::Zeroizing;

/// Where requests go: no network is involved, the name is only signed.
const ENDPOINT: &str = "http://gateway.teifs.internal";
/// The region requests are signed for (TeiFS takes any).
const REGION: &str = "us-east-1";
/// The in-memory connection's buffer.
const PIPE_BYTES: usize = 256 * 1024;

/// An access key and its secret, as a person signed in with them.
#[derive(Clone)]
pub struct Key {
    /// The access key id.
    pub id: String,
    /// The secret, wiped from memory when dropped.
    pub secret: Arc<Zeroizing<String>>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The S3 service the gateways call.
#[derive(Clone)]
pub struct Backend {
    service: teifs_s3::Service,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend").finish_non_exhaustive()
    }
}

/// Why a sign-in failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInError {
    /// The key is unknown, inactive, or its secret is wrong.
    Refused,
    /// The S3 service couldn't be asked.
    Unavailable(String),
}

impl Backend {
    /// The gateways' way to `service`.
    #[must_use]
    pub fn new(service: teifs_s3::Service) -> Self {
        Self { service }
    }

    /// A connector whose requests come from `client`.
    fn connector(&self, client: teifs_s3::Client) -> InMemory {
        InMemory {
            service: self.service.for_client(client),
        }
    }

    /// An S3 client signed with `key`, its requests from `client`, its user agent naming
    /// `protocol` (`teifs-sftp`), which the audit log records.
    #[must_use]
    pub fn s3(
        &self,
        key: &Key,
        client: teifs_s3::Client,
        protocol: &'static str,
    ) -> aws_sdk_s3::Client {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(REGION))
            .endpoint_url(ENDPOINT)
            .credentials_provider(credentials(key))
            .force_path_style(true)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            // A failure is the person's to see; their client may try again.
            .retry_config(RetryConfig::disabled())
            .http_client(self.connector(client))
            .app_name(AppName::new(protocol).expect("the gateways' names are valid app names"))
            .build();
        aws_sdk_s3::Client::from_conf(config)
    }

    /// Checks `key` with STS `GetCallerIdentity`, as `client` would: the ARN it signs in
    /// as.
    ///
    /// # Errors
    ///
    /// [`SignInError::Refused`] for a key the service doesn't take.
    pub async fn sign_in(
        &self,
        key: &Key,
        client: teifs_s3::Client,
        protocol: &'static str,
    ) -> Result<String, SignInError> {
        let config = aws_sdk_sts::Config::builder()
            .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
            .region(aws_sdk_sts::config::Region::new(REGION))
            .endpoint_url(ENDPOINT)
            .credentials_provider(credentials(key))
            .retry_config(aws_sdk_sts::config::retry::RetryConfig::disabled())
            .http_client(self.connector(client))
            .app_name(
                aws_sdk_sts::config::AppName::new(protocol)
                    .expect("the gateways' names are valid app names"),
            )
            .build();
        let sts = aws_sdk_sts::Client::from_conf(config);
        match sts.get_caller_identity().send().await {
            Ok(identity) => Ok(identity.arn.unwrap_or_default()),
            Err(err) => match err.raw_response().map(|r| r.status().as_u16()) {
                Some(400 | 401 | 403) => Err(SignInError::Refused),
                _ => Err(SignInError::Unavailable(format!(
                    "{}",
                    aws_smithy_types::error::display::DisplayErrorContext(&err)
                ))),
            },
        }
    }
}

fn credentials(key: &Key) -> Credentials {
    Credentials::new(&key.id, key.secret.as_str(), None, None, "teifs-gateway")
}

/// Sends the SDK's requests to the S3 service over in-memory connections.
#[derive(Clone)]
struct InMemory {
    service: teifs_s3::Service,
}

impl std::fmt::Debug for InMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemory").finish_non_exhaustive()
    }
}

fn failed(why: &str) -> ConnectorError {
    ConnectorError::other(why.to_owned().into(), None)
}

impl InMemory {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ConnectorError> {
        let request = request
            .try_into_http1x()
            .map_err(|e| ConnectorError::other(e.into(), None))?;
        let (mut parts, body) = request.into_parts();
        // The gateways send whole bodies (a part at most): never a stream.
        let body = body
            .bytes()
            .map(Bytes::copy_from_slice)
            .ok_or_else(|| failed("a gateway's request body is streamed"))?;
        if !parts.headers.contains_key(HOST)
            && let Some(host) = parts.uri.authority()
            && let Ok(host) = HeaderValue::from_str(host.as_str())
        {
            parts.headers.insert(HOST, host);
        }
        // The request line carries the path only, as on the wire.
        if let Some(path) = parts.uri.path_and_query().cloned() {
            parts.uri = http::Uri::from(path);
        }
        let request = http::Request::from_parts(parts, Full::new(body));
        let (near, far) = tokio::io::duplex(PIPE_BYTES);
        let service = self.service.clone();
        tokio::spawn(async move {
            let served = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(far), service)
                .await;
            if let Err(err) = served {
                tracing::debug!(error = %err, "a gateway's in-memory connection ended");
            }
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(near))
            .await
            .map_err(io)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await.map_err(io)?;
        let response = response.map(SdkBody::from_body_1_x);
        HttpResponse::try_from(response).map_err(|e| ConnectorError::other(e.into(), None))
    }
}

fn io(err: hyper::Error) -> ConnectorError {
    ConnectorError::io(err.into())
}

impl HttpConnector for InMemory {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let this = self.clone();
        HttpConnectorFuture::new(async move { this.send(request).await })
    }
}

impl HttpClient for InMemory {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}
