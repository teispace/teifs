//! An S3 client that calls this server's own S3 service in-process: what S3 Batch
//! Operations runs a job's tasks with, signed with the job role's session, so a task
//! is allowed exactly what a request of that role's would be.

use std::sync::{Arc, OnceLock};

use aws_sdk_s3::{
    Client,
    config::{
        BehaviorVersion, Credentials, Region, RequestChecksumCalculation,
        ResponseChecksumValidation, retry::RetryConfig,
    },
    primitives::SdkBody,
};
use aws_smithy_runtime_api::client::{
    http::{
        HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
    },
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
    runtime_components::RuntimeComponents,
};
use http::{HeaderValue, header::HOST};
use s3s::service::S3Service;

/// Where requests go: no network is involved, the name is only signed.
const ENDPOINT: &str = "http://batch.teifs.internal";

/// The largest answer a task reads, a manifest's range included.
const MAX_ANSWER: usize = 16 * 1024 * 1024;

/// The S3 service, once it's built: the service's workers are made before it.
#[derive(Clone, Default)]
pub(crate) struct Loopback(Arc<OnceLock<S3Service>>);

impl std::fmt::Debug for Loopback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loopback")
            .field("ready", &self.0.get().is_some())
            .finish()
    }
}

impl Loopback {
    /// Sends requests to `s3` from now on; `s3`.
    pub(crate) fn serving(&self, s3: S3Service) -> S3Service {
        // Set once, when the service is built.
        let _ = self.0.set(s3.clone());
        s3
    }

    /// A client signed in with a session's credentials.
    pub(crate) fn client(&self, access_key: &str, secret: &str, token: &str) -> Client {
        let credentials = Credentials::new(
            access_key,
            secret,
            Some(token.to_owned()),
            None,
            "teifs-batch",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(crate::drive::REGION))
            .endpoint_url(ENDPOINT)
            .credentials_provider(credentials)
            .force_path_style(true)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            // A task that fails is counted and reported, as on AWS.
            .retry_config(RetryConfig::disabled())
            .http_client(self.clone())
            .build();
        Client::from_conf(config)
    }

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ConnectorError> {
        let s3 = self
            .0
            .get()
            .ok_or_else(|| failed("the S3 service isn't running yet"))?;
        let request = request
            .try_into_http1x()
            .map_err(|e| ConnectorError::other(e.into(), None))?;
        let (mut parts, body) = request.into_parts();
        let body = body
            .bytes()
            .map(bytes::Bytes::copy_from_slice)
            .ok_or_else(|| failed("a task's request body is streamed"))?;
        if !parts.headers.contains_key(HOST)
            && let Some(host) = parts.uri.authority()
            && let Ok(host) = HeaderValue::from_str(host.as_str())
        {
            parts.headers.insert(HOST, host);
        }
        // As a request over TLS from no address: no source address condition matches.
        parts.extensions.insert(crate::Client {
            ip: None,
            secure: true,
            tls: None,
        });
        let request = http::Request::from_parts(parts, s3s::Body::from(body));
        let response = s3
            .call(request)
            .await
            .map_err(|e| failed(&format!("{e:?}")))?;
        let (parts, mut body) = response.into_parts();
        let body = body
            .store_all_limited(MAX_ANSWER)
            .await
            .map_err(ConnectorError::io)?;
        HttpResponse::try_from(http::Response::from_parts(parts, SdkBody::from(body)))
            .map_err(|e| ConnectorError::other(e.into(), None))
    }
}

fn failed(why: &str) -> ConnectorError {
    ConnectorError::other(why.to_owned().into(), None)
}

impl HttpConnector for Loopback {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let this = self.clone();
        HttpConnectorFuture::new(async move { this.send(request).await })
    }
}

impl HttpClient for Loopback {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}
