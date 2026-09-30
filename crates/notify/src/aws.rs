//! Requests to AWS's services (or ones that speak their APIs), signed with Signature
//! Version 4: the credentials, the region taken from an endpoint, and the signing.

use std::{fmt, time::SystemTime};

use aws_sigv4::{
    http_request::{SignableBody, SignableRequest, SigningSettings, sign},
    sign::v4,
};
use zeroize::Zeroizing;

/// The keys requests are signed with.
#[derive(Clone)]
pub struct AwsCredentials {
    /// The access key id.
    pub access_key: String,
    /// The secret access key.
    pub secret: Zeroizing<String>,
    /// A session's token, for temporary credentials.
    pub session_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

/// The region of an AWS endpoint's host (`sqs.eu-west-1.amazonaws.com` gives
/// `eu-west-1`), if it names one.
#[must_use]
pub fn region_of(host: &str, service: &str) -> Option<String> {
    let rest = host.strip_prefix(service)?.strip_prefix('.')?;
    let (region, domain) = rest.split_once('.')?;
    (domain.starts_with("amazonaws.") && !region.is_empty()).then(|| region.to_owned())
}

/// A request to `service` in `region`: `POST url` with `headers` and `body`.
pub(crate) struct Call<'a> {
    pub service: &'a str,
    pub region: &'a str,
    pub url: &'a reqwest::Url,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Vec<u8>,
}

impl Call<'_> {
    /// Sends it, signed with `credentials` if there are any, and gives the status and
    /// body of the answer.
    pub(crate) async fn send(
        self,
        client: &reqwest::Client,
        credentials: Option<&AwsCredentials>,
    ) -> Result<(reqwest::StatusCode, Vec<u8>), String> {
        let mut request = client.post(self.url.clone());
        for (name, value) in self.headers {
            request = request.header(*name, *value);
        }
        if let Some(credentials) = credentials {
            for (name, value) in self.signature(credentials)? {
                request = request.header(name, value);
            }
        }
        let answer = request
            .body(self.body)
            .send()
            .await
            .map_err(|e| format!("can't reach it: {e}"))?;
        let status = answer.status();
        let body = answer
            .bytes()
            .await
            .map_err(|e| format!("its answer was cut short: {e}"))?;
        Ok((status, body.to_vec()))
    }

    /// The headers that sign it.
    fn signature(&self, credentials: &AwsCredentials) -> Result<Vec<(String, String)>, String> {
        let host = match self.url.port() {
            Some(port) => format!("{}:{port}", self.url.host_str().unwrap_or_default()),
            None => self.url.host_str().unwrap_or_default().to_owned(),
        };
        let identity = aws_credential_types::Credentials::new(
            &credentials.access_key,
            credentials.secret.as_str(),
            credentials.session_token.as_deref().cloned(),
            None,
            "teifs-notify",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(self.region)
            .name(self.service)
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|e| e.to_string())?
            .into();
        let headers = std::iter::once(("host", host.as_str())).chain(self.headers.iter().copied());
        let signable = SignableRequest::new(
            "POST",
            self.url.as_str(),
            headers,
            SignableBody::Bytes(&self.body),
        )
        .map_err(|e| e.to_string())?;
        let (instructions, _) = sign(signable, &params)
            .map_err(|e| e.to_string())?
            .into_parts();
        Ok(instructions
            .headers()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_are_read_from_aws_hosts() {
        assert_eq!(
            region_of("sqs.eu-west-1.amazonaws.com", "sqs").as_deref(),
            Some("eu-west-1")
        );
        assert_eq!(
            region_of("sqs.cn-north-1.amazonaws.com.cn", "sqs").as_deref(),
            Some("cn-north-1")
        );
        assert_eq!(
            region_of("sns.us-east-2.amazonaws.com", "sns").as_deref(),
            Some("us-east-2")
        );
        for other in [
            "localhost",
            "sqs.local",
            "queue.amazonaws.com",
            "sqs..amazonaws.com",
        ] {
            assert_eq!(region_of(other, "sqs"), None, "{other}");
        }
    }

    #[test]
    fn requests_are_signed_for_their_service_and_region() {
        let url = reqwest::Url::parse("https://sqs.eu-west-1.amazonaws.com/").unwrap();
        let call = Call {
            service: "sqs",
            region: "eu-west-1",
            url: &url,
            headers: &[("x-amz-target", "AmazonSQS.SendMessage")],
            body: b"{}".to_vec(),
        };
        let credentials = AwsCredentials {
            access_key: "AKIDEXAMPLE".into(),
            secret: Zeroizing::new("secret".into()),
            session_token: Some(Zeroizing::new("token".into())),
        };
        let headers = call.signature(&credentials).unwrap();
        let get = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let authorization = get("authorization");
        assert!(
            authorization.contains("/eu-west-1/sqs/aws4_request"),
            "{authorization}"
        );
        assert!(authorization.contains("x-amz-target"), "{authorization}");
        assert_eq!(get("x-amz-security-token"), "token");
        assert!(!format!("{credentials:?}").contains("secret"));
    }
}
