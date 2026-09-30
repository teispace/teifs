//! Lambda targets, as S3's own: each event invoked asynchronously on a function as S3
//! invokes it (`{"Records":[record]}`, `InvocationType` `Event`), signed with Signature
//! Version 4. Rules name the function by its ARN, as on S3. Starting to name one checks,
//! with a `DryRun` invocation, that the keys may invoke it; like S3, it isn't sent a
//! test event.

use teifs_types::notify::EventMessage;

use crate::aws::{Answer, AwsCredentials, Call};

/// A function events are sent to.
#[derive(Debug, Clone)]
pub struct Lambda {
    /// The function's ARN: `arn:aws:lambda:REGION:ACCOUNT:function:NAME`, with a version
    /// or alias after another `:` if one is named.
    pub function_arn: String,
    /// The region, from the ARN.
    pub region: String,
    /// Where requests go: Lambda's endpoint in the region, unless another is given.
    pub endpoint: reqwest::Url,
    /// The keys requests are signed with; none sends them unsigned.
    pub credentials: Option<AwsCredentials>,
}

impl Lambda {
    /// Events for the function `function_arn`, sent to `endpoint` (by default Lambda's
    /// endpoint in the function's region).
    ///
    /// # Errors
    ///
    /// When `function_arn` isn't a function's ARN, or `endpoint` isn't an `http` or
    /// `https` URL without credentials in it.
    pub fn new(function_arn: &str, endpoint: Option<&str>) -> Result<Self, String> {
        let function_arn = function_arn.trim();
        let wrong = || {
            format!(
                "`{function_arn}` isn't a function's ARN: give \
                 arn:aws:lambda:REGION:ACCOUNT:function:NAME"
            )
        };
        let parts: Vec<&str> = function_arn.split(':').collect();
        let (partition, region, account, name, qualifier) = match parts.as_slice() {
            [
                "arn",
                partition,
                "lambda",
                region,
                account,
                "function",
                name,
            ] => (*partition, *region, *account, *name, None),
            [
                "arn",
                partition,
                "lambda",
                region,
                account,
                "function",
                name,
                qualifier,
            ] => (*partition, *region, *account, *name, Some(*qualifier)),
            _ => return Err(wrong()),
        };
        let named = |s: &str, extra: &[u8]| {
            !s.is_empty()
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || extra.contains(&b)
                })
        };
        if !partition.starts_with("aws")
            || !named(region, &[])
            || account.len() != 12
            || !account.bytes().all(|b| b.is_ascii_digit())
            || !named(name, b".")
            || name.len() > 64
            || qualifier.is_some_and(|q| !named(q, b"$.") || q.len() > 128)
        {
            return Err(wrong());
        }
        let endpoint = crate::aws::endpoint("lambda", partition, region, endpoint)?;
        Ok(Self {
            function_arn: function_arn.to_owned(),
            region: region.to_owned(),
            endpoint,
            credentials: None,
        })
    }

    /// Where it sends.
    #[must_use]
    pub fn shown(&self) -> String {
        format!("{} at {}", self.function_arn, self.endpoint)
    }

    /// Invokes the function with a queued event as S3 does, without waiting for it to
    /// run.
    pub(crate) async fn send(&self, client: &reqwest::Client, body: &[u8]) -> Result<(), String> {
        let event: EventMessage =
            serde_json::from_slice(body).map_err(|_| "not an event".to_owned())?;
        let payload = serde_json::json!({ "Records": event.records }).to_string();
        self.invoke(client, "Event", payload.into_bytes()).await
    }

    /// Checks the keys may invoke the function, without running it.
    pub(crate) async fn test(&self, client: &reqwest::Client) -> Result<(), String> {
        self.invoke(client, "DryRun", b"{}".to_vec()).await
    }

    async fn invoke(
        &self,
        client: &reqwest::Client,
        kind: &str,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        let mut url = self.endpoint.clone();
        // The function's ARN is one segment, its `:` encoded as AWS's SDKs encode it.
        url.set_path(&format!(
            "/2015-03-31/functions/{}/invocations",
            self.function_arn.replace(':', "%3A").replace('$', "%24")
        ));
        let call = Call {
            service: "lambda",
            region: &self.region,
            url: &url,
            headers: &[
                ("content-type", "application/json"),
                ("x-amz-invocation-type", kind),
            ],
            body: payload,
        };
        let Answer {
            status,
            error_type,
            body,
        } = call.send(client, self.credentials.as_ref()).await?;
        let expected = if kind == "DryRun" { 204 } else { 202 };
        if status.as_u16() == expected {
            return Ok(());
        }
        let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let kind = error_type
            .or_else(|| answer["Type"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let why = answer["message"]
            .as_str()
            .or(answer["Message"].as_str())
            .unwrap_or("no reason");
        Err(format!("Lambda answered {status}: {kind} ({why})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functions_are_read_from_their_arns() {
        let f = Lambda::new(
            "arn:aws:lambda:eu-west-1:123456789012:function:thumbnails",
            None,
        )
        .unwrap();
        assert_eq!(f.region, "eu-west-1");
        assert_eq!(
            f.endpoint.as_str(),
            "https://lambda.eu-west-1.amazonaws.com/"
        );
        let alias = Lambda::new(
            "arn:aws-cn:lambda:cn-north-1:123456789012:function:t:$LATEST",
            None,
        )
        .unwrap();
        assert_eq!(
            alias.endpoint.as_str(),
            "https://lambda.cn-north-1.amazonaws.com.cn/"
        );
        let local = Lambda::new(
            "arn:aws:lambda:us-east-1:000000000000:function:f",
            Some("http://localhost:4566"),
        )
        .unwrap();
        assert_eq!(local.endpoint.as_str(), "http://localhost:4566/");
        for bad in [
            "",
            "thumbnails",
            "123456789012:function:thumbnails",
            "arn:aws:lambda:eu-west-1:123456789012:thumbnails",
            "arn:aws:lambda:eu-west-1:1234:function:thumbnails",
            "arn:aws:sns:eu-west-1:123456789012:function:thumbnails",
            "arn:aws:lambda:eu-west-1:123456789012:function:a b",
            "arn:aws:lambda:eu-west-1:123456789012:function:t:v1:x",
        ] {
            assert!(Lambda::new(bad, None).is_err(), "{bad}");
        }
    }
}
