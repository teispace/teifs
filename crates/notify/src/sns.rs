//! SNS targets, as S3's own: each event published to a topic as S3 publishes it
//! (`{"Records":[record]}`, subject `Amazon S3 Notification`), and S3's test event when a
//! rule starts naming the topic, with `Publish` in SNS's Query protocol, signed with
//! Signature Version 4. Rules name the topic by its own ARN, as on S3.

use sha2::{Digest as _, Sha256};
use teifs_types::notify::EventMessage;

use crate::aws::{AwsCredentials, Call, group_id, hex, xml_text};

/// The subject S3 publishes its notifications with.
pub const SUBJECT: &str = "Amazon S3 Notification";

/// A topic events are published to.
#[derive(Debug, Clone)]
pub struct Sns {
    /// The topic's ARN: `arn:aws:sns:REGION:ACCOUNT:NAME`.
    pub topic_arn: String,
    /// The region, from the ARN.
    pub region: String,
    /// Where requests go: SNS's endpoint in the region, unless another is given.
    pub endpoint: reqwest::Url,
    /// The keys requests are signed with; none sends them unsigned.
    pub credentials: Option<AwsCredentials>,
}

impl Sns {
    /// Events for the topic `topic_arn`, sent to `endpoint` (by default SNS's endpoint in
    /// the topic's region).
    ///
    /// # Errors
    ///
    /// When `topic_arn` isn't a topic's ARN, or `endpoint` isn't an `http` or `https` URL
    /// without credentials in it.
    pub fn new(topic_arn: &str, endpoint: Option<&str>) -> Result<Self, String> {
        let topic_arn = topic_arn.trim();
        let wrong =
            || format!("`{topic_arn}` isn't a topic's ARN: give arn:aws:sns:REGION:ACCOUNT:NAME");
        let parts: Vec<&str> = topic_arn.split(':').collect();
        let ["arn", partition, "sns", region, account, name] = parts.as_slice() else {
            return Err(wrong());
        };
        let named = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        };
        if !partition.starts_with("aws")
            || !named(region)
            || !account.bytes().all(|b| b.is_ascii_digit())
            || account.is_empty()
            || !named(name)
        {
            return Err(wrong());
        }
        let endpoint = if let Some(url) = endpoint {
            let url = reqwest::Url::parse(url.trim())
                .map_err(|_| format!("`{url}` isn't an endpoint's URL"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(format!("`{url}` isn't an http or https URL"));
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err("give its keys in the environment, not in the URL".to_owned());
            }
            url
        } else {
            let domain = if *partition == "aws-cn" {
                "amazonaws.com.cn"
            } else {
                "amazonaws.com"
            };
            reqwest::Url::parse(&format!("https://sns.{region}.{domain}/")).map_err(|_| wrong())?
        };
        Ok(Self {
            topic_arn: topic_arn.to_owned(),
            region: (*region).to_owned(),
            endpoint,
            credentials: None,
        })
    }

    /// Where it publishes.
    #[must_use]
    pub fn shown(&self) -> String {
        format!("{} at {}", self.topic_arn, self.endpoint)
    }

    /// Whether it's a FIFO topic, whose messages need a group.
    fn fifo(&self) -> bool {
        self.topic_arn.strip_suffix(".fifo").is_some()
    }

    /// Publishes a queued event as S3 does, or the test event as it is.
    pub(crate) async fn send(&self, client: &reqwest::Client, body: &[u8]) -> Result<(), String> {
        let (message, group) = match serde_json::from_slice::<EventMessage>(body) {
            Ok(event) => (
                serde_json::json!({ "Records": event.records }).to_string(),
                event.key,
            ),
            Err(_) => (
                String::from_utf8(body.to_vec()).map_err(|_| "not an event".to_owned())?,
                "teifs-test".to_owned(),
            ),
        };
        let form = {
            // Built apart: the serializer can't be held across an `await`.
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("Action", "Publish")
                .append_pair("Version", "2010-03-31")
                .append_pair("TopicArn", &self.topic_arn)
                .append_pair("Subject", SUBJECT)
                .append_pair("Message", &message);
            if self.fifo() {
                // As for SQS: a group per object, and the same message sent again dropped.
                form.append_pair("MessageGroupId", &group_id(&group))
                    .append_pair(
                        "MessageDeduplicationId",
                        &hex(&Sha256::digest(message.as_bytes())),
                    );
            }
            form.finish()
        };
        let call = Call {
            service: "sns",
            region: &self.region,
            url: &self.endpoint,
            headers: &[(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )],
            body: form.into_bytes(),
        };
        let (status, answer) = call.send(client, self.credentials.as_ref()).await?;
        let answer = String::from_utf8_lossy(&answer);
        if !status.is_success() {
            let code = xml_text(&answer, "Code").unwrap_or_default();
            let why = xml_text(&answer, "Message").unwrap_or_else(|| "no reason".to_owned());
            return Err(format!("SNS answered {status}: {code} ({why})"));
        }
        if xml_text(&answer, "MessageId").is_none_or(|id| id.is_empty()) {
            return Err("SNS's answer has no message id".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topics_are_read_from_their_arns() {
        let sns = Sns::new("arn:aws:sns:eu-west-1:123456789012:events", None).unwrap();
        assert_eq!(sns.region, "eu-west-1");
        assert_eq!(
            sns.endpoint.as_str(),
            "https://sns.eu-west-1.amazonaws.com/"
        );
        assert!(!sns.fifo());
        let china = Sns::new("arn:aws-cn:sns:cn-north-1:123456789012:t.fifo", None).unwrap();
        assert_eq!(
            china.endpoint.as_str(),
            "https://sns.cn-north-1.amazonaws.com.cn/"
        );
        assert!(china.fifo());
        let local = Sns::new(
            "arn:aws:sns:us-east-1:000000000000:t",
            Some("http://localhost:4566"),
        )
        .unwrap();
        assert_eq!(local.endpoint.as_str(), "http://localhost:4566/");
        for bad in [
            "",
            "arn:aws:sqs:eu-west-1:123456789012:q",
            "arn:aws:sns:eu-west-1:123456789012",
            "arn:aws:sns:eu-west-1:1234x:t",
            "arn:aws:sns::123456789012:t",
            "arn:other:sns:eu-west-1:123456789012:t",
            "arn:aws:sns:eu-west-1:123456789012:t:sub",
        ] {
            assert!(Sns::new(bad, None).is_err(), "{bad}");
        }
        for bad in ["ftp://h", "https://k:s@h/", "nope"] {
            assert!(
                Sns::new("arn:aws:sns:us-east-1:1:t", Some(bad)).is_err(),
                "{bad}"
            );
        }
    }
}
