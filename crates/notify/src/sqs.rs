//! SQS targets, as S3's own: each event sent to a queue as S3 sends it
//! (`{"Records":[record]}`), and S3's test event when a rule starts naming the queue,
//! with `SendMessage` in SQS's JSON protocol, signed with Signature Version 4. Any service
//! that speaks SQS's API will do. The body's MD5 in the answer is checked, as AWS's SDKs
//! check it.

use md5::{Digest as _, Md5};
use sha2::Sha256;
use teifs_types::notify::EventMessage;

use crate::aws::{self, AwsCredentials, Call, group_id, hex};

/// A queue events are sent to.
#[derive(Debug, Clone)]
pub struct Sqs {
    /// The queue's URL: `https://sqs.REGION.amazonaws.com/ACCOUNT/NAME`.
    pub queue_url: reqwest::Url,
    /// The region requests are signed for.
    pub region: String,
    /// The keys requests are signed with; none sends them unsigned.
    pub credentials: Option<AwsCredentials>,
}

impl Sqs {
    /// Events for the queue at `queue_url`, signed for `region` (by default the one its
    /// host names, else `us-east-1`).
    ///
    /// # Errors
    ///
    /// When `queue_url` isn't an `http` or `https` URL of a queue, or has credentials in
    /// it.
    pub fn new(queue_url: &str, region: Option<&str>) -> Result<Self, String> {
        let url = reqwest::Url::parse(queue_url.trim())
            .map_err(|_| format!("`{queue_url}` isn't a queue's URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url
                .path_segments()
                .is_none_or(|s| s.filter(|p| !p.is_empty()).count() < 2)
        {
            return Err(format!(
                "`{queue_url}` isn't a queue's URL: give https://sqs.REGION.amazonaws.com/ACCOUNT/NAME"
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("give its keys in the environment, not in the URL".to_owned());
        }
        let region = match region {
            Some(region) => region.to_owned(),
            None => url
                .host_str()
                .and_then(|host| aws::region_of(host, "sqs"))
                .unwrap_or_else(|| "us-east-1".to_owned()),
        };
        Ok(Self {
            queue_url: url,
            region,
            credentials: None,
        })
    }

    /// Where it sends, and the AWS ARN rules may name it by.
    #[must_use]
    pub fn shown(&self) -> String {
        match self.aws_arn() {
            Some(arn) => format!("{} ({}), also {arn}", self.queue_url, self.region),
            None => format!("{} ({})", self.queue_url, self.region),
        }
    }

    /// Its ARN on AWS, `arn:PARTITION:sqs:REGION:ACCOUNT:NAME`, when its URL is
    /// `…/ACCOUNT/NAME` (as AWS's, and those of the services that copy it, are).
    #[must_use]
    pub fn aws_arn(&self) -> Option<String> {
        let mut path = self.queue_url.path_segments()?.filter(|p| !p.is_empty());
        let (account, name) = (path.next()?, path.next()?);
        if path.next().is_some() {
            return None;
        }
        let host = self.queue_url.host_str().unwrap_or_default();
        let partition = if host.ends_with(".amazonaws.com.cn") {
            "aws-cn"
        } else if self.region.starts_with("us-gov-") {
            "aws-us-gov"
        } else {
            "aws"
        };
        Some(format!(
            "arn:{partition}:sqs:{}:{account}:{name}",
            self.region
        ))
    }

    /// Whether it's a FIFO queue, whose messages need a group.
    fn fifo(&self) -> bool {
        // SQS names them so, in lower case.
        self.queue_url.path().strip_suffix(".fifo").is_some()
    }

    /// Sends a queued event as S3 does, or the test event as it is.
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
        let mut request = serde_json::json!({
            "QueueUrl": self.queue_url.as_str(),
            "MessageBody": message,
        });
        if self.fifo() {
            // A group per object keeps each object's events in order; the same message
            // sent again is dropped as a duplicate.
            request["MessageGroupId"] = group_id(&group).into();
            request["MessageDeduplicationId"] = hex(&Sha256::digest(message.as_bytes())).into();
        }
        let mut endpoint = self.queue_url.clone();
        endpoint.set_path("/");
        endpoint.set_query(None);
        let call = Call {
            service: "sqs",
            region: &self.region,
            url: &endpoint,
            headers: &[
                ("content-type", "application/x-amz-json-1.0"),
                ("x-amz-target", "AmazonSQS.SendMessage"),
            ],
            body: request.to_string().into_bytes(),
        };
        let (status, answer) = call.send(client, self.credentials.as_ref()).await?;
        let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap_or_default();
        if !status.is_success() {
            let kind = answer["__type"]
                .as_str()
                .map_or("", |t| t.rsplit('#').next().unwrap_or(t));
            let why = answer["message"]
                .as_str()
                .or(answer["Message"].as_str())
                .unwrap_or("no reason");
            return Err(format!("SQS answered {status}: {kind} ({why})"));
        }
        let expected = hex(&Md5::digest(message.as_bytes()));
        if answer["MD5OfMessageBody"].as_str() != Some(expected.as_str()) {
            return Err("SQS's answer doesn't match the message sent".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_urls_and_regions_are_checked() {
        let sqs = Sqs::new(
            "https://sqs.eu-west-1.amazonaws.com/123456789012/events",
            None,
        )
        .unwrap();
        assert_eq!(sqs.region, "eu-west-1");
        assert!(!sqs.fifo());
        let local = Sqs::new("http://localhost:9324/000000000000/events.fifo", None).unwrap();
        assert_eq!(local.region, "us-east-1", "the default");
        assert!(local.fifo());
        let given = Sqs::new("http://localhost:9324/q/events", Some("eu-north-1")).unwrap();
        assert_eq!(given.region, "eu-north-1");
        for bad in [
            "",
            "sqs.amazonaws.com/1/q",
            "ftp://h/1/q",
            "https://h/q",
            "https://key:secret@h/1/q",
        ] {
            assert!(Sqs::new(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn queues_are_named_by_their_aws_arns() {
        let arn = |url: &str, region: Option<&str>| Sqs::new(url, region).unwrap().aws_arn();
        assert_eq!(
            arn(
                "https://sqs.eu-west-1.amazonaws.com/123456789012/events.fifo",
                None
            )
            .as_deref(),
            Some("arn:aws:sqs:eu-west-1:123456789012:events.fifo")
        );
        assert_eq!(
            arn(
                "https://sqs.cn-north-1.amazonaws.com.cn/123456789012/q",
                None
            )
            .as_deref(),
            Some("arn:aws-cn:sqs:cn-north-1:123456789012:q")
        );
        assert_eq!(
            arn(
                "https://sqs.us-gov-west-1.amazonaws.com/123456789012/q",
                None
            )
            .as_deref(),
            Some("arn:aws-us-gov:sqs:us-gov-west-1:123456789012:q")
        );
        assert_eq!(
            arn("http://localhost:4566/000000000000/q", None).as_deref(),
            Some("arn:aws:sqs:us-east-1:000000000000:q"),
            "as LocalStack names it"
        );
        assert_eq!(arn("http://localhost:4566/queue/eu/1/q", None), None);
    }

    #[test]
    fn digests_are_written_in_hex() {
        assert_eq!(hex(&Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
