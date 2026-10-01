//! `MinIO`'s service calls (`mc admin service restart|stop|freeze|unfreeze`): the server
//! is asked to restart or stop once it has answered, and freezes hold S3's requests
//! (not the admin API's, nor health checks) until as many unfreezes have come.

use http::StatusCode;
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;
use tokio::sync::watch;

use crate::{admin, minio_iam::query, routes::Routes};

/// What a server was asked to do with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Stop, as a signal would stop it.
    Stop,
    /// Stop, then start again as it was started.
    Restart,
}

/// A server's freezes, and whether it was asked to stop: shared by its service, which
/// answers the calls, and whoever runs it.
#[derive(Debug)]
pub struct Control {
    /// How many freezes haven't been undone yet.
    frozen: watch::Sender<u32>,
    asked: watch::Sender<Option<Stop>>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            frozen: watch::Sender::new(0),
            asked: watch::Sender::new(None),
        }
    }
}

impl Control {
    fn freeze(&self) {
        self.frozen.send_modify(|n| *n = n.saturating_add(1));
    }

    fn unfreeze(&self) {
        self.frozen.send_modify(|n| *n = n.saturating_sub(1));
    }

    /// Waits while the server is frozen.
    pub(crate) async fn thawed(&self) {
        let mut frozen = self.frozen.subscribe();
        // The sender lives as long as `self`.
        let _ = frozen.wait_for(|n| *n == 0).await;
    }

    /// Lets every held request go: the server is stopping, and they'd hold it up.
    pub fn thaw(&self) {
        self.frozen.send_replace(0);
    }

    /// Waits until the server is asked to stop or restart.
    pub async fn asked(&self) -> Stop {
        let mut asked = self.asked.subscribe();
        loop {
            if let Some(stop) = *asked.borrow_and_update() {
                return stop;
            }
            if asked.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

/// A service call, as `?action=` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Restart,
    Stop,
    Freeze,
    Unfreeze,
}

impl Action {
    /// The call `?action=` names, or `MinIO`'s error for one it doesn't know.
    pub(crate) fn asked(query: Option<&str>) -> S3Result<Self> {
        let action = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .find(|(name, _)| name == "action")
            .map(|(_, value)| value);
        match action.as_deref() {
            Some("restart") => Ok(Self::Restart),
            Some("stop") => Ok(Self::Stop),
            Some("freeze") => Ok(Self::Freeze),
            Some("unfreeze") => Ok(Self::Unfreeze),
            _ => Err(admin::error(
                StatusCode::BAD_REQUEST,
                "MalformedPOSTRequest",
                "The body of your POST request is not well-formed multipart/form-data.",
            )),
        }
    }

    /// The action a caller needs for it.
    pub(crate) const fn needs(self) -> &'static str {
        match self {
            Self::Restart => "admin:ServiceRestart",
            Self::Stop => "admin:ServiceStop",
            Self::Freeze | Self::Unfreeze => "admin:ServiceFreeze",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Stop => "stop",
            Self::Freeze => "freeze",
            Self::Unfreeze => "unfreeze",
        }
    }
}

/// `madmin.ServiceActionResult`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Done {
    action: &'static str,
    dry_run: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    results: Vec<Peer>,
}

/// `madmin.ServiceActionPeerResult`: the server that was asked.
#[derive(Serialize)]
struct Peer {
    host: String,
}

/// Does what `?action=` asks, unless `?dry-run=true`: `MinIO`'s first form (no `type`)
/// answers nothing, its second (`type=2`, what `madmin` sends) what was done.
pub(crate) fn call(routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
    let action = Action::asked(req.uri.query())?;
    let query = query(req);
    let is = |name: &str, value: &str| query.iter().any(|(n, v)| n == name && v == value);
    let dry_run = is("dry-run", "true");
    if !dry_run {
        match action {
            Action::Freeze => routes.control.freeze(),
            Action::Unfreeze => routes.control.unfreeze(),
            // Asked now, stopped once the answer is out: a stopping server finishes
            // what it's answering.
            Action::Restart => drop(routes.control.asked.send_replace(Some(Stop::Restart))),
            Action::Stop => drop(routes.control.asked.send_replace(Some(Stop::Stop))),
        }
    }
    if !is("type", "2") {
        return Ok(S3Response::new(Body::empty()));
    }
    let results = match action {
        Action::Restart | Action::Stop => vec![Peer {
            host: crate::minio_info::endpoint(routes, req),
        }],
        Action::Freeze | Action::Unfreeze => Vec::new(),
    };
    Ok(admin::json(&Done {
        action: action.name(),
        dry_run,
        results,
    }))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn each_freeze_needs_its_unfreeze() {
        let control = Control::default();
        control.thawed().await;
        control.freeze();
        control.freeze();
        control.unfreeze();
        let waiting = tokio::time::timeout(Duration::from_millis(50), control.thawed());
        assert!(waiting.await.is_err(), "still frozen once");
        control.unfreeze();
        control.thawed().await;
        // More unfreezes than freezes don't freeze it ahead of time.
        control.unfreeze();
        control.freeze();
        let waiting = tokio::time::timeout(Duration::from_millis(50), control.thawed());
        assert!(waiting.await.is_err());
    }

    #[test]
    fn actions_are_named_in_the_query() {
        assert_eq!(
            Action::asked(Some("action=restart&type=2")).unwrap(),
            Action::Restart
        );
        assert_eq!(
            Action::asked(Some("type=2&action=stop")).unwrap(),
            Action::Stop
        );
        assert_eq!(
            Action::asked(Some("action=freeze")).unwrap().needs(),
            "admin:ServiceFreeze"
        );
        assert_eq!(
            Action::asked(Some("action=unfreeze")).unwrap().needs(),
            "admin:ServiceFreeze"
        );
        for query in [
            None,
            Some("action=cancel-restart"),
            Some("action=Restart"),
            Some(""),
        ] {
            let err = Action::asked(query).unwrap_err();
            assert_eq!(err.code().as_str(), "MalformedPOSTRequest");
            assert_eq!(err.status_code(), Some(StatusCode::BAD_REQUEST));
        }
    }
}
