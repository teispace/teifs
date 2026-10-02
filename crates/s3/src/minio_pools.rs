//! `MinIO`'s server pools (`mc admin decommission`, `mc admin rebalance`), answered as a
//! one-drive server must: the drive is the only pool, so its status is listed but there's
//! no other pool to move its objects to or to balance them with.

use http::StatusCode;
use s3s::{Body, S3Request, S3Response, S3Result};
use serde::Serialize;

use crate::{
    admin::{error, json},
    routes::Routes,
};

/// Which of the calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Call {
    /// `GET pools/list`.
    List,
    /// `GET pools/status?pool=`.
    Status,
    /// `POST pools/decommission?pool=`.
    Decommission,
    /// `POST pools/cancel?pool=`.
    Cancel,
    /// `POST rebalance/start`.
    RebalanceStart,
    /// `GET rebalance/status`.
    RebalanceStatus,
    /// `POST rebalance/stop`.
    RebalanceStop,
}

impl Call {
    /// The call's name, as the audit log and traces name it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::List => "ListPools",
            Self::Status => "StatusPool",
            Self::Decommission => "StartDecommission",
            Self::Cancel => "CancelDecommission",
            Self::RebalanceStart => "RebalanceStart",
            Self::RebalanceStatus => "RebalanceStatus",
            Self::RebalanceStop => "RebalanceStop",
        }
    }

    pub(crate) fn call(self, routes: &Routes, req: &S3Request<Body>) -> S3Result<S3Response<Body>> {
        match self {
            Self::List => Ok(json(&[pool(routes)])),
            Self::Status => {
                asked_pool(routes, req)?;
                Ok(json(&pool(routes)))
            }
            Self::Decommission | Self::Cancel => {
                asked_pool(routes, req)?;
                Err(one_pool("there's no other pool to move its objects to"))
            }
            Self::RebalanceStart | Self::RebalanceStop => {
                Err(one_pool("there's no other pool to balance it with"))
            }
            Self::RebalanceStatus => Err(error(
                StatusCode::NOT_FOUND,
                "XMinioAdminRebalanceNotStarted",
                "Pool rebalance is not started",
            )),
        }
    }
}

/// `madmin.PoolStatus`, without a decommission: the drive's only pool.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PoolStatus {
    id: usize,
    cmdline: String,
    last_update: String,
}

fn pool(routes: &Routes) -> PoolStatus {
    PoolStatus {
        id: 0,
        cmdline: cmdline(routes),
        last_update: routes.store.format().created.clone(),
    }
}

/// The pool's name, as `MinIO` names a pool by its command line's arguments: the drive.
fn cmdline(routes: &Routes) -> String {
    routes.store.root().display().to_string()
}

/// Checks that the query names the pool: by name, or by index with `by-id=true`.
fn asked_pool(routes: &Routes, req: &S3Request<Body>) -> S3Result<()> {
    let query = req.uri.query().unwrap_or_default();
    let value = |name: &str| {
        form_urlencoded::parse(query.as_bytes())
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.into_owned())
    };
    let asked = value("pool").unwrap_or_default();
    let found = if value("by-id").as_deref() == Some("true") {
        asked == "0"
    } else {
        // MinIO's decommission takes a comma-separated list; there's one pool to name.
        !asked.is_empty() && asked.split(',').all(|pool| pool == cmdline(routes))
    };
    if found {
        Ok(())
    } else {
        Err(error(
            StatusCode::BAD_REQUEST,
            "XMinioAdminInvalidArgument",
            format!("specified pool '{asked}' not found, please specify a valid pool"),
        ))
    }
}

fn one_pool(why: &str) -> s3s::S3Error {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        format!("The drive is the server's only pool: {why}."),
    )
}
