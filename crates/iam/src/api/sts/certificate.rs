//! MinIO's `AssumeRoleWithCertificate`: temporary credentials for whoever holds a client
//! certificate the server trusts. Unsigned: the TLS connection's certificate is the
//! proof. The session has the managed policy the certificate's subject common name
//! names, and ends no later than the certificate does.

use super::{
    ApiError, MINIO_LONGEST, ONE_HOUR, Out, Run, SHORTEST, answer, credentials, duration,
    managed_policy, min_token_size, session_policies,
};
use crate::{
    certificate::CertificateError,
    sessions::{Claims, Who, now_seconds},
};

/// The action's name.
pub(in crate::api) const CERTIFICATE: &str = "AssumeRoleWithCertificate";

/// The action: refused when the server doesn't take certificates, or this one.
pub(in crate::api) fn assume_role_with_certificate(r: &Run<'_>) -> Out {
    let Some(sign_in) = r.iam.certificate_sign_in() else {
        return Err(ApiError {
            status: 503,
            code: "STSNotInitialized",
            message: format!("STS API '{CERTIFICATE}' is disabled"),
        });
    };
    let policies = session_policies(r)?;
    let seconds = duration(r, SHORTEST..=MINIO_LONGEST)?.unwrap_or(ONE_HOUR);
    let min_token = min_token_size(r)?;
    let now = now_seconds();
    let presented = sign_in.check(r.certificates, now).map_err(refused)?;
    let Some(policy) = r.iam.read(|s| Ok(managed_policy(s, &presented.cn)))? else {
        return Err(ApiError::invalid_parameter(format!(
            "No policy is called {}, the certificate's common name: credentials will not \
             be generated",
            presented.cn
        )));
    };
    let expires = presented.not_after.min(now + i64::from(seconds));
    let who = Who::Certificate {
        cn: presented.cn.clone(),
        policy,
    };
    let mut claims = Claims::new(who, now, expires);
    claims.policies = policies;
    let issued = r.iam.issue_at_least(&claims, min_token)?;
    tracing::info!(cn = %presented.cn, "a client certificate signed in");
    answer(|x| {
        credentials(x, &issued);
    })
}

/// A certificate that isn't accepted, as MinIO answers it.
fn refused(err: CertificateError) -> ApiError {
    match err {
        CertificateError::Invalid(why) => {
            tracing::info!(reason = %why, "a client certificate was refused");
            ApiError {
                status: 400,
                code: "InvalidClientCertificate",
                message: "The provided client certificate is invalid. Retry with a different \
                          certificate."
                    .into(),
            }
        }
        CertificateError::NotForClients => ApiError {
            status: 400,
            code: "InvalidClientCertificate",
            message: err.to_string(),
        },
        other => ApiError::invalid_parameter(other.to_string()),
    }
}
