//! S3 Control: the account's Block Public Access settings, which apply with every
//! bucket's (each setting on where either has it), as `aws s3control
//! get|put|delete-public-access-block` and the SDKs call them.
//!
//! The SDKs send the account in the host (`{account}.endpoint`) and in the
//! `x-amz-account-id` header; TeiFS reads the header, which must name the drive's
//! account. [`crate::routes`] decides who may call it.

use http::{HeaderMap, HeaderValue, header};
use s3s::{
    Body, S3Error, S3ErrorCode, S3Request, S3Response, S3Result, dto,
    xml::{Deserialize, Deserializer, SerializeContent, Serializer},
};
use teifs_store::Store;

use crate::{
    bucket_access::{Rules, block_from_dto, block_to_dto, no_public_access_block},
    errors::StoreResultExt,
    routes::{s3_refusal, signed_body},
};

/// Where S3 Control's operations are.
pub(crate) const PREFIX: &str = "/v20180820/";

/// The account's Block Public Access settings.
pub(crate) const PUBLIC_ACCESS_BLOCK: &str = "/v20180820/configuration/publicAccessBlock";

/// The header that names the account.
pub(crate) const ACCOUNT_HEADER: &str = "x-amz-account-id";

/// S3 Control's XML namespace.
const NAMESPACE: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";

/// The largest settings body accepted: four booleans, with room for whitespace.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// An S3 Control error, which S3 Control wraps in `ErrorResponse` (unlike S3's).
pub(crate) fn error_response(err: &S3Error) -> S3Response<Body> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut xml = Vec::new();
    let mut s = Serializer::new(&mut xml);
    let written = s.decl().and_then(|()| {
        s.element("ErrorResponse", |s| {
            s.element("Error", |s| {
                s.content("Code", err.code().as_str())?;
                s.content("Message", err.message().unwrap_or_default())
            })?;
            s.content("RequestId", request_id.as_str())
        })
    });
    debug_assert!(written.is_ok(), "writing to a Vec can't fail");
    let mut response = S3Response::new(Body::from(xml));
    response.status = Some(
        err.status_code()
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
    );
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    if let Ok(id) = HeaderValue::from_str(&request_id) {
        response.headers.insert("x-amz-request-id", id);
    }
    response
}

/// Refuses a request for another account than the drive's.
pub(crate) fn check_account(headers: &HeaderMap, account: &str) -> S3Result<()> {
    let named = headers.get(ACCOUNT_HEADER).and_then(|v| v.to_str().ok());
    if named == Some(account) {
        Ok(())
    } else {
        Err(s3s::s3_error!(
            AccessDenied,
            "Access Denied: x-amz-account-id doesn't name this drive's account"
        ))
    }
}

pub(crate) async fn get_public_access_block(store: &Store) -> S3Result<S3Response<Body>> {
    let block = store
        .account_public_access_block()
        .await
        .s3()?
        .ok_or_else(no_public_access_block)?;
    let mut xml = Vec::new();
    let mut s = Serializer::new(&mut xml);
    s.decl()
        .and_then(|()| {
            s.element_with_ns("PublicAccessBlockConfiguration", NAMESPACE, |s| {
                block_to_dto(block).serialize_content(s)
            })
        })
        .map_err(S3Error::internal_error)?;
    let mut response = S3Response::new(Body::from(xml));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    Ok(response)
}

pub(crate) async fn put_public_access_block(
    store: &Store,
    rules: &Rules,
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let body = signed_body(&mut req, MAX_BODY_BYTES)
        .await
        .map_err(s3_refusal)?;
    let config = dto::PublicAccessBlockConfiguration::deserialize(&mut Deserializer::new(&body))
        .map_err(|_| {
            S3Error::with_message(
                S3ErrorCode::MalformedXML,
                "The body must be a PublicAccessBlockConfiguration.",
            )
        })?;
    store
        .set_account_public_access_block(Some(block_from_dto(&config)))
        .await
        .s3()?;
    rules.forget_all();
    Ok(S3Response::new(Body::empty()))
}

pub(crate) async fn delete_public_access_block(
    store: &Store,
    rules: &Rules,
) -> S3Result<S3Response<Body>> {
    store.set_account_public_access_block(None).await.s3()?;
    rules.forget_all();
    Ok(S3Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_drive_account_is_served() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(ACCOUNT_HEADER, HeaderValue::from_str(value).unwrap());
            headers
        };
        assert!(check_account(&with("123456789012"), "123456789012").is_ok());
        for other in ["210987654321", "123456789012 ", ""] {
            let err = check_account(&with(other), "123456789012").unwrap_err();
            assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{other:?}");
        }
        assert!(check_account(&HeaderMap::new(), "123456789012").is_err());
    }
}
