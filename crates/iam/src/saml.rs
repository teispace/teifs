//! SAML 2.0 sign-in (`AssumeRoleWithSAML`): the account's SAML providers' metadata, and
//! the signed responses their users bring.

pub(crate) mod metadata;
pub(crate) mod private_key;
pub(crate) mod xml;
