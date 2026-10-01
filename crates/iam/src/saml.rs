//! SAML 2.0 sign-in (`AssumeRoleWithSAML`): the account's SAML providers' metadata, and
//! the signed responses their users bring.

pub(crate) mod c14n;
pub(crate) mod dsig;
pub(crate) mod encryption;
pub(crate) mod metadata;
pub(crate) mod private_key;
pub(crate) mod response;
pub(crate) mod xml;
