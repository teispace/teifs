//! A SAML identity provider for tests: its metadata, the responses it signs, and private
//! keys that decrypt the assertions encrypted for a TeiFS server.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize};

/// A SAML identity provider that signs with a new RSA key: its issuer (`entityID`) and
/// its metadata document, naming its certificate.
pub struct SamlIdp {
    pub entity_id: String,
    pub metadata: String,
    pub key: KeyPair,
}

impl SamlIdp {
    pub fn new(entity_id: &str) -> Self {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let cert = CertificateParams::new(vec!["idp.example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let metadata = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor \
             xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
             xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{entity_id}\">\
             <md:IDPSSODescriptor \
             protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\
             <md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>\
             <ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>\
             </md:KeyDescriptor><md:SingleSignOnService \
             Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
             Location=\"https://idp.example.com/sso\"/></md:IDPSSODescriptor>\
             </md:EntityDescriptor>",
            STANDARD.encode(cert.der())
        );
        Self {
            entity_id: entity_id.to_owned(),
            metadata,
            key,
        }
    }

    /// A response saying `subject` signed in, to assume the role `role_arn` with the
    /// provider `provider_arn` as `session_name`: base64, as `AssumeRoleWithSAML` takes it.
    #[allow(dead_code, reason = "not every test binary signs responses")]
    pub fn response(
        &self,
        subject: &str,
        role_arn: &str,
        provider_arn: &str,
        session_name: &str,
    ) -> String {
        teifs_iam::saml_fake::response(
            &teifs_iam::saml_fake::Response {
                issuer: &self.entity_id,
                subject,
                roles: &[&format!("{role_arn},{provider_arn}")],
                session_name,
            },
            &self.key.serialize_der(),
        )
    }
}

/// A new RSA private key, in PEM, for decrypting assertions.
pub fn private_key_pem() -> String {
    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
        .unwrap()
        .serialize_pem()
}
