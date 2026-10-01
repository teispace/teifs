//! SAML providers: the identity providers a role's trust policy can name as `Federated`
//! for `AssumeRoleWithSAML`, with their metadata and the private keys that decrypt
//! their assertions.

use super::{
    ApiError, On, Out, Resource, Run, answer, done, paged, truncation, with_request_tags, xml::Xml,
};
use crate::{NewSamlProvider, SamlProviderUpdate};

/// The assertion encryption modes AWS has.
const MODES: &[&str] = &["Required", "Allowed"];

/// `name` of `value`, which must have `min..=max` characters. A secret's value is never
/// repeated in the error, nor a document's (which may be megabytes).
fn length<'p>(
    name: &str,
    value: &'p str,
    min: usize,
    max: usize,
    shown: bool,
) -> Result<&'p str, ApiError> {
    let n = value.chars().count();
    if (min..=max).contains(&n) {
        return Ok(value);
    }
    let constraint = if n < min {
        format!("Member must have length greater than or equal to {min}")
    } else {
        format!("Member must have length less than or equal to {max}")
    };
    if shown {
        return Err(ApiError::constraint(name, value, &constraint));
    }
    Err(ApiError::validation(format!(
        "1 validation error detected: Value at '{}' failed to satisfy constraint: {constraint}",
        super::camel(name)
    )))
}

/// `SAMLProviderArn`: 20 to 2048 characters, as AWS allows.
fn arn<'p>(r: &'p Run<'_>) -> Result<&'p str, ApiError> {
    length(
        "SAMLProviderArn",
        r.p.required("SAMLProviderArn")?,
        20,
        2048,
        true,
    )
}

/// The provider `SAMLProviderArn` names, and its ARN.
fn named<'p>(r: &'p Run<'_>) -> Result<(&'p str, Resource), ApiError> {
    let arn = arn(r)?;
    Ok((arn, r.saml_provider(arn)))
}

fn metadata(value: &str) -> Result<&str, ApiError> {
    length("SAMLMetadataDocument", value, 1000, 10_000_000, false)
}

fn private_key(value: &str) -> Result<&str, ApiError> {
    length("AddPrivateKey", value, 1, 16_384, false)
}

fn tags_xml(x: &mut Xml, tags: &[(String, String)]) {
    if !tags.is_empty() {
        x.tags(tags);
    }
}

pub(super) fn create(r: &Run<'_>) -> Out {
    let name = length("Name", r.p.required("Name")?, 1, 128, true)?;
    let document = metadata(r.p.required("SAMLMetadataDocument")?)?;
    let encryption = r.p.choice("AssertionEncryptionMode", MODES)?;
    let key = r.p.optional("AddPrivateKey").map(private_key).transpose()?;
    let tags = r.p.tags()?;
    let provider = Resource {
        on: On::SamlProvider,
        arn: format!("arn:aws:iam::{}:saml-provider/{name}", r.account),
        name: name.to_owned(),
        path: String::new(),
        tags: Vec::new(),
        boundary: None,
    };
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:CreateSAMLProvider", &provider, &context)?;
    if !tags.is_empty() {
        r.check_with("iam:TagSAMLProvider", &provider, &context)?;
    }
    let provider = r.iam.create_saml_provider(&NewSamlProvider {
        name,
        metadata: document,
        encryption,
        private_key: key,
        tags: &tags,
    })?;
    answer(|x| {
        x.text("SAMLProviderArn", &provider.arn);
        tags_xml(x, &provider.tags);
    })
}

pub(super) fn get(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    r.check("iam:GetSAMLProvider", &provider)?;
    let provider = r.iam.saml_provider(arn)?;
    answer(|x| {
        x.text("SAMLProviderUUID", &provider.uuid)
            .text("SAMLMetadataDocument", &provider.metadata)
            .date("CreateDate", provider.created_ms)
            .date("ValidUntil", provider.valid_until_ms)
            .maybe("AssertionEncryptionMode", provider.encryption);
        if !provider.keys.is_empty() {
            x.members("PrivateKeyList", &provider.keys, |x, (id, added)| {
                x.text("KeyId", id).date("Timestamp", *added);
            });
        }
        tags_xml(x, &provider.tags);
    })
}

pub(super) fn list(r: &Run<'_>) -> Out {
    r.check("iam:ListSAMLProviders", &Run::any())?;
    let providers = r.iam.saml_providers()?;
    answer(|x| {
        x.members("SAMLProviderList", &providers, |x, p| {
            x.text("Arn", &p.arn)
                .date("ValidUntil", p.valid_until_ms)
                .date("CreateDate", p.created_ms);
        });
    })
}

pub(super) fn update(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let document =
        r.p.optional("SAMLMetadataDocument")
            .map(metadata)
            .transpose()?;
    let encryption = r.p.choice("AssertionEncryptionMode", MODES)?;
    let add_key = r.p.optional("AddPrivateKey").map(private_key).transpose()?;
    let remove_key =
        r.p.optional("RemovePrivateKey")
            .map(|id| length("RemovePrivateKey", id, 22, 64, true))
            .transpose()?;
    r.check("iam:UpdateSAMLProvider", &provider)?;
    r.iam.update_saml_provider(
        arn,
        &SamlProviderUpdate {
            metadata: document,
            encryption,
            add_key,
            remove_key,
        },
    )?;
    let arn = r.iam.saml_provider(arn)?.arn;
    answer(|x| {
        x.text("SAMLProviderArn", &arn);
    })
}

pub(super) fn delete(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    r.check("iam:DeleteSAMLProvider", &provider)?;
    r.iam.delete_saml_provider(arn)?;
    done()
}

pub(super) fn tag(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let tags = r.p.tags()?;
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:TagSAMLProvider", &provider, &context)?;
    r.iam.tag_saml_provider(arn, &tags)?;
    done()
}

pub(super) fn untag(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let keys = r.p.list("TagKeys")?;
    let context = r.context().with_tag_keys(keys.iter().copied());
    r.check_with("iam:UntagSAMLProvider", &provider, &context)?;
    let keys: Vec<String> = keys.into_iter().map(str::to_owned).collect();
    r.iam.untag_saml_provider(arn, &keys)?;
    done()
}

pub(super) fn list_tags(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let page = r.page()?;
    r.check("iam:ListSAMLProviderTags", &provider)?;
    let (tags, marker) = paged(r.iam.saml_provider(arn)?.tags, &page, |(k, _)| {
        k.to_ascii_lowercase()
    });
    answer(|x| {
        x.tags(&tags);
        truncation(x, marker.as_deref());
    })
}
