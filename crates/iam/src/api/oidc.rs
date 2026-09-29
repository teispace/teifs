//! OpenID Connect providers: the identity providers a role's trust policy can name as
//! `Federated`, with the audiences and certificate thumbprints they're trusted with.

use super::{
    ApiError, On, Out, Resource, Run, answer, done, paged, truncation, with_request_tags, xml::Xml,
};
use crate::NewOidcProvider;

/// `OpenIDConnectProviderArn`: 20 to 2048 characters, as AWS allows.
fn arn<'p>(r: &'p Run<'_>) -> Result<&'p str, ApiError> {
    let arn = r.p.required("OpenIDConnectProviderArn")?;
    if !(20..=2048).contains(&arn.chars().count()) {
        return Err(ApiError::constraint(
            "OpenIDConnectProviderArn",
            arn,
            "Member must have length between 20 and 2048",
        ));
    }
    Ok(arn)
}

/// The provider `OpenIDConnectProviderArn` names, and its ARN.
fn named<'p>(r: &'p Run<'_>) -> Result<(&'p str, Resource), ApiError> {
    let arn = arn(r)?;
    Ok((arn, r.oidc_provider(arn)))
}

/// A list parameter as owned strings.
fn owned(r: &Run<'_>, name: &str) -> Result<Vec<String>, ApiError> {
    Ok(r.p.list(name)?.into_iter().map(str::to_owned).collect())
}

fn tags_xml(x: &mut Xml, tags: &[(String, String)]) {
    if !tags.is_empty() {
        x.tags(tags);
    }
}

pub(super) fn create(r: &Run<'_>) -> Out {
    let url = r.p.required("Url")?;
    let client_ids = owned(r, "ClientIDList")?;
    let thumbprints = owned(r, "ThumbprintList")?;
    let tags = r.p.tags()?;
    let name = url.split_once("://").map_or(url, |(_, name)| name);
    let provider = Resource {
        on: On::OidcProvider,
        arn: format!("arn:aws:iam::{}:oidc-provider/{name}", r.account),
        name: name.to_owned(),
        path: String::new(),
        tags: Vec::new(),
        boundary: None,
    };
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:CreateOpenIDConnectProvider", &provider, &context)?;
    if !tags.is_empty() {
        r.check_with("iam:TagOpenIDConnectProvider", &provider, &context)?;
    }
    let provider = r.iam.create_oidc_provider(&NewOidcProvider {
        url,
        client_ids: &client_ids,
        thumbprints: &thumbprints,
        tags: &tags,
    })?;
    answer(|x| {
        x.text("OpenIDConnectProviderArn", &provider.arn);
        tags_xml(x, &provider.tags);
    })
}

pub(super) fn get(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    r.check("iam:GetOpenIDConnectProvider", &provider)?;
    let provider = r.iam.oidc_provider(arn)?;
    answer(|x| {
        x.list("ThumbprintList", &provider.thumbprints)
            .date("CreateDate", provider.created_ms)
            .list("ClientIDList", &provider.client_ids)
            .text(
                "Url",
                provider
                    .url
                    .split_once("://")
                    .map_or(&*provider.url, |(_, name)| name),
            );
        tags_xml(x, &provider.tags);
    })
}

pub(super) fn list(r: &Run<'_>) -> Out {
    r.check("iam:ListOpenIDConnectProviders", &Run::any())?;
    let providers = r.iam.oidc_providers()?;
    answer(|x| {
        x.members("OpenIDConnectProviderList", &providers, |x, p| {
            x.text("Arn", &p.arn);
        });
    })
}

pub(super) fn delete(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    r.check("iam:DeleteOpenIDConnectProvider", &provider)?;
    r.iam.delete_oidc_provider(arn)?;
    done()
}

/// `ClientID`: 1 to 255 characters.
fn client_id<'p>(r: &'p Run<'_>) -> Result<&'p str, ApiError> {
    let id = r.p.required("ClientID")?;
    if id.chars().count() > 255 {
        return Err(ApiError::constraint(
            "ClientID",
            id,
            "Member must have length less than or equal to 255",
        ));
    }
    Ok(id)
}

pub(super) fn add_client_id(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let id = client_id(r)?;
    r.check("iam:AddClientIDToOpenIDConnectProvider", &provider)?;
    r.iam.add_client_id(arn, id)?;
    done()
}

pub(super) fn remove_client_id(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let id = client_id(r)?;
    r.check("iam:RemoveClientIDFromOpenIDConnectProvider", &provider)?;
    r.iam.remove_client_id(arn, id)?;
    done()
}

pub(super) fn update_thumbprint(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let thumbprints = owned(r, "ThumbprintList")?;
    r.check("iam:UpdateOpenIDConnectProviderThumbprint", &provider)?;
    r.iam.set_thumbprints(arn, &thumbprints)?;
    done()
}

pub(super) fn tag(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let tags = r.p.tags()?;
    let context = with_request_tags(r.context(), &tags);
    r.check_with("iam:TagOpenIDConnectProvider", &provider, &context)?;
    r.iam.tag_oidc_provider(arn, &tags)?;
    done()
}

pub(super) fn untag(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let keys = r.p.list("TagKeys")?;
    let context = r.context().with_tag_keys(keys.iter().copied());
    r.check_with("iam:UntagOpenIDConnectProvider", &provider, &context)?;
    let keys: Vec<String> = keys.into_iter().map(str::to_owned).collect();
    r.iam.untag_oidc_provider(arn, &keys)?;
    done()
}

pub(super) fn list_tags(r: &Run<'_>) -> Out {
    let (arn, provider) = named(r)?;
    let page = r.page()?;
    r.check("iam:ListOpenIDConnectProviderTags", &provider)?;
    let (tags, marker) = paged(r.iam.oidc_provider(arn)?.tags, &page, |(k, _)| {
        k.to_ascii_lowercase()
    });
    answer(|x| {
        x.tags(&tags);
        truncation(x, marker.as_deref());
    })
}
