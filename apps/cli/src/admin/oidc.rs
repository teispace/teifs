//! `teifs admin oidc`: the account's OpenID Connect providers, whose ID tokens (a CI
//! job's, a Kubernetes service account's, a company's single sign-on) `teifs sts
//! assume-web` and the AWS SDKs exchange for temporary credentials.

use aws_sdk_iam::{Client, types::Tag};
use clap::Subcommand;
use serde_json::json;

use crate::{
    error::{Error, Kind},
    ui,
    units::{date, from_ms},
};

/// The tag that lets a provider's tokens name the account's managed policies, as MinIO
/// has it (the server's `teifs:policy-claim`).
const POLICY_CLAIM_TAG: &str = "teifs:policy-claim";

#[derive(Subcommand)]
pub enum OidcAction {
    /// Add a provider: the issuer URL its tokens name, and the audiences they may be for.
    Add {
        /// The server's alias.
        alias: String,
        /// The provider's URL, like `https://token.actions.githubusercontent.com`.
        url: String,
        /// An audience (`aud`) its tokens may be for (repeatable); GitHub Actions' for
        /// AWS is `sts.amazonaws.com`.
        #[arg(long = "client-id", value_name = "ID", required = true)]
        client_ids: Vec<String>,
        /// The SHA-1 thumbprint of a certificate to trust for it, when the system
        /// doesn't trust its certificate (repeatable).
        #[arg(long = "thumbprint", value_name = "HEX")]
        thumbprints: Vec<String>,
        /// Let its tokens name the account's managed policies in this claim (`policy`
        /// if not given), for credentials without a role, as MinIO has it.
        #[arg(long, value_name = "CLAIM", num_args = 0..=1, default_missing_value = "")]
        policy_claim: Option<String>,
    },
    /// List the providers.
    Ls {
        /// The server's alias.
        alias: String,
    },
    /// Delete a provider (asks first): its tokens get no credentials from now on.
    Rm {
        /// The server's alias.
        alias: String,
        /// The provider: its URL, host or ARN.
        provider: String,
    },
}

impl OidcAction {
    fn alias(&self) -> &str {
        match self {
            Self::Add { alias, .. } | Self::Ls { alias } | Self::Rm { alias, .. } => alias,
        }
    }
}

pub async fn run(aliases: &crate::client::alias::Aliases, action: OidcAction) -> Result<(), Error> {
    let server = super::alias(aliases, action.alias())?.0.clone();
    let iam = super::iam(&server);
    match action {
        OidcAction::Add {
            url,
            client_ids,
            thumbprints,
            policy_claim,
            ..
        } => {
            let tags = policy_claim
                .as_ref()
                .map(|claim| {
                    Tag::builder()
                        .key(POLICY_CLAIM_TAG)
                        .value(claim)
                        .build()
                        .map_err(|e| Error::usage(e.to_string()))
                })
                .transpose()?;
            let created = iam
                .create_open_id_connect_provider()
                .url(&url)
                .set_client_id_list(Some(client_ids.clone()))
                .set_thumbprint_list((!thumbprints.is_empty()).then_some(thumbprints))
                .set_tags(tags.map(|t| vec![t]))
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't add a provider for {url}"), &e))?;
            let arn = created.open_id_connect_provider_arn().unwrap_or_default();
            let claim = policy_claim.map(|c| if c.is_empty() { "policy".to_owned() } else { c });
            ui::done(format!("Added OpenID Connect provider {arn}"), || {
                json!({
                    "type": "oidcProvider", "arn": arn, "url": url, "clientIds": client_ids,
                    "policyClaim": claim,
                })
            });
            if let Some(claim) = claim {
                ui::note(format!(
                    "Its tokens' {claim} claim names the policies of sessions without a role"
                ));
            }
            ui::note(
                "Trust it in a role: teifs admin role add ALIAS NAME --trust oidc:HOST --sub …",
            );
            Ok(())
        }
        OidcAction::Ls { .. } => list(&iam).await,
        OidcAction::Rm { provider, .. } => {
            let arn = find(&iam, &provider).await?;
            if !ui::confirm(
                &format!("Delete {arn}? Its tokens get no credentials from now on."),
                "add --yes to delete it",
            )? {
                return Err(Error::general("nothing was deleted").shown());
            }
            iam.delete_open_id_connect_provider()
                .open_id_connect_provider_arn(&arn)
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't delete {arn}"), &e))?;
            ui::done(
                format!("Deleted {arn}"),
                || json!({"type": "oidcProviderDeleted", "arn": arn}),
            );
            Ok(())
        }
    }
}

/// Every provider's ARN.
async fn arns(iam: &Client) -> Result<Vec<String>, Error> {
    let providers = iam
        .list_open_id_connect_providers()
        .send()
        .await
        .map_err(|e| Error::s3("can't list OpenID Connect providers", &e))?;
    Ok(providers
        .open_id_connect_provider_list()
        .iter()
        .filter_map(|p| p.arn().map(str::to_owned))
        .collect())
}

/// The ARN of the provider `given` names: its ARN, URL or host.
async fn find(iam: &Client, given: &str) -> Result<String, Error> {
    if given.starts_with("arn:") {
        return Ok(given.to_owned());
    }
    let host = given.split_once("://").map_or(given, |(_, h)| h);
    let host = host.trim_end_matches('/');
    let suffix = format!(":oidc-provider/{host}");
    arns(iam)
        .await?
        .into_iter()
        .find(|arn| arn.ends_with(&suffix))
        .ok_or_else(|| {
            Error::new(
                Kind::NotFound,
                format!("there's no OpenID Connect provider for {host}"),
            )
            .with_hint("see `teifs admin oidc ls`")
        })
}

async fn list(iam: &Client) -> Result<(), Error> {
    let mut table = ui::Table::new(&[
        "URL",
        "CLIENT IDS",
        "THUMBPRINTS",
        "POLICY CLAIM",
        "CREATED",
    ]);
    let mut records = Vec::new();
    for arn in arns(iam).await? {
        let provider = iam
            .get_open_id_connect_provider()
            .open_id_connect_provider_arn(&arn)
            .send()
            .await
            .map_err(|e| Error::s3(format_args!("can't read {arn}"), &e))?;
        let url = provider.url().unwrap_or_default();
        let claim = provider
            .tags()
            .iter()
            .find(|t| t.key().eq_ignore_ascii_case(POLICY_CLAIM_TAG))
            .map(|t| {
                if t.value().is_empty() {
                    "policy"
                } else {
                    t.value()
                }
            });
        let created = provider
            .create_date()
            .and_then(|d| d.to_millis().ok())
            .unwrap_or_default();
        table.row(vec![
            url.to_owned(),
            provider.client_id_list().join(", "),
            provider.thumbprint_list().len().to_string(),
            claim.unwrap_or_default().to_owned(),
            date(from_ms(created)),
        ]);
        records.push(json!({
            "type": "oidcProvider",
            "arn": arn,
            "url": url,
            "clientIds": provider.client_id_list(),
            "thumbprints": provider.thumbprint_list(),
            "policyClaim": claim,
            "createdMs": created,
        }));
    }
    ui::rows(
        &table,
        &records,
        "No OpenID Connect providers yet. Add one with `teifs admin oidc add`.",
    );
    Ok(())
}
