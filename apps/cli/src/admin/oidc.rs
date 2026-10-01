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
/// The tag that gives a provider's clients MinIO's role policies (the server's
/// `teifs:role-policy`): the policies, separated by spaces.
const ROLE_POLICY_TAG: &str = "teifs:role-policy";

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
        /// Give every token of each client these managed policies when it names the
        /// client's role (`arn:minio:iam:::role/…`, shown after), as MinIO's
        /// `role_policy` (repeatable, or comma-separated).
        #[arg(long, value_name = "NAMES", value_delimiter = ',')]
        role_policy: Vec<String>,
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
            role_policy,
            ..
        } => {
            let role_policy: Vec<String> = role_policy
                .iter()
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect();
            let tag = |key: &str, value: &str| {
                Tag::builder()
                    .key(key)
                    .value(value)
                    .build()
                    .map_err(|e| Error::usage(e.to_string()))
            };
            let mut tags = Vec::new();
            if let Some(claim) = &policy_claim {
                tags.push(tag(POLICY_CLAIM_TAG, claim)?);
            }
            if !role_policy.is_empty() {
                tags.push(tag(ROLE_POLICY_TAG, &role_policy.join(" "))?);
            }
            let created = iam
                .create_open_id_connect_provider()
                .url(&url)
                .set_client_id_list(Some(client_ids.clone()))
                .set_thumbprint_list((!thumbprints.is_empty()).then_some(thumbprints))
                .set_tags((!tags.is_empty()).then_some(tags))
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't add a provider for {url}"), &e))?;
            let arn = created.open_id_connect_provider_arn().unwrap_or_default();
            let claim = policy_claim.map(|c| if c.is_empty() { "policy".to_owned() } else { c });
            let roles = roles(&client_ids, !role_policy.is_empty());
            ui::done(format!("Added OpenID Connect provider {arn}"), || {
                json!({
                    "type": "oidcProvider", "arn": arn, "url": url, "clientIds": client_ids,
                    "policyClaim": claim, "rolePolicy": role_policy, "roleArns": roles,
                })
            });
            if let Some(claim) = claim {
                ui::note(format!(
                    "Its tokens' {claim} claim names the policies of sessions without a role"
                ));
            }
            for (client, role) in &roles {
                ui::note(format!(
                    "Tokens for {client} get {} with RoleArn {role}",
                    role_policy.join(", ")
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

/// Each client's MinIO role, when the provider has role policies.
fn roles(
    client_ids: &[String],
    has_role_policy: bool,
) -> serde_json::Map<String, serde_json::Value> {
    client_ids
        .iter()
        .filter(|_| has_role_policy)
        .map(|client| (client.clone(), teifs_iam::openid_role_arn(client).into()))
        .collect()
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
        "ROLE POLICY",
        "CREATED",
    ]);
    let mut records = Vec::new();
    let mut role_notes = Vec::new();
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
        let role_policy: Vec<&str> = provider
            .tags()
            .iter()
            .find(|t| t.key().eq_ignore_ascii_case(ROLE_POLICY_TAG))
            .map(|t| t.value().split_whitespace().collect())
            .unwrap_or_default();
        let roles = roles(provider.client_id_list(), !role_policy.is_empty());
        role_notes.extend(roles.iter().map(|(client, role)| {
            format!(
                "{url} {client}: RoleArn {}",
                role.as_str().unwrap_or_default()
            )
        }));
        let created = provider
            .create_date()
            .and_then(|d| d.to_millis().ok())
            .unwrap_or_default();
        table.row(vec![
            url.to_owned(),
            provider.client_id_list().join(", "),
            provider.thumbprint_list().len().to_string(),
            claim.unwrap_or_default().to_owned(),
            role_policy.join(", "),
            date(from_ms(created)),
        ]);
        records.push(json!({
            "type": "oidcProvider",
            "arn": arn,
            "url": url,
            "clientIds": provider.client_id_list(),
            "thumbprints": provider.thumbprint_list(),
            "policyClaim": claim,
            "rolePolicy": role_policy,
            "roleArns": roles,
            "createdMs": created,
        }));
    }
    ui::rows(
        &table,
        &records,
        "No OpenID Connect providers yet. Add one with `teifs admin oidc add`.",
    );
    for note in role_notes {
        ui::note(note);
    }
    Ok(())
}
