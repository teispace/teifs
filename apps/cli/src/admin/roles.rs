//! `teifs admin role`: IAM roles in one step — whom the role trusts (the account, a
//! user, a GitHub Actions workflow, another OpenID Connect provider's subjects, or a trust
//! policy file) and what it may do. It speaks AWS's IAM API, as `aws iam` does; `teifs
//! sts assume` then gets its sessions.

use std::time::Duration;

use aws_sdk_iam::Client;
use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::policy::{POLICY_NAME, PolicyArgs};
use crate::{
    client::alias::{Alias, percent_decode},
    error::{Error, Kind},
    ui,
    units::{date, from_ms, parse_duration},
};

/// GitHub Actions' OpenID Connect provider, and the audience AWS's action asks for.
const GITHUB: &str = "token.actions.githubusercontent.com";
const GITHUB_AUDIENCE: &str = "sts.amazonaws.com";

#[derive(Subcommand)]
pub enum RoleAction {
    /// Add a role: whom it trusts and what it may do.
    Add {
        /// The server's alias.
        alias: String,
        /// The role's name.
        name: String,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        policy: PolicyArgs,
        /// The longest session it gives, from `1h` (the default) to `12h`.
        #[arg(long, value_parser = parse_duration)]
        max_session: Option<Duration>,
        /// What it's for.
        #[arg(long)]
        description: Option<String>,
    },
    /// List the roles with whom they trust and their policies.
    Ls {
        /// The server's alias.
        alias: String,
    },
    /// Delete a role with its policies (asks first); its sessions stop working.
    Rm {
        /// The server's alias.
        alias: String,
        /// The role's name.
        name: String,
    },
    /// Replace the policy `role add` gave a role.
    Policy {
        /// The server's alias.
        alias: String,
        /// The role's name.
        name: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Replace whom a role trusts.
    Trust {
        /// The server's alias.
        alias: String,
        /// The role's name.
        name: String,
        #[command(flatten)]
        trust: TrustArgs,
    },
}

/// Whom a role trusts.
#[derive(Args)]
pub struct TrustArgs {
    /// `account` (the account's users and roles whose policies allow it), `user:NAME`,
    /// `github:OWNER/REPO[:SUBJECT]` (a GitHub Actions workflow: `github:acme/site`, or
    /// `github:acme/site:ref:refs/heads/main` for one branch), `oidc:HOST` (tokens of the
    /// account's OpenID Connect provider for HOST, with `--sub`), or a trust policy file.
    #[arg(long)]
    trust: String,
    /// For `oidc:`, the subjects (`sub`) it trusts; `*` matches any characters.
    #[arg(long)]
    sub: Option<String>,
    /// For `oidc:`, the audience (`aud`) tokens must be for, when the provider has more
    /// than one client id.
    #[arg(long)]
    aud: Option<String>,
}

impl RoleAction {
    fn alias(&self) -> &str {
        match self {
            Self::Add { alias, .. }
            | Self::Ls { alias }
            | Self::Rm { alias, .. }
            | Self::Policy { alias, .. }
            | Self::Trust { alias, .. } => alias,
        }
    }
}

pub async fn run(aliases: &crate::client::alias::Aliases, action: RoleAction) -> Result<(), Error> {
    let server = super::alias(aliases, action.alias())?.0.clone();
    let iam = super::iam(&server);
    match action {
        RoleAction::Add {
            name,
            trust,
            policy,
            max_session,
            description,
            ..
        } => {
            // Everything that can be checked here is, before anything changes.
            let document = policy.document()?;
            let max_session = max_session
                .map(|d| {
                    i32::try_from(d.as_secs())
                        .map_err(|_| Error::usage("--max-session is at most 12h"))
                })
                .transpose()?;
            let (trusted, trust) = trust.document(&iam, &server).await?;
            iam.create_role()
                .role_name(&name)
                .assume_role_policy_document(&trust)
                .set_description(description)
                .set_max_session_duration(max_session)
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't add role {name}"), &e))?;
            if let Err(err) = put_policy(&iam, &name, &document).await {
                if let Err(e) = delete_role(&iam, &name).await {
                    ui::warn(format!(
                        "role {name} was added but not finished: {}",
                        e.message
                    ));
                }
                return Err(err);
            }
            ui::done(
                format!(
                    "Added role {name}, trusting {trusted}, with the {} policy",
                    policy.policy
                ),
                || {
                    json!({
                        "type": "role", "role": name, "trusts": trusted,
                        "policy": policy.policy,
                    })
                },
            );
            ui::note(format!(
                "Get a session: teifs sts assume ALIAS {name} --save-alias NEW"
            ));
            Ok(())
        }
        RoleAction::Ls { .. } => list(&iam).await,
        RoleAction::Rm { name, .. } => {
            if !ui::confirm(
                &format!("Delete role {name}? Its sessions stop working at once."),
                "add --yes to delete it",
            )? {
                return Err(Error::general("nothing was deleted").shown());
            }
            delete_role(&iam, &name).await?;
            ui::done(
                format!("Deleted role {name}"),
                || json!({"type": "roleDeleted", "role": name}),
            );
            Ok(())
        }
        RoleAction::Policy { name, policy, .. } => {
            put_policy(&iam, &name, &policy.document()?).await?;
            ui::done(
                format!("Gave role {name} the {} policy", policy.policy),
                || json!({"type": "rolePolicy", "role": name, "policy": policy.policy}),
            );
            Ok(())
        }
        RoleAction::Trust { name, trust, .. } => {
            let (trusted, document) = trust.document(&iam, &server).await?;
            iam.update_assume_role_policy()
                .role_name(&name)
                .policy_document(document)
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't change whom {name} trusts"), &e))?;
            ui::done(
                format!("Role {name} now trusts {trusted}"),
                || json!({"type": "roleTrust", "role": name, "trusts": trusted}),
            );
            Ok(())
        }
    }
}

impl TrustArgs {
    /// Whom the trust policy trusts, in words, and the policy.
    async fn document(&self, iam: &Client, server: &Alias) -> Result<(String, String), Error> {
        let (kind, rest) = self.trust.split_once(':').unwrap_or((&self.trust, ""));
        let web = matches!(kind, "oidc" | "github");
        if !web && (self.sub.is_some() || self.aud.is_some()) {
            return Err(Error::usage("--sub and --aud are for oidc: trust")
                .with_hint("use --trust oidc:HOST"));
        }
        let aws = |principal: &str| {
            trust_policy(
                &json!({"AWS": principal}),
                &json!(["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]),
                None,
            )
        };
        Ok(match (kind, rest) {
            ("account", "") => {
                let account = crate::sts::account(server).await?;
                (
                    "the account".to_owned(),
                    aws(&format!("arn:aws:iam::{account}:root")),
                )
            }
            ("user", name) if !name.is_empty() => {
                let user = iam
                    .get_user()
                    .user_name(name)
                    .send()
                    .await
                    .map_err(|e| Error::s3(format_args!("can't find user {name}"), &e))?;
                let arn = user.user().map(|u| u.arn().to_owned()).unwrap_or_default();
                (format!("user {name}"), aws(&arn))
            }
            ("github", repo) if repo.contains('/') => {
                let (repo, subject) = repo.split_once(':').map_or((repo, "*"), |(r, s)| (r, s));
                let sub = format!("repo:{repo}:{subject}");
                let provider = provider_arn(iam, GITHUB).await?;
                (
                    format!("GitHub Actions workflows of {repo}"),
                    web_trust(&provider, GITHUB, &sub, GITHUB_AUDIENCE),
                )
            }
            ("oidc", host) if !host.is_empty() => {
                let host = host.split_once("://").map_or(host, |(_, h)| h);
                let Some(sub) = &self.sub else {
                    return Err(Error::usage("oidc: trust needs --sub")
                        .with_hint("name the subjects it trusts, or --sub '*' for all of them"));
                };
                let provider = provider_arn(iam, host).await?;
                let aud = match &self.aud {
                    Some(aud) => aud.clone(),
                    None => only_client_id(iam, &provider).await?,
                };
                (
                    format!("{host} subjects {sub}"),
                    web_trust(&provider, host, sub, &aud),
                )
            }
            _ => {
                let document = std::fs::read_to_string(&self.trust).map_err(|e| {
                    let kind = if e.kind() == std::io::ErrorKind::NotFound {
                        Kind::NotFound
                    } else {
                        Kind::General
                    };
                    Error::new(
                        kind,
                        format!(
                            "`{}` isn't account, user:NAME, github:OWNER/REPO, oidc:HOST or a \
                             trust policy file: {e}",
                            self.trust
                        ),
                    )
                })?;
                (format!("the principals in {}", self.trust), document)
            }
        })
    }
}

/// A trust policy that lets `principal` do `actions`, if `condition` holds.
fn trust_policy(principal: &Value, actions: &Value, condition: Option<Value>) -> String {
    let mut statement = json!({"Effect": "Allow", "Principal": principal, "Action": actions});
    if let Some(condition) = condition {
        statement["Condition"] = condition;
    }
    json!({"Version": "2012-10-17", "Statement": [statement]}).to_string()
}

/// A trust policy for the web identities `sub` (a pattern) of the provider `provider`
/// (its ARN, for `host`), in tokens for `aud`.
fn web_trust(provider: &str, host: &str, sub: &str, aud: &str) -> String {
    let matching = if sub.contains(['*', '?']) {
        "StringLike"
    } else {
        "StringEquals"
    };
    let mut condition = json!({"StringEquals": {format!("{host}:aud"): aud}});
    condition[matching][format!("{host}:sub")] = json!(sub);
    trust_policy(
        &json!({"Federated": provider}),
        &json!("sts:AssumeRoleWithWebIdentity"),
        Some(condition),
    )
}

/// The ARN of the account's OpenID Connect provider for `host`.
async fn provider_arn(iam: &Client, host: &str) -> Result<String, Error> {
    let providers = iam
        .list_open_id_connect_providers()
        .send()
        .await
        .map_err(|e| Error::s3("can't list OpenID Connect providers", &e))?;
    let suffix = format!(":oidc-provider/{host}");
    providers
        .open_id_connect_provider_list()
        .iter()
        .filter_map(|p| p.arn())
        .find(|arn| arn.ends_with(&suffix))
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                Kind::NotFound,
                format!("there's no OpenID Connect provider for {host}"),
            )
            .with_hint(format!(
                "add it first: teifs admin oidc add ALIAS https://{host} --client-id {}",
                if host == GITHUB {
                    GITHUB_AUDIENCE
                } else {
                    "CLIENT_ID"
                }
            ))
        })
}

/// The provider's client id, when it has only one.
async fn only_client_id(iam: &Client, provider: &str) -> Result<String, Error> {
    let found = iam
        .get_open_id_connect_provider()
        .open_id_connect_provider_arn(provider)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't read {provider}"), &e))?;
    match found.client_id_list() {
        [only] => Ok(only.clone()),
        [] => Err(Error::usage(format!(
            "{provider} has no client ids, so it accepts no token"
        ))
        .with_hint("add one: aws iam add-client-id-to-open-id-connect-provider")),
        _ => Err(Error::usage(format!("{provider} has several client ids"))
            .with_hint("name the one to trust with --aud")),
    }
}

async fn put_policy(iam: &Client, name: &str, document: &str) -> Result<(), Error> {
    iam.put_role_policy()
        .role_name(name)
        .policy_name(POLICY_NAME)
        .policy_document(document)
        .send()
        .await
        .map_err(|e| Error::s3(format_args!("can't set {name}'s policy"), &e))?;
    Ok(())
}

/// The names of a role's policies: inline, then attached.
async fn policy_names(iam: &Client, name: &str) -> Result<(Vec<String>, Vec<String>), Error> {
    let what = format!("can't list {name}'s policies");
    let (inline, attached) = tokio::try_join!(
        async {
            iam.list_role_policies()
                .role_name(name)
                .send()
                .await
                .map_err(|e| Error::s3(&what, &e))
        },
        async {
            iam.list_attached_role_policies()
                .role_name(name)
                .send()
                .await
                .map_err(|e| Error::s3(&what, &e))
        },
    )?;
    Ok((
        inline.policy_names().to_vec(),
        attached
            .attached_policies()
            .iter()
            .filter_map(|p| p.policy_arn().map(str::to_owned))
            .collect(),
    ))
}

/// Deletes a role and first what IAM wants gone before it: its policies.
async fn delete_role(iam: &Client, name: &str) -> Result<(), Error> {
    let what = format!("can't delete role {name}");
    let (inline, attached) = policy_names(iam, name).await?;
    for policy in inline {
        iam.delete_role_policy()
            .role_name(name)
            .policy_name(policy)
            .send()
            .await
            .map_err(|e| Error::s3(&what, &e))?;
    }
    for arn in attached {
        iam.detach_role_policy()
            .role_name(name)
            .policy_arn(arn)
            .send()
            .await
            .map_err(|e| Error::s3(&what, &e))?;
    }
    iam.delete_role()
        .role_name(name)
        .send()
        .await
        .map_err(|e| Error::s3(&what, &e))?;
    Ok(())
}

/// Whom a trust policy (as IAM answers it, URL-encoded) trusts, in short: `account`,
/// `user/alice`, `role/ci`, `oidc/host (sub pattern)`, `*`.
fn trusted(encoded: &str) -> Vec<String> {
    let text = percent_decode(encoded).unwrap_or_else(|_| encoded.to_owned());
    let Ok(policy) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let statements = match &policy["Statement"] {
        Value::Array(items) => items.clone(),
        single => vec![single.clone()],
    };
    let strings = |value: &Value| -> Vec<String> {
        match value {
            Value::String(s) => vec![s.clone()],
            Value::Array(items) => items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    };
    let mut out = Vec::new();
    for statement in statements.iter().filter(|s| s["Effect"] == "Allow") {
        let principal = &statement["Principal"];
        if principal == "*" {
            out.push("*".to_owned());
            continue;
        }
        for arn in strings(&principal["AWS"]) {
            let short = arn.split_once(":root").map_or_else(
                || {
                    arn.rsplit_once(':')
                        .map_or(arn.clone(), |(_, r)| r.to_owned())
                },
                |_| "account".to_owned(),
            );
            out.push(short);
        }
        for provider in strings(&principal["Federated"]) {
            let host = provider
                .split_once(":oidc-provider/")
                .map_or(provider.as_str(), |(_, h)| h);
            let sub = statement["Condition"]
                .as_object()
                .into_iter()
                .flat_map(|ops| ops.values())
                .find_map(|keys| keys.get(format!("{host}:sub")).map(strings))
                .map(|subs| format!(" ({})", subs.join(", ")))
                .unwrap_or_default();
            out.push(format!("oidc/{host}{sub}"));
        }
    }
    out
}

async fn list(iam: &Client) -> Result<(), Error> {
    let roles = iam
        .list_roles()
        .into_paginator()
        .items()
        .send()
        .collect::<Result<Vec<_>, _>>()
        .await
        .map_err(|e| Error::s3("can't list roles", &e))?;
    let mut table = ui::Table::new(&["ROLE", "TRUSTS", "POLICIES", "MAX SESSION", "CREATED"]);
    let mut records = Vec::with_capacity(roles.len());
    for role in &roles {
        let name = role.role_name();
        let (inline, attached) = policy_names(iam, name).await?;
        let policies: Vec<String> = inline
            .into_iter()
            .chain(
                attached
                    .iter()
                    .map(|arn| arn.rsplit('/').next().unwrap_or(arn).to_owned()),
            )
            .collect();
        let trusts = trusted(role.assume_role_policy_document().unwrap_or_default());
        let max_session = role.max_session_duration().unwrap_or(3600);
        let created = role.create_date().to_millis().unwrap_or_default();
        table.row(vec![
            name.to_owned(),
            trusts.join(", "),
            policies.join(", "),
            format!("{}h", f64::from(max_session) / 3600.0),
            date(from_ms(created)),
        ]);
        records.push(json!({
            "type": "role",
            "name": name,
            "arn": role.arn(),
            "trusts": trusts,
            "policies": policies,
            "maxSessionSeconds": max_session,
            "createdMs": created,
        }));
    }
    ui::rows(
        &table,
        &records,
        "No roles yet. Add one with `teifs admin role add`.",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_policies_are_summed_up() {
        let encoded = |v: &Value| {
            v.to_string()
                .replace('%', "%25")
                .replace('"', "%22")
                .replace(':', "%3A")
        };
        let policy = json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": [
                "arn:aws:iam::123456789012:root",
                "arn:aws:iam::123456789012:user/alice",
                "arn:aws:iam::123456789012:role/ci"]},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow",
             "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/idp.example.com"},
             "Action": "sts:AssumeRoleWithWebIdentity",
             "Condition": {"StringLike": {"idp.example.com:sub": "repo:acme/*"}}},
            {"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"},
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
        ]});
        assert_eq!(
            trusted(&encoded(&policy)),
            [
                "account",
                "user/alice",
                "role/ci",
                "oidc/idp.example.com (repo:acme/*)",
                "*"
            ]
        );
        assert!(trusted("not a policy").is_empty());
    }

    #[test]
    fn web_trusts_match_subjects_exactly_unless_they_have_wildcards() {
        let exact: Value =
            serde_json::from_str(&web_trust("P", "h", "repo:a/b:ref:x", "app")).unwrap();
        let condition = &exact["Statement"][0]["Condition"];
        assert_eq!(condition["StringEquals"]["h:sub"], "repo:a/b:ref:x");
        assert_eq!(condition["StringEquals"]["h:aud"], "app");
        let pattern: Value = serde_json::from_str(&web_trust("P", "h", "repo:a/*", "app")).unwrap();
        let condition = &pattern["Statement"][0]["Condition"];
        assert_eq!(condition["StringLike"]["h:sub"], "repo:a/*");
        assert_eq!(condition["StringEquals"]["h:aud"], "app");
        assert!(condition["StringEquals"].get("h:sub").is_none());
    }
}
