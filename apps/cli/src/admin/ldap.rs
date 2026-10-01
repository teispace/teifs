//! `teifs admin ldap policy`: the managed policies mapped to LDAP users and groups (as
//! `mc idp ldap policy`), which the sessions of users who sign in with the directory
//! (`teifs sts assume-ldap`) get.

use clap::{Args, Subcommand};
use serde_json::json;
use teifs_client::{LdapPolicyMapping, LdapPolicyRequest};

use crate::{error::Error, ui};

#[derive(Subcommand)]
pub enum LdapAction {
    /// Map managed policies to LDAP users and groups, or list and remove mappings.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand)]
pub enum PolicyAction {
    /// Map managed policies to a user's or a group's DN: their sessions get them at the
    /// next request.
    Attach(Change),
    /// Remove managed policies from a user's or a group's DN.
    Detach(Change),
    /// List the DNs with policies.
    Ls {
        /// The server's alias.
        alias: String,
        /// Only this user's DN.
        #[arg(long, value_name = "DN", conflicts_with = "group")]
        user: Option<String>,
        /// Only this group's DN.
        #[arg(long, value_name = "DN")]
        group: Option<String>,
    },
}

/// Whose policies change, and which.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("who").required(true).args(["user", "group"])))]
pub struct Change {
    /// The server's alias.
    alias: String,
    /// The managed policies: names or ARNs.
    #[arg(required = true)]
    policies: Vec<String>,
    /// The user's DN, like `uid=dillon,ou=people,dc=example,dc=com`.
    #[arg(long, value_name = "DN")]
    user: Option<String>,
    /// The group's DN, like `cn=engineers,ou=groups,dc=example,dc=com`.
    #[arg(long, value_name = "DN")]
    group: Option<String>,
}

pub async fn run(aliases: &crate::client::alias::Aliases, action: LdapAction) -> Result<(), Error> {
    let LdapAction::Policy { action } = action;
    match action {
        PolicyAction::Attach(change) => apply(aliases, change, true).await,
        PolicyAction::Detach(change) => apply(aliases, change, false).await,
        PolicyAction::Ls { alias, user, group } => {
            let client = super::client(aliases, &alias)?;
            let dn = user.as_deref().or(group.as_deref());
            let mappings = client
                .ldap_policies(dn)
                .await
                .map_err(|e| Error::admin("can't list the LDAP policy mappings", &e))?;
            list(&mappings, user.is_some(), group.is_some());
            Ok(())
        }
    }
}

async fn apply(
    aliases: &crate::client::alias::Aliases,
    change: Change,
    attach: bool,
) -> Result<(), Error> {
    let client = super::client(aliases, &change.alias)?;
    let request = LdapPolicyRequest {
        user: change.user,
        group: change.group,
        policies: change.policies,
    };
    let done = if attach {
        client.attach_ldap_policies(&request).await
    } else {
        client.detach_ldap_policies(&request).await
    }
    .map_err(|e| {
        let what = if attach { "attach" } else { "detach" };
        Error::admin(format_args!("can't {what} the policies"), &e)
    })?;
    let verb = if attach { "Attached" } else { "Detached" };
    let message = if done.changed.is_empty() {
        format!(
            "Nothing changed: {} {} has {}",
            done.entity,
            done.dn,
            policies(&done.policies)
        )
    } else {
        format!(
            "{verb} {} for {} {}; it has {}",
            done.changed.join(", "),
            done.entity,
            done.dn,
            policies(&done.policies)
        )
    };
    ui::done(message, || {
        json!({
            "type": "ldapPolicies", "dn": done.dn, "entity": done.entity,
            "changed": done.changed, "policies": done.policies,
        })
    });
    Ok(())
}

fn policies(names: &[String]) -> String {
    if names.is_empty() {
        "no policy now".to_owned()
    } else {
        names.join(", ")
    }
}

fn list(mappings: &[LdapPolicyMapping], users: bool, groups: bool) {
    let shown: Vec<&LdapPolicyMapping> = mappings
        .iter()
        .filter(|m| !users || m.entity == "user")
        .filter(|m| !groups || m.entity == "group")
        .collect();
    let mut table = ui::Table::new(&["ENTITY", "DN", "POLICIES"]);
    let mut records = Vec::new();
    for m in shown {
        table.row(vec![m.entity.clone(), m.dn.clone(), m.policies.join(", ")]);
        records.push(super::record("ldapPolicies", m));
    }
    ui::rows(
        &table,
        &records,
        "No LDAP user or group has policies: map some with `teifs admin ldap policy attach`",
    );
}
