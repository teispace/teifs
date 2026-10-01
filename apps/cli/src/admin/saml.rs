//! `teifs admin saml`: the account's SAML providers, whose signed responses (a company's
//! single sign-on: Okta, Microsoft Entra ID, Keycloak, AD FS) `AssumeRoleWithSAML`
//! exchanges for a role's temporary credentials.

use std::path::{Path, PathBuf};

use aws_sdk_iam::{Client, types::AssertionEncryptionModeType};
use clap::{Subcommand, ValueEnum};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Kind},
    ui,
    units::{date, from_ms},
};

/// Whether a provider's assertions must be encrypted.
#[derive(Clone, Copy, ValueEnum)]
pub enum Encryption {
    /// Only encrypted assertions are taken.
    Required,
    /// Encrypted and plain assertions are taken.
    Allowed,
}

impl From<Encryption> for AssertionEncryptionModeType {
    fn from(mode: Encryption) -> Self {
        match mode {
            Encryption::Required => Self::Required,
            Encryption::Allowed => Self::Allowed,
        }
    }
}

#[derive(Subcommand)]
pub enum SamlAction {
    /// Add a provider from its metadata document (the XML its administration exports).
    Add {
        /// The server's alias.
        alias: String,
        /// The provider's name: letters, digits and `_.-`.
        name: String,
        /// Its metadata document (`-` for standard input).
        #[arg(long, value_name = "FILE")]
        metadata: PathBuf,
        /// A private key (PEM) that decrypts its encrypted assertions.
        #[arg(long, value_name = "FILE")]
        private_key: Option<PathBuf>,
        /// Whether its assertions must be encrypted.
        #[arg(long, value_enum)]
        encryption: Option<Encryption>,
    },
    /// List the providers.
    Ls {
        /// The server's alias.
        alias: String,
    },
    /// Change a provider: its metadata, its private keys (two at most, to rotate them)
    /// or whether its assertions must be encrypted.
    Update {
        /// The server's alias.
        alias: String,
        /// The provider: its name or ARN.
        provider: String,
        /// A new metadata document (`-` for standard input).
        #[arg(long, value_name = "FILE")]
        metadata: Option<PathBuf>,
        /// Add a private key (PEM).
        #[arg(long, value_name = "FILE", conflicts_with = "remove_key")]
        add_key: Option<PathBuf>,
        /// Remove the private key with this id (see `teifs admin saml ls`).
        #[arg(long, value_name = "ID")]
        remove_key: Option<String>,
        /// Whether its assertions must be encrypted.
        #[arg(long, value_enum)]
        encryption: Option<Encryption>,
    },
    /// Delete a provider (asks first): its responses get no credentials from now on.
    Rm {
        /// The server's alias.
        alias: String,
        /// The provider: its name or ARN.
        provider: String,
    },
}

impl SamlAction {
    fn alias(&self) -> &str {
        match self {
            Self::Add { alias, .. }
            | Self::Ls { alias }
            | Self::Update { alias, .. }
            | Self::Rm { alias, .. } => alias,
        }
    }
}

/// A file's text: a metadata document, or a private key (kept out of memory after).
fn text(file: &Path, what: &str) -> Result<Zeroizing<String>, Error> {
    let bytes = super::read_file(file)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::usage(format!("{} isn't a {what}: it isn't text", file.display())))?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub async fn run(aliases: &crate::client::alias::Aliases, action: SamlAction) -> Result<(), Error> {
    let server = super::alias(aliases, action.alias())?.0.clone();
    let iam = super::iam(&server);
    match action {
        SamlAction::Add {
            name,
            metadata,
            private_key,
            encryption,
            ..
        } => {
            let document = text(&metadata, "metadata document")?;
            let key = private_key
                .map(|file| text(&file, "private key"))
                .transpose()?;
            let created = iam
                .create_saml_provider()
                .name(&name)
                .saml_metadata_document(document.as_str())
                .set_add_private_key(key.as_ref().map(|k| k.to_string()))
                .set_assertion_encryption_mode(encryption.map(Into::into))
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't add SAML provider {name}"), &e))?;
            let arn = created.saml_provider_arn().unwrap_or_default();
            ui::done(
                format!("Added SAML provider {arn}"),
                || json!({"type": "samlProvider", "arn": arn, "name": name}),
            );
            ui::note(format!(
                "Trust it in a role with a policy whose Principal is {{\"Federated\": \"{arn}\"}} \
                 and Action sts:AssumeRoleWithSAML"
            ));
            Ok(())
        }
        SamlAction::Ls { .. } => list(&iam).await,
        SamlAction::Update {
            provider,
            metadata,
            add_key,
            remove_key,
            encryption,
            ..
        } => {
            let arn = find(&iam, &provider).await?;
            let document = metadata
                .map(|file| text(&file, "metadata document"))
                .transpose()?;
            let key = add_key.map(|file| text(&file, "private key")).transpose()?;
            iam.update_saml_provider()
                .saml_provider_arn(&arn)
                .set_saml_metadata_document(document.as_ref().map(|d| d.to_string()))
                .set_add_private_key(key.as_ref().map(|k| k.to_string()))
                .set_remove_private_key(remove_key)
                .set_assertion_encryption_mode(encryption.map(Into::into))
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't change {arn}"), &e))?;
            ui::done(
                format!("Changed {arn}"),
                || json!({"type": "samlProviderChanged", "arn": arn}),
            );
            Ok(())
        }
        SamlAction::Rm { provider, .. } => {
            let arn = find(&iam, &provider).await?;
            if !ui::confirm(
                &format!("Delete {arn}? Its responses get no credentials from now on."),
                "add --yes to delete it",
            )? {
                return Err(Error::general("nothing was deleted").shown());
            }
            iam.delete_saml_provider()
                .saml_provider_arn(&arn)
                .send()
                .await
                .map_err(|e| Error::s3(format_args!("can't delete {arn}"), &e))?;
            ui::done(
                format!("Deleted {arn}"),
                || json!({"type": "samlProviderDeleted", "arn": arn}),
            );
            Ok(())
        }
    }
}

/// Every provider's ARN.
async fn arns(iam: &Client) -> Result<Vec<String>, Error> {
    let providers = iam
        .list_saml_providers()
        .send()
        .await
        .map_err(|e| Error::s3("can't list SAML providers", &e))?;
    Ok(providers
        .saml_provider_list()
        .iter()
        .filter_map(|p| p.arn().map(str::to_owned))
        .collect())
}

/// The ARN of the provider `given` names: its ARN or name.
async fn find(iam: &Client, given: &str) -> Result<String, Error> {
    if given.starts_with("arn:") {
        return Ok(given.to_owned());
    }
    let suffix = format!(":saml-provider/{given}").to_ascii_lowercase();
    arns(iam)
        .await?
        .into_iter()
        .find(|arn| arn.to_ascii_lowercase().ends_with(&suffix))
        .ok_or_else(|| {
            Error::new(Kind::NotFound, format!("there's no SAML provider {given}"))
                .with_hint("see `teifs admin saml ls`")
        })
}

fn millis(time: Option<&aws_sdk_iam::primitives::DateTime>) -> i64 {
    time.and_then(|d| d.to_millis().ok()).unwrap_or_default()
}

async fn list(iam: &Client) -> Result<(), Error> {
    let mut table = ui::Table::new(&["NAME", "UUID", "ISSUER", "ENCRYPTION", "KEYS", "CREATED"]);
    let mut records = Vec::new();
    for arn in arns(iam).await? {
        let provider = iam
            .get_saml_provider()
            .saml_provider_arn(&arn)
            .send()
            .await
            .map_err(|e| Error::s3(format_args!("can't read {arn}"), &e))?;
        let name = arn.rsplit_once('/').map_or(arn.as_str(), |(_, n)| n);
        let issuer = provider
            .saml_metadata_document()
            .and_then(entity_id)
            .unwrap_or_default();
        let encryption = provider
            .assertion_encryption_mode()
            .map(|m| m.as_str().to_owned());
        let keys: Vec<_> = provider
            .private_key_list()
            .iter()
            .map(|k| json!({"id": k.key_id(), "addedMs": millis(k.timestamp())}))
            .collect();
        let created = millis(provider.create_date());
        let uuid = provider.saml_provider_uuid().unwrap_or_default();
        table.row(vec![
            name.to_owned(),
            uuid.to_owned(),
            issuer.clone(),
            encryption.clone().unwrap_or_default(),
            provider
                .private_key_list()
                .iter()
                .filter_map(|k| k.key_id())
                .collect::<Vec<_>>()
                .join(", "),
            date(from_ms(created)),
        ]);
        records.push(json!({
            "type": "samlProvider",
            "arn": arn,
            "name": name,
            "uuid": uuid,
            "issuer": issuer,
            "encryption": encryption,
            "privateKeys": keys,
            "createdMs": created,
            "validUntilMs": millis(provider.valid_until()),
        }));
    }
    ui::rows(
        &table,
        &records,
        "No SAML providers yet. Add one with `teifs admin saml add`.",
    );
    Ok(())
}

/// The `entityID` of a metadata document's `EntityDescriptor`: what its responses name
/// as their issuer. Shown only; the server reads the document properly.
fn entity_id(document: &str) -> Option<String> {
    let at = document.find("entityID")? + "entityID".len();
    let rest = document[at..].trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &rest[1..];
    Some(rest[..rest.find(quote)?].to_owned())
}

#[cfg(test)]
mod tests {
    use super::entity_id;

    #[test]
    fn the_issuer_is_read_from_metadata() {
        for (document, issuer) in [
            (
                r#"<md:EntityDescriptor entityID="https://a/saml">"#,
                Some("https://a/saml"),
            ),
            ("<EntityDescriptor entityID = 'b'>", Some("b")),
            ("<EntityDescriptor>", None),
            ("<EntityDescriptor entityID=b>", None),
            (r#"<EntityDescriptor entityID="unterminated>"#, None),
        ] {
            assert_eq!(entity_id(document).as_deref(), issuer, "{document}");
        }
    }
}
