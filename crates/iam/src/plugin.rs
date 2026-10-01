//! MinIO's identity plugin: a web service that vouches for the opaque tokens clients
//! give `AssumeRoleWithCustomToken`. TeiFS posts the token to it (`POST URL?token=…`,
//! with the configured `Authorization` header); `200` names the user and how long its
//! session may last, `403` says why not. Sessions get the plugin's role's policies.

use std::time::Duration;

use reqwest::{Client, StatusCode, Url, header};
use zeroize::Zeroizing;

use crate::CertificateDer;

/// How long the plugin may take to answer, as MinIO allows it.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The session lengths a plugin may allow: 15 minutes to a year.
pub(crate) const SHORTEST: u32 = 900;
pub(crate) const LONGEST: u32 = 31_536_000;
/// The most of an answer read.
const MAX_ANSWER: usize = 64 * 1024;

/// How to reach the plugin, and what its users' sessions may do.
#[derive(Debug, Clone, Default)]
pub struct PluginSettings {
    /// Where it's asked: an `http(s)` URL.
    pub url: String,
    /// The `Authorization` header it's sent, as it is.
    pub auth_token: Option<Zeroizing<String>>,
    /// The managed policies (by name) its users' sessions get; at least one.
    pub role_policies: Vec<String>,
    /// The role's id in its ARN; by default derived from the URL, as MinIO does.
    pub role_id: Option<String>,
    /// Authorities its certificate may be issued by, besides the system's.
    pub ca: Vec<CertificateDer<'static>>,
}

/// The plugin, ready to ask.
#[derive(Debug)]
pub struct IdentityPlugin {
    url: Url,
    auth_token: Option<Zeroizing<String>>,
    role_policies: Vec<String>,
    role_arn: String,
    http: Client,
}

/// Whom the plugin vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginUser {
    /// Who the user is, as the plugin names it.
    pub user: String,
    /// The longest its session may last, in seconds.
    pub max_seconds: u32,
}

/// Why the plugin vouched for no one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginError {
    /// It refused the token (`403`), and why.
    #[error("{0}")]
    Denied(String),
    /// It couldn't be asked, or answered something else.
    #[error("{0}")]
    Failed(String),
    /// It vouched for no one in particular.
    #[error("A valid user was not returned by the authenticator.")]
    NoUser,
    /// The server has no plugin.
    #[error("no identity plugin is set up")]
    NotSetUp,
}

impl IdentityPlugin {
    /// Checks `settings` offline: the URL, the role's policies and id. `region` goes in
    /// the role's ARN, as MinIO's has the server's region.
    ///
    /// # Errors
    /// What's wrong with the settings.
    pub fn new(settings: PluginSettings, region: &str) -> Result<Self, String> {
        let url = Url::parse(&settings.url)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| format!("{} isn't an http(s) URL", settings.url))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "the URL can't hold a user name or password: give the token instead".into(),
            );
        }
        let role_policies: Vec<String> = settings
            .role_policies
            .iter()
            .flat_map(|p| p.split(','))
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        if role_policies.is_empty() {
            return Err("name the policies its users' sessions get".into());
        }
        let id = match &settings.role_id {
            Some(id)
                if !id.is_empty()
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') =>
            {
                id.clone()
            }
            Some(id) => {
                return Err(format!(
                    "the role id {id:?} may have only letters, digits, `_` and `-`"
                ));
            }
            None => crate::minio_role_id(&settings.url),
        };
        let http = Client::builder()
            .tls_certs_merge(
                settings
                    .ca
                    .iter()
                    .filter_map(|der| reqwest::Certificate::from_der(der).ok()),
            )
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(TIMEOUT)
            .timeout(TIMEOUT)
            .user_agent(concat!("teifs/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("can't make its HTTP client: {e}"))?;
        Ok(Self {
            url,
            auth_token: settings.auth_token,
            role_policies,
            role_arn: format!("arn:minio:iam:{region}::role/idmp-{id}"),
            http,
        })
    }

    /// The role's ARN, which `AssumeRoleWithCustomToken` names.
    #[must_use]
    pub fn role_arn(&self) -> &str {
        &self.role_arn
    }

    /// The managed policies (by name) its users' sessions get.
    #[must_use]
    pub fn role_policies(&self) -> &[String] {
        &self.role_policies
    }

    /// Where it's asked, without its query (which may hold secrets).
    #[must_use]
    pub fn shown_url(&self) -> String {
        let mut url = self.url.clone();
        url.set_query(None);
        url.to_string()
    }

    /// Asks the plugin about `token`.
    pub(crate) async fn authenticate(&self, token: &str) -> Result<PluginUser, PluginError> {
        let mut url = self.url.clone();
        url.query_pairs_mut().append_pair("token", token);
        let mut request = self.http.post(url);
        if let Some(auth) = &self.auth_token {
            request = request.header(header::AUTHORIZATION, auth.as_str());
        }
        let failed = |e: &dyn std::fmt::Display| PluginError::Failed(e.to_string());
        let mut response = request.send().await.map_err(|e| failed(&without_url(e)))?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| failed(&without_url(e)))?
        {
            if body.len() + chunk.len() > MAX_ANSWER {
                return Err(failed(&"the plugin's answer is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        match status {
            StatusCode::OK => {
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "camelCase")]
                struct Success {
                    #[serde(default)]
                    user: String,
                    max_validity_seconds: i64,
                }
                let answer: Success = serde_json::from_slice(&body).map_err(|e| {
                    failed(&format!("the plugin's answer isn't what it should be: {e}"))
                })?;
                let max_seconds = u32::try_from(answer.max_validity_seconds)
                    .ok()
                    .filter(|s| (SHORTEST..=LONGEST).contains(s))
                    .ok_or_else(|| {
                        failed(&format!(
                            "Plugin returned an invalid validity duration ({}) - should be \
                             between {SHORTEST} and {LONGEST}",
                            answer.max_validity_seconds
                        ))
                    })?;
                if answer.user.is_empty() {
                    return Err(PluginError::NoUser);
                }
                Ok(PluginUser {
                    user: answer.user,
                    max_seconds,
                })
            }
            StatusCode::FORBIDDEN => {
                #[derive(serde::Deserialize)]
                struct Refusal {
                    #[serde(default)]
                    reason: String,
                }
                let refusal: Refusal = serde_json::from_slice(&body).map_err(|e| {
                    failed(&format!(
                        "the plugin's refusal isn't what it should be: {e}"
                    ))
                })?;
                Err(PluginError::Denied(refusal.reason))
            }
            other => Err(failed(&format!(
                "Invalid status code {} from auth plugin",
                other.as_u16()
            ))),
        }
    }

    /// Whether the plugin answers at all (`HEAD`, as MinIO checks it).
    ///
    /// # Errors
    /// Why it can't be reached.
    pub async fn check(&self) -> Result<(), PluginError> {
        let mut request = self.http.head(self.url.clone());
        if let Some(auth) = &self.auth_token {
            request = request.header(header::AUTHORIZATION, auth.as_str());
        }
        request
            .send()
            .await
            .map(drop)
            .map_err(|e| PluginError::Failed(without_url(e).to_string()))
    }
}

/// A request's error without its URL, whose query holds the token.
fn without_url(err: reqwest::Error) -> reqwest::Error {
    err.without_url()
}

#[cfg(any(test, feature = "fake-plugin"))]
pub mod fake;
#[cfg(test)]
mod tests;
