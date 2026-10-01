//! TLS for the S3 listener: certificates from PEM files, chosen by the name a client
//! asks for (SNI), and reloaded when their files change.
//!
//! A certificates folder has MinIO's layout: `public.crt` and `private.key` (or
//! Kubernetes' `tls.crt` and `tls.key`) for the default certificate, and one subfolder
//! per further certificate with the same files. Folders whose names start with `.` (a
//! Kubernetes secret's `..data`) and `CAs` are skipped.

use std::{
    fmt, fs,
    hash::{DefaultHasher, Hash, Hasher},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError, RwLock},
};

use rustls::{
    DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, DnsName, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{
        ClientHello, ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};

/// The certificate and key file names a folder may use: MinIO's, then Kubernetes'.
const PAIR_NAMES: [(&str, &str); 2] = [("public.crt", "private.key"), ("tls.crt", "tls.key")];

/// Where the certificates come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsSource {
    /// A certificates folder (MinIO's layout), read again on every reload so new
    /// subfolders count too.
    Dir(PathBuf),
    /// One certificate (with its chain) and its private key.
    Files {
        /// The PEM certificate chain, the server's own certificate first.
        cert: PathBuf,
        /// The PEM private key.
        key: PathBuf,
    },
}

impl fmt::Display for TlsSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dir(dir) => write!(f, "{}", dir.display()),
            Self::Files { cert, .. } => write!(f, "{}", cert.display()),
        }
    }
}

/// Why certificates couldn't be loaded.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A file or folder couldn't be read.
    #[error("can't read {}: {source}", path.display())]
    Read {
        /// The file or folder.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// A certificates folder has no certificate.
    #[error(
        "{} has no certificate: put public.crt and private.key in it (or tls.crt and tls.key)",
        .0.display()
    )]
    Empty(PathBuf),
    /// A file isn't what it should be.
    #[error("{}: {message}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What's wrong.
        message: String,
    },
}

/// One certificate, ready to present.
#[derive(Debug)]
struct Entry {
    /// The server's own certificate, whose names SNI is matched against.
    leaf: CertificateDer<'static>,
    key: Arc<CertifiedKey>,
}

impl Entry {
    /// Whether the certificate is valid for `name` (as clients check it: wildcards too).
    fn serves(&self, name: &DnsName<'_>) -> bool {
        webpki::EndEntityCert::try_from(&self.leaf).is_ok_and(|cert| {
            cert.verify_is_valid_for_subject_name(&rustls::pki_types::ServerName::DnsName(
                name.to_owned(),
            ))
            .is_ok()
        })
    }
}

/// The certificates in use: the named ones first, the default last.
#[derive(Debug)]
struct Certs(Vec<Entry>);

impl Certs {
    fn pick(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let name = name.and_then(|n| DnsName::try_from(n).ok());
        let chosen = name
            .and_then(|name| self.0.iter().find(|entry| entry.serves(&name)))
            .or_else(|| self.0.last())?;
        Some(Arc::clone(&chosen.key))
    }
}

/// What the files held when last loaded: their paths and a hash of their contents
/// (times and sizes can stay the same when a file is replaced quickly).
type Stamp = Vec<(PathBuf, Option<u64>)>;

/// The listener's TLS: its settings and the certificates, reloadable while it serves.
#[derive(Debug)]
pub struct Tls {
    source: TlsSource,
    provider: Arc<CryptoProvider>,
    certs: Arc<RwLock<Arc<Certs>>>,
    stamps: Mutex<Stamps>,
    config: Arc<ServerConfig>,
}

/// The files as last loaded, and as they were when loading them last failed (so a
/// broken file is reported once, not at every check).
#[derive(Debug)]
struct Stamps {
    loaded: Stamp,
    failed: Option<Stamp>,
}

impl Tls {
    /// Loads the certificates: every one must load, its key must match it.
    pub fn load(source: TlsSource) -> Result<Self, TlsError> {
        Self::load_with(source, false)
    }

    /// [`Self::load`]; with `client_certificates`, clients are asked for a certificate
    /// too (`AssumeRoleWithCertificate`), which they needn't send.
    pub fn load_with(source: TlsSource, client_certificates: bool) -> Result<Self, TlsError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let (certs, stamp) = read(&source, &provider)?;
        let certs = Arc::new(RwLock::new(Arc::new(certs)));
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| TlsError::Invalid {
                path: PathBuf::new(),
                message: e.to_string(),
            })?;
        let builder = if client_certificates {
            builder.with_client_cert_verifier(Arc::new(AnyClientCertificate(Arc::clone(&provider))))
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder.with_cert_resolver(Arc::new(Resolver(Arc::clone(&certs))));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            source,
            provider,
            certs,
            stamps: Mutex::new(Stamps {
                loaded: stamp,
                failed: None,
            }),
            config: Arc::new(config),
        })
    }

    /// The settings connections are accepted with.
    #[must_use]
    pub fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// Where the certificates come from.
    #[must_use]
    pub const fn source(&self) -> &TlsSource {
        &self.source
    }

    /// Loads the certificates again if their files changed since they were loaded (or
    /// since loading them last failed), or always when `force`, and uses them for new
    /// connections. Returns whether they were loaded; on an error the ones in use stay.
    pub fn reload(&self, force: bool) -> Result<bool, TlsError> {
        let mut stamps = self.stamps.lock().unwrap_or_else(PoisonError::into_inner);
        let now = stamp(&pairs(&self.source)?);
        if !force && (now == stamps.loaded || stamps.failed.as_ref() == Some(&now)) {
            return Ok(false);
        }
        match read(&self.source, &self.provider) {
            Ok((certs, stamp)) => {
                *self.certs.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(certs);
                *stamps = Stamps {
                    loaded: stamp,
                    failed: None,
                };
                Ok(true)
            }
            Err(err) => {
                stamps.failed = Some(now);
                Err(err)
            }
        }
    }
}

/// Asks clients for a certificate without requiring one, and takes any: who issued it is
/// checked when it signs in (`AssumeRoleWithCertificate`), as MinIO does, so a client
/// with an unrelated certificate still connects. The handshake still proves the client
/// holds the certificate's key.
#[derive(Debug)]
struct AnyClientCertificate(Arc<CryptoProvider>);

impl ClientCertVerifier for AnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Picks each connection's certificate by the name the client asked for; without one,
/// or when none serves it, the default.
#[derive(Debug)]
struct Resolver(Arc<RwLock<Arc<Certs>>>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let certs = Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner));
        certs.pick(hello.server_name())
    }
}

/// The certificate and key files `source` names: subfolders' in name order, the
/// default last.
fn pairs(source: &TlsSource) -> Result<Vec<(PathBuf, PathBuf)>, TlsError> {
    let dir = match source {
        TlsSource::Files { cert, key } => return Ok(vec![(cert.clone(), key.clone())]),
        TlsSource::Dir(dir) => dir,
    };
    let unreadable = |source| TlsError::Read {
        path: dir.clone(),
        source,
    };
    let mut folders = Vec::new();
    for entry in fs::read_dir(dir).map_err(unreadable)? {
        let path = entry.map_err(unreadable)?.path();
        let skipped = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_none_or(|n| n.starts_with('.') || n == "CAs");
        // Following links, as a Kubernetes secret's folders are.
        if !skipped && path.is_dir() {
            folders.push(path);
        }
    }
    folders.sort();
    let mut found: Vec<_> = folders.iter().filter_map(|f| pair_in(f)).collect();
    found.extend(pair_in(dir));
    if found.is_empty() {
        return Err(TlsError::Empty(dir.clone()));
    }
    Ok(found)
}

impl TlsSource {
    /// Each certificate file it names, with the server's own certificate in it (the
    /// first of its chain), without loading the keys: for checking when they expire.
    pub fn certificates(&self) -> Result<Vec<(PathBuf, CertificateDer<'static>)>, TlsError> {
        pairs(self)?
            .into_iter()
            .map(|(cert, _)| {
                let pem = fs::read(&cert).map_err(|source| TlsError::Read {
                    path: cert.clone(),
                    source,
                })?;
                let leaf = CertificateDer::pem_slice_iter(&pem)
                    .next()
                    .and_then(Result::ok)
                    .ok_or_else(|| TlsError::Invalid {
                        path: cert.clone(),
                        message: "has no PEM certificate".into(),
                    })?;
                Ok((cert, leaf))
            })
            .collect()
    }
}

impl TlsSource {
    /// Where MinIO keeps the authorities client certificates are checked against: the
    /// certificates folder's `CAs`. None for a certificate given as files.
    #[must_use]
    pub fn authorities(&self) -> Option<PathBuf> {
        match self {
            Self::Dir(dir) => Some(dir.join("CAs")),
            Self::Files { .. } => None,
        }
    }
}

/// The PEM certificates in `path`: a file, or every file in a folder (not in its
/// subfolders, nor those whose names start with `.`).
pub fn read_authorities(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let unreadable = |path: &Path, source| TlsError::Read {
        path: path.to_owned(),
        source,
    };
    let files = if path.is_dir() {
        let mut files = Vec::new();
        for entry in fs::read_dir(path).map_err(|e| unreadable(path, e))? {
            let file = entry.map_err(|e| unreadable(path, e))?.path();
            let hidden = file
                .file_name()
                .and_then(|n| n.to_str())
                .is_none_or(|n| n.starts_with('.'));
            if !hidden && file.is_file() {
                files.push(file);
            }
        }
        files.sort();
        files
    } else {
        vec![path.to_owned()]
    };
    let mut found = Vec::new();
    for file in files {
        let pem = fs::read(&file).map_err(|e| unreadable(&file, e))?;
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Invalid {
                path: file.clone(),
                message: format!("isn't a PEM certificate: {e}"),
            })?;
        if certificates.is_empty() {
            return Err(TlsError::Invalid {
                path: file,
                message: "has no PEM certificate".into(),
            });
        }
        found.extend(certificates);
    }
    Ok(found)
}

/// The certificate and key in `dir`, if it has both.
fn pair_in(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    PAIR_NAMES.iter().find_map(|(cert, key)| {
        let (cert, key) = (dir.join(cert), dir.join(key));
        (cert.is_file() && key.is_file()).then_some((cert, key))
    })
}

fn stamp(pairs: &[(PathBuf, PathBuf)]) -> Stamp {
    pairs
        .iter()
        .flat_map(|(cert, key)| [cert, key])
        .map(|path| {
            let hash = fs::read(path).ok().map(|bytes| {
                let mut hasher = DefaultHasher::new();
                bytes.hash(&mut hasher);
                hasher.finish()
            });
            (path.clone(), hash)
        })
        .collect()
}

fn read(source: &TlsSource, provider: &CryptoProvider) -> Result<(Certs, Stamp), TlsError> {
    let pairs = pairs(source)?;
    // Stamped before reading: a change while reading is seen at the next check.
    let stamp = stamp(&pairs);
    let entries = pairs
        .iter()
        .map(|(cert, key)| load_pair(cert, key, provider))
        .collect::<Result<_, _>>()?;
    Ok((Certs(entries), stamp))
}

fn load_pair(cert: &Path, key: &Path, provider: &CryptoProvider) -> Result<Entry, TlsError> {
    let invalid = |path: &Path, message: String| TlsError::Invalid {
        path: path.to_owned(),
        message,
    };
    let unreadable = |path: &Path, source| TlsError::Read {
        path: path.to_owned(),
        source,
    };
    let pem = fs::read(cert).map_err(|e| unreadable(cert, e))?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(cert, format!("isn't a PEM certificate: {e}")))?;
    let Some(leaf) = chain.first().cloned() else {
        return Err(invalid(cert, "has no certificate".into()));
    };
    webpki::EndEntityCert::try_from(&leaf)
        .map_err(|e| invalid(cert, format!("isn't a valid certificate: {e}")))?;
    let pem = fs::read(key).map_err(|e| unreadable(key, e))?;
    let private = PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|e| invalid(key, format!("isn't a PEM private key: {e}")))?;
    let certified = CertifiedKey::from_der(chain, private, provider)
        .map_err(|e| invalid(key, format!("isn't the key of {}: {e}", cert.display())))?;
    Ok(Entry {
        leaf,
        key: Arc::new(certified),
    })
}

/// How often certificate files are checked for changes.
pub const RELOAD_CHECK: std::time::Duration = std::time::Duration::from_secs(10);

/// Reloads `tls`'s certificates when their files change (checked every
/// [`RELOAD_CHECK`]) and, on Unix, at once on `SIGHUP`, until dropped. A reload that
/// fails keeps the certificates in use.
pub async fn watch(tls: Arc<Tls>) {
    let mut tick = tokio::time::interval(RELOAD_CHECK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    let mut hangups = crate::signals::Hangups::new();
    loop {
        let force = tokio::select! {
            _ = tick.tick() => false,
            () = hangups.next() => true,
        };
        let reloading = Arc::clone(&tls);
        match tokio::task::spawn_blocking(move || reloading.reload(force)).await {
            Ok(Ok(true)) => tracing::info!(source = %tls.source(), "reloaded the TLS certificates"),
            Ok(Ok(false)) => {}
            Ok(Err(err)) => tracing::warn!(
                error = %err,
                "couldn't reload the TLS certificates; still using the ones loaded before"
            ),
            Err(err) => tracing::warn!(error = %err, "the TLS certificate reload failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};

    use super::*;

    /// A self-signed certificate for `names`, and its key, PEM.
    fn issue(names: &[&str]) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        (params.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    fn write(dir: &Path, names: (&str, &str), pair: &(String, String)) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(names.0), &pair.0).unwrap();
        fs::write(dir.join(names.1), &pair.1).unwrap();
    }

    fn message(source: TlsSource) -> String {
        Tls::load(source).unwrap_err().to_string()
    }

    #[test]
    fn folders_have_minio_s_layout_or_kubernetes_names() {
        let dir = tempfile::tempdir().unwrap();
        let err = message(TlsSource::Dir(dir.path().to_owned()));
        assert!(err.contains("has no certificate: put public.crt"), "{err}");
        // A certificate without its key isn't one.
        fs::write(dir.path().join("public.crt"), issue(&["a.test"]).0).unwrap();
        assert!(Tls::load(TlsSource::Dir(dir.path().to_owned())).is_err());

        write(
            dir.path(),
            ("tls.crt", "tls.key"),
            &issue(&["default.test"]),
        );
        write(
            &dir.path().join("b"),
            ("public.crt", "private.key"),
            &issue(&["b.test"]),
        );
        write(
            &dir.path().join("a"),
            ("tls.crt", "tls.key"),
            &issue(&["*.a.test"]),
        );
        write(
            &dir.path().join(".hidden"),
            ("public.crt", "private.key"),
            &issue(&["h.test"]),
        );
        write(
            &dir.path().join("CAs"),
            ("public.crt", "private.key"),
            &issue(&["ca.test"]),
        );
        fs::create_dir(dir.path().join("empty")).unwrap();
        let tls = Tls::load(TlsSource::Dir(dir.path().to_owned())).unwrap();
        let certs = Arc::clone(&tls.certs.read().unwrap());
        assert_eq!(certs.0.len(), 3, "a, b, then the default");
        let chosen = |name| {
            let key = certs.pick(name).unwrap();
            certs
                .0
                .iter()
                .position(|e| Arc::ptr_eq(&e.key, &key))
                .unwrap()
        };
        assert_eq!(chosen(Some("x.a.test")), 0);
        assert_eq!(chosen(Some("b.test")), 1);
        assert_eq!(chosen(Some("default.test")), 2);
        assert_eq!(chosen(Some("h.test")), 2, "hidden folders are skipped");
        assert_eq!(chosen(Some("ca.test")), 2, "so is CAs");
        assert_eq!(chosen(Some("a.test")), 2, "a wildcard is one label");
        assert_eq!(chosen(Some("not a name")), 2);
        assert_eq!(chosen(None), 2);
        assert_eq!(
            tls.config().alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // Each certificate the folder serves, its own first, as read for its expiry.
        let found = TlsSource::Dir(dir.path().to_owned())
            .certificates()
            .unwrap();
        let files: Vec<PathBuf> = found.iter().map(|(path, _)| path.clone()).collect();
        assert_eq!(
            files,
            [
                dir.path().join("a/tls.crt"),
                dir.path().join("b/public.crt"),
                dir.path().join("tls.crt")
            ]
        );
        let first = fs::read(dir.path().join("a/tls.crt")).unwrap();
        let leaf = CertificateDer::pem_slice_iter(&first)
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(found[0].1, leaf);
        fs::write(dir.path().join("b/public.crt"), "nonsense").unwrap();
        let err = TlsSource::Dir(dir.path().to_owned())
            .certificates()
            .unwrap_err();
        assert!(err.to_string().contains("has no PEM certificate"), "{err}");
    }

    #[test]
    fn clients_are_asked_for_a_certificate_and_must_hold_its_key() {
        let verifier =
            AnyClientCertificate(Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        assert!(verifier.offer_client_auth());
        assert!(!verifier.client_auth_mandatory());
        assert!(verifier.root_hint_subjects().is_empty());
        assert!(!verifier.supported_verify_schemes().is_empty());
        let pem = issue(&["client.test"]).0;
        let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        // Any issuer: it's checked when it signs in.
        assert!(
            verifier
                .verify_client_cert(&cert, &[], UnixTime::now())
                .is_ok()
        );
        let config = Tls::load_with(
            TlsSource::Files {
                cert: PathBuf::from("/nonexistent"),
                key: PathBuf::from("/nonexistent"),
            },
            true,
        );
        assert!(config.is_err());
    }

    #[test]
    fn authorities_come_from_a_file_or_a_folder() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            TlsSource::Dir(dir.path().to_owned()).authorities(),
            Some(dir.path().join("CAs"))
        );
        let files = TlsSource::Files {
            cert: dir.path().join("c"),
            key: dir.path().join("k"),
        };
        assert_eq!(files.authorities(), None);
        let cas = dir.path().join("CAs");
        fs::create_dir_all(cas.join("sub")).unwrap();
        let (a, b) = (issue(&["a.test"]).0, issue(&["b.test"]).0);
        fs::write(cas.join("a.crt"), format!("{a}{b}")).unwrap();
        fs::write(cas.join("b.pem"), &b).unwrap();
        fs::write(cas.join(".hidden"), "nonsense").unwrap();
        fs::write(cas.join("sub/c.crt"), "nonsense").unwrap();
        assert_eq!(read_authorities(&cas).unwrap().len(), 3);
        assert_eq!(read_authorities(&cas.join("b.pem")).unwrap().len(), 1);
        fs::write(cas.join("c.txt"), "nonsense").unwrap();
        let err = read_authorities(&cas).unwrap_err().to_string();
        assert!(err.contains("c.txt: has no PEM certificate"), "{err}");
        let err = read_authorities(&dir.path().join("missing")).unwrap_err();
        assert!(err.to_string().starts_with("can't read"), "{err}");
    }

    #[test]
    fn broken_files_are_named_with_what_s_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let files = || TlsSource::Files {
            cert: cert.clone(),
            key: key.clone(),
        };
        let err = message(files());
        assert!(err.starts_with("can't read"), "{err}");
        let (good_cert, good_key) = issue(&["a.test"]);
        fs::write(&cert, "not PEM").unwrap();
        fs::write(&key, &good_key).unwrap();
        let err = message(files());
        assert!(err.ends_with("has no certificate"), "{err}");
        fs::write(
            &cert,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let err = message(files());
        assert!(err.contains("isn't a valid certificate"), "{err}");
        fs::write(&cert, &good_cert).unwrap();
        fs::write(&key, "not a key").unwrap();
        let err = message(files());
        assert!(err.contains("isn't a PEM private key"), "{err}");
        fs::write(&key, issue(&["a.test"]).1).unwrap();
        let err = message(files());
        assert!(err.contains("isn't the key of"), "{err}");
        fs::write(&key, &good_key).unwrap();
        let tls = Tls::load(files()).unwrap();
        assert_eq!(tls.source().to_string(), cert.display().to_string());
        assert!(!tls.reload(false).unwrap());
        // Rewritten with the same bytes: nothing to load.
        fs::write(&cert, &good_cert).unwrap();
        assert!(!tls.reload(false).unwrap());
    }
}
