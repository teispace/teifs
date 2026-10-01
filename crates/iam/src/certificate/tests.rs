#![allow(clippy::unwrap_used, reason = "tests fail on any error")]

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};

use super::*;

const DAY: i64 = 86_400;

fn now() -> i64 {
    crate::sessions::now_seconds()
}

/// Valid from yesterday for `days` days.
fn dated(params: &mut CertificateParams, days: i64) {
    let today = time::OffsetDateTime::now_utc();
    params.not_before = today - time::Duration::days(1);
    params.not_after = today + time::Duration::days(days);
}

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
}

fn ca(name: &str) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    dated(&mut params, 3650);
    let key = KeyPair::generate().unwrap();
    let der = params.self_signed(&key).unwrap().der().clone();
    Ca {
        issuer: Issuer::new(params, key),
        der,
    }
}

impl Ca {
    /// An intermediate CA this one issues.
    fn intermediate(&self, name: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        dated(&mut params, 3650);
        let key = KeyPair::generate().unwrap();
        let der = params.signed_by(&key, &self.issuer).unwrap().der().clone();
        Ca {
            issuer: Issuer::new(params, key),
            der,
        }
    }

    /// A client certificate for `cn` (none: no common name), for `usages`.
    fn client(
        &self,
        cn: Option<&str>,
        usages: Vec<ExtendedKeyUsagePurpose>,
        days: i64,
    ) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        // Not rcgen's default name.
        params.distinguished_name = DistinguishedName::new();
        if let Some(cn) = cn {
            params.distinguished_name.push(DnType::CommonName, cn);
        }
        params
            .distinguished_name
            .push(DnType::OrganizationName, "TeiFS tests");
        params.extended_key_usages = usages;
        dated(&mut params, days);
        let key = KeyPair::generate().unwrap();
        params.signed_by(&key, &self.issuer).unwrap().der().clone()
    }
}

fn for_clients() -> Vec<ExtendedKeyUsagePurpose> {
    vec![ExtendedKeyUsagePurpose::ClientAuth]
}

#[test]
fn a_certificate_from_a_trusted_authority_names_its_policy() {
    let root = ca("root");
    let signin = CertificateSignIn::new(std::slice::from_ref(&root.der), false).unwrap();
    assert_eq!(signin.authorities(), 1);
    assert!(!signin.skips_verification());
    let leaf = root.client(Some("consoleAdmin"), for_clients(), 30);
    let presented = signin.check(&[leaf], now()).unwrap();
    assert_eq!(presented.cn, "consoleAdmin");
    let left = presented.not_after - now();
    assert!(left > 29 * DAY && left <= 30 * DAY, "{left}");

    // Through an intermediate the client sends, in either order.
    let middle = root.intermediate("middle");
    let leaf = middle.client(Some("readonly"), for_clients(), 30);
    for chain in [
        [leaf.clone(), middle.der.clone()],
        [middle.der.clone(), leaf.clone()],
    ] {
        assert_eq!(signin.check(&chain, now()).unwrap().cn, "readonly");
    }
    // Without it, the leaf can't be traced to the root.
    assert!(matches!(
        signin.check(&[leaf], now()),
        Err(CertificateError::Invalid(_))
    ));
}

#[test]
fn certificates_that_cant_sign_in_are_refused() {
    let root = ca("root");
    let other = ca("other");
    let signin = CertificateSignIn::new(std::slice::from_ref(&root.der), false).unwrap();
    let check = |chain: &[CertificateDer<'static>]| signin.check(chain, now()).unwrap_err();

    assert_eq!(check(&[]), CertificateError::Missing);
    assert_eq!(
        check(std::slice::from_ref(&root.der)),
        CertificateError::Missing
    );
    let a = root.client(Some("a"), for_clients(), 30);
    let b = root.client(Some("b"), for_clients(), 30);
    assert_eq!(check(&[a.clone(), b]), CertificateError::Several);
    let mut long = vec![a];
    long.extend((0..11).map(|i| root.intermediate(&format!("i{i}")).der));
    assert_eq!(check(&long), CertificateError::TooManyIntermediates);
    long.pop();
    assert_eq!(signin.check(&long, now()).unwrap().cn, "a");

    // Another authority's, an expired one, one for servers only, one without a name.
    assert!(matches!(
        check(&[other.client(Some("a"), for_clients(), 30)]),
        CertificateError::Invalid(_)
    ));
    let expired = root.client(Some("a"), for_clients(), 30);
    assert!(matches!(
        signin.check(&[expired], now() + 31 * DAY),
        Err(CertificateError::Invalid(_))
    ));
    assert!(matches!(
        check(&[root.client(Some("a"), vec![ExtendedKeyUsagePurpose::ServerAuth], 30)]),
        CertificateError::Invalid(_)
    ));
    // No extended key usage at all passes the chain check but isn't for clients.
    assert_eq!(
        check(&[root.client(Some("a"), Vec::new(), 30)]),
        CertificateError::NotForClients
    );
    assert_eq!(
        check(&[root.client(None, for_clients(), 30)]),
        CertificateError::NoCommonName
    );
    assert!(matches!(
        check(&[CertificateDer::from(vec![1, 2, 3])]),
        CertificateError::Invalid(m) if m.contains("can't be read")
    ));
}

#[test]
fn without_verification_any_issuer_will_do_but_not_anything_else() {
    let stranger = ca("stranger");
    let signin = CertificateSignIn::new(&[], true).unwrap();
    assert!(signin.skips_verification());
    let leaf = stranger.client(Some("readonly"), for_clients(), 30);
    assert_eq!(
        signin.check(std::slice::from_ref(&leaf), now()).unwrap().cn,
        "readonly"
    );
    assert!(matches!(
        signin.check(&[leaf], now() + 31 * DAY),
        Err(CertificateError::Invalid(_))
    ));
    let not_yet = stranger.client(Some("a"), for_clients(), 30);
    assert!(matches!(
        signin.check(&[not_yet], now() - 2 * DAY),
        Err(CertificateError::Invalid(_))
    ));
    assert_eq!(
        signin
            .check(
                &[stranger.client(Some("a"), vec![ExtendedKeyUsagePurpose::ServerAuth], 30)],
                now()
            )
            .unwrap_err(),
        CertificateError::NotForClients
    );
    let any = stranger.client(Some("a"), vec![ExtendedKeyUsagePurpose::Any], 30);
    assert_eq!(signin.check(&[any], now()).unwrap().cn, "a");
}

#[test]
fn only_ca_certificates_are_authorities() {
    let err = CertificateSignIn::new(&[CertificateDer::from(vec![0])], false).unwrap_err();
    assert!(
        err.starts_with("certificate 1 isn't a CA certificate"),
        "{err}"
    );
}

mod sign_in {
    use std::sync::Arc;

    use teifs_crypto::LocalKms;
    use teifs_policy::Date;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AuthError, Call, Iam, Identity, Reply, RootKey};

    const READ_PHOTOS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
      "Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;

    async fn iam(dir: &std::path::Path) -> Iam {
        let kms = LocalKms::open(dir.join("keyring.json")).unwrap();
        let root = RootKey {
            access_key: "TFROOTKEY".into(),
            secret: Zeroizing::new("root-secret".into()),
        };
        let iam = Iam::open(&dir.join("system.db"), "drive-1", &kms, Some(root))
            .await
            .unwrap();
        iam.create_policy("readphotos", None, None, READ_PHOTOS, &[])
            .unwrap();
        iam
    }

    /// Asks for a session with `chain`, the parameters in `query`.
    async fn sign_in(iam: &Iam, chain: &[CertificateDer<'static>], query: &str) -> Reply {
        let body = format!("Action=AssumeRoleWithCertificate&Version=2011-06-15{query}");
        assert!(Iam::proves_itself(body.as_bytes()));
        let identity = Identity::anonymous();
        let context = identity.context(Date::now());
        iam.serve_self_proving(&Call {
            identity: &identity,
            context: &context,
            body: body.as_bytes(),
            request_id: "test",
            certificates: chain,
        })
        .await
    }

    fn element<'a>(body: &'a str, name: &str) -> &'a str {
        let start = body.find(&format!("<{name}>")).unwrap() + name.len() + 2;
        let end = start + body[start..].find(&format!("</{name}>")).unwrap();
        &body[start..end]
    }

    fn refusal(reply: &Reply) -> (u16, &str, &str) {
        (
            reply.status,
            element(&reply.body, "Code"),
            element(&reply.body, "Message"),
        )
    }

    fn identity(iam: &Iam, reply: &Reply) -> Result<Arc<Identity>, AuthError> {
        assert_eq!(reply.status, 200, "{}", reply.body);
        iam.identify(
            element(&reply.body, "AccessKeyId"),
            Some(element(&reply.body, "SessionToken")),
        )
    }

    fn allows(identity: &Identity, action: &str, resource: &str) -> bool {
        identity.allows(&identity.context(Date::now()), action, resource)
    }

    #[tokio::test]
    async fn a_certificate_gets_the_policy_its_name_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = ca("root");
        let iam = iam(dir.path()).await.with_certificates(
            CertificateSignIn::new(std::slice::from_ref(&root.der), false).unwrap(),
        );
        let leaf = root.client(Some("ReadPhotos"), for_clients(), 30);
        let first = sign_in(&iam, std::slice::from_ref(&leaf), "").await;
        assert!(first.body.contains("<AssumeRoleWithCertificateResponse"));
        let session = identity(&iam, &first).unwrap();
        assert_eq!(
            session.principal().arn(),
            Some(format!("arn:aws:sts::{}:federated-user/ReadPhotos", iam.account()).as_str())
        );
        let s = session.session().unwrap();
        assert_eq!(s.kind(), crate::SessionKind::Certificate);
        let left = s.expires() - now();
        assert!(left > 3500 && left <= 3600, "{left}");
        assert!(allows(
            &session,
            "s3:GetObject",
            "arn:aws:s3:::photos/cat.jpg"
        ));
        assert!(!allows(
            &session,
            "s3:PutObject",
            "arn:aws:s3:::photos/cat.jpg"
        ));

        // A session policy narrows it; no session outlives its certificate.
        let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}"#;
        let short = root.client(Some("readphotos"), for_clients(), 2);
        let query = format!(
            "&DurationSeconds=31536000&Policy={}",
            form_urlencoded::byte_serialize(deny.as_bytes()).collect::<String>()
        );
        let reply = sign_in(&iam, &[short], &query).await;
        let narrowed = identity(&iam, &reply).unwrap();
        assert!(!allows(
            &narrowed,
            "s3:GetObject",
            "arn:aws:s3:::photos/cat.jpg"
        ));
        let left = narrowed.session().unwrap().expires() - now();
        assert!(left > DAY && left <= 2 * DAY, "{left}");

        // A session may call IAM, as MinIO's do.
        assert!(s.may_manage());

        // Deleting the policy takes the permissions with it.
        let arn = format!("arn:aws:iam::{}:policy/readphotos", iam.account());
        iam.delete_policy(&arn).unwrap();
        let fresh = identity(&iam, &first).unwrap();
        assert!(!allows(
            &fresh,
            "s3:GetObject",
            "arn:aws:s3:::photos/cat.jpg"
        ));
        assert_eq!(
            refusal(&sign_in(&iam, &[leaf], "").await),
            (
                400,
                "InvalidParameterValue",
                "No policy is called ReadPhotos, the certificate&apos;s common name: \
                 credentials will not be generated"
            )
        );
    }

    #[tokio::test]
    async fn certificates_that_cant_sign_in_are_told_why() {
        let dir = tempfile::tempdir().unwrap();
        let root = ca("root");
        let iam = iam(dir.path()).await;
        let leaf = root.client(Some("readphotos"), for_clients(), 30);
        // A server that doesn't take certificates says so.
        assert_eq!(
            refusal(&sign_in(&iam, std::slice::from_ref(&leaf), "").await),
            (
                503,
                "STSNotInitialized",
                "STS API &apos;AssumeRoleWithCertificate&apos; is disabled"
            )
        );
        let iam = iam.with_certificates(
            CertificateSignIn::new(std::slice::from_ref(&root.der), false).unwrap(),
        );
        assert_eq!(
            refusal(&sign_in(&iam, &[], "").await),
            (
                400,
                "InvalidParameterValue",
                "No client certificate provided"
            )
        );
        let stranger = ca("stranger").client(Some("readphotos"), for_clients(), 30);
        assert_eq!(
            refusal(&sign_in(&iam, &[stranger], "").await),
            (
                400,
                "InvalidClientCertificate",
                "The provided client certificate is invalid. Retry with a different certificate."
            )
        );
        let servers_only = root.client(Some("readphotos"), Vec::new(), 30);
        assert_eq!(
            refusal(&sign_in(&iam, &[servers_only], "").await),
            (
                400,
                "InvalidClientCertificate",
                "certificate is not valid for client authentication"
            )
        );
        for duration in ["899", "31536001", "soon"] {
            let reply = sign_in(
                &iam,
                std::slice::from_ref(&leaf),
                &format!("&DurationSeconds={duration}"),
            )
            .await;
            assert_eq!(reply.status, 400, "{duration}: {}", reply.body);
        }
        let reply = sign_in(&iam, &[leaf], "&DurationSeconds=900").await;
        let left = identity(&iam, &reply).unwrap().session().unwrap().expires() - now();
        assert!(left > 800 && left <= 900, "{left}");
    }
}
