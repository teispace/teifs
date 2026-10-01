//! The directory client against [`super::fake::FakeLdap`].

use tokio::net::TcpListener;
use zeroize::Zeroizing;

use super::{
    Directory, LdapError, LdapSettings,
    client::{Kind, Srv, in_order},
    fake::{FakeLdap, group},
};

#[tokio::test]
async fn a_user_signs_in_with_its_groups_and_attributes() {
    let fake = FakeLdap::start().await;
    let directory = fake.directory();
    let dillon = directory
        .sign_in("dillon", "dillon-password")
        .await
        .unwrap();
    assert_eq!(dillon.dn, "uid=dillon,ou=people,dc=min,dc=io");
    assert_eq!(dillon.actual_dn, "uid=dillon,ou=people,dc=min,dc=io");
    assert_eq!(dillon.username, "dillon");
    assert_eq!(
        dillon.groups,
        [
            "cn=projecta,ou=groups,dc=min,dc=io",
            "cn=projectb,ou=groups,dc=min,dc=io"
        ]
    );
    assert_eq!(dillon.attributes["mail"], ["dillon@min.io"]);
    // A name that needs escaping in a filter and in a DN.
    let smith = directory
        .sign_in("Smith, John", "Smith, John-password")
        .await
        .unwrap();
    assert_eq!(smith.dn, "uid=Smith\\, John,ou=people,dc=min,dc=io");
    assert!(smith.groups.is_empty());
    // Groups by the name signed in with (`%s`), and none looked up without a filter.
    let by_name = Directory::new(LdapSettings {
        group_filter: Some("(memberUid=%s)".into()),
        ..fake.settings()
    })
    .unwrap();
    let liza = by_name.sign_in("liza", "liza-password").await.unwrap();
    assert_eq!(liza.groups, ["cn=projectb,ou=groups,dc=min,dc=io"]);
    let no_groups = Directory::new(LdapSettings {
        group_filter: None,
        user_attributes: vec![],
        ..fake.settings()
    })
    .unwrap();
    let dillon = no_groups
        .sign_in("dillon", "dillon-password")
        .await
        .unwrap();
    assert!(dillon.groups.is_empty() && dillon.attributes.is_empty());
}

#[tokio::test]
async fn wrong_names_and_passwords_are_refused_alike() {
    let fake = FakeLdap::start().await;
    let directory = fake.directory();
    for (name, password) in [
        ("dillon", "wrong"),
        ("nobody", "x"),
        // The fake takes an empty password as an unauthenticated bind; TeiFS mustn't.
        ("dillon", ""),
        ("", "x"),
        // Outside the user base DNs.
        ("outsider", "outsider-password"),
        // A filter injection finds nobody.
        ("*", "x"),
        ("dillon)(uid=*", "dillon-password"),
    ] {
        assert_eq!(
            directory.sign_in(name, password).await,
            Err(LdapError::Refused),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_filter_that_finds_two_users_is_reported() {
    let fake = FakeLdap::start().await;
    let directory = Directory::new(LdapSettings {
        user_filter: "(|(uid=%s)(uid=liza))".into(),
        ..fake.settings()
    })
    .unwrap();
    assert_eq!(
        directory.sign_in("dillon", "dillon-password").await,
        Err(LdapError::Ambiguous("dillon".into()))
    );
}

#[tokio::test]
async fn directory_failures_say_what_failed() {
    let fake = FakeLdap::start().await;
    let wrong_lookup = Directory::new(LdapSettings {
        lookup_password: Some(Zeroizing::new("nope".into())),
        ..fake.settings()
    })
    .unwrap();
    let err = wrong_lookup
        .sign_in("dillon", "dillon-password")
        .await
        .unwrap_err();
    assert!(matches!(err, LdapError::LookupBind(_)), "{err}");
    assert!(wrong_lookup.check().await.is_err());

    let missing_base = Directory::new(LdapSettings {
        user_bases: vec!["ou=gone,dc=min,dc=io".into()],
        ..fake.settings()
    })
    .unwrap();
    let err = missing_base.sign_in("dillon", "x").await.unwrap_err();
    assert!(err.to_string().contains("ou=gone,dc=min,dc=io"), "{err}");
    let err = missing_base.check().await.unwrap_err();
    assert!(err.to_string().contains("isn't in the directory"), "{err}");
    fake.directory().check().await.unwrap();

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let unreachable = Directory::new(LdapSettings {
        server: address.to_string(),
        ..fake.settings()
    })
    .unwrap();
    let err = unreachable.sign_in("dillon", "x").await.unwrap_err();
    assert!(matches!(err, LdapError::Unreachable(_)), "{err}");
    assert!(err.to_string().contains(&address.to_string()), "{err}");
}

#[tokio::test]
async fn dns_are_found_in_any_spelling() {
    let fake = FakeLdap::start().await;
    let directory = fake.directory();
    let found = directory
        .find("UID=dillon, OU=People,dc=MIN,dc=io", Kind::User)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.dn, "uid=dillon,ou=people,dc=min,dc=io");
    assert!(found.under_base);
    let group = directory
        .find("cn=projecta,ou=groups,dc=min,dc=io", Kind::Group)
        .await
        .unwrap()
        .unwrap();
    assert!(group.under_base);
    // A user isn't under the group base DNs, nor an outsider under the user ones.
    let as_group = directory
        .find("uid=dillon,ou=people,dc=min,dc=io", Kind::Group)
        .await
        .unwrap()
        .unwrap();
    assert!(!as_group.under_base);
    let outsider = directory
        .find("uid=outsider,ou=others,dc=min,dc=io", Kind::User)
        .await
        .unwrap()
        .unwrap();
    assert!(!outsider.under_base);
    assert_eq!(
        directory
            .find("uid=nobody,ou=people,dc=min,dc=io", Kind::User)
            .await,
        Ok(None)
    );
}

#[tokio::test]
async fn a_refresh_sees_new_groups_and_gone_users() {
    let fake = FakeLdap::start().await;
    let directory = fake.directory();
    let liza = "uid=liza,ou=people,dc=min,dc=io";
    assert_eq!(
        directory.refresh(liza, "liza").await,
        Ok(Some(vec!["cn=projectb,ou=groups,dc=min,dc=io".into()]))
    );
    fake.add(group("projectc", &["liza"]));
    assert_eq!(
        directory
            .refresh(liza, "liza")
            .await
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    fake.remove(liza);
    assert_eq!(directory.refresh(liza, "liza").await, Ok(None));
    assert_eq!(
        directory
            .refresh("uid=outsider,ou=others,dc=min,dc=io", "outsider")
            .await,
        Ok(None)
    );
}

#[test]
fn srv_records_are_tried_by_priority_then_weight() {
    let srv = |priority, weight, target: &str| Srv {
        priority,
        weight,
        target: target.to_owned(),
        port: 636,
    };
    assert_eq!(
        in_order(vec![
            srv(20, 0, "backup.example.com."),
            srv(10, 5, "light.example.com."),
            srv(10, 50, "heavy.example.com."),
        ]),
        [
            "heavy.example.com:636",
            "light.example.com:636",
            "backup.example.com:636"
        ]
    );
}
