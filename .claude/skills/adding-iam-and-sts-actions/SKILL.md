---
name: adding-iam-and-sts-actions
description: Adds or changes an IAM or STS action in TeiFS (the action tables in crates/iam/src/api, the Draft operation behind it, its authorization and condition keys, the service-reference test, SDK end-to-end tests and the docs). Use when implementing an AWS IAM or STS API such as instance profiles or AssumeRoleWithWebIdentity, or when changing how temporary credentials behave.
---

# Adding an IAM or STS action

TeiFS serves AWS's IAM and STS Query APIs on the S3 endpoint (`crates/s3/src/iam_api.rs`
dispatches on the signature's service). `teifs-iam` parses the form, finds the action in
a table, authorizes it and answers in AWS's XML.

## Checklist

1. **Read AWS's API reference** for the action (parameters, limits, errors) and its entry
   in the service reference (resource and condition keys). If the fixture lacks it,
   refresh `crates/iam/tests/fixtures/iam-reference.json` from
   `https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json` (STS: the `sts`
   section, from `…/v1/sts/sts.json`), trimmed to `conditionKeys` and `resources`.
2. **The table entry.** IAM actions are in the `actions!` table in
   `crates/iam/src/api/mod.rs`; STS actions in `ACTIONS` in `crates/iam/src/api/sts.rs`.
   Each names its resource kind (`On`) and exactly the condition keys the reference lists
   (reuse the constants such as `TAGGING` and `CREATE_ROLE`):

   ```rust
   CreateRole: Role, CREATE_ROLE, roles::create;
   ```

   `actions_match_aws_service_reference` in `crates/iam/src/api/tests.rs` fails until
   the resource and keys match AWS's (keys of other identity providers, such as
   `saml:…`, are left out for STS).
3. **The handler** (`crates/iam/src/api/<entity>.rs`): resolve names to the entity's own
   ARN and tags first (`r.user`, `r.role`, `r.group`, `r.policy`, `r.oidc_provider`), build the context with
   the action's keys, authorize, then run the operation:

   ```rust
   let role = r.new_resource(On::Role, path.unwrap_or("/"), name);
   let context = with_boundary(with_request_tags(r.context(), &tags), boundary_arn.as_deref());
   r.check_with("iam:CreateRole", &role, &context)?;
   ```

   Parameters come from `r.p` (`required`, `optional`, `list`, `members`, `tags`,
   `page`); a constraint error is `ApiError::constraint`, AWS's wording.
4. **The operation** is a `Draft` method with all its checks (`crates/iam/src/ops.rs`,
   `crates/iam/src/ops/roles.rs`), called once through `Iam::change`, so import
   (`crates/iam/src/transfer.rs`) runs the same checks. AWS's limits live in
   `crates/iam/src/rules.rs`; errors are `IamError` variants with AWS's code and status.
   New tables or columns: follow the `changing-on-disk-format` skill.
5. **Temporary credentials.** Which APIs a session may call is decided in two places:
   `sts::permitted` (STS) and `Session::may_manage` (IAM and the admin API) in
   `crates/iam/src/snapshot.rs`. What a session is made of is `sessions::Claims`; a
   change to it bumps `VERSION` only if older tokens can't be read the new way (a new
   optional field with `#[serde(default)]`, as `web`, doesn't). A new kind of session is
   a `sessions::Who` variant holding unique ids, resolved against IAM as it is now in
   `Snapshot::build_session`, and a `SessionKind` that both places above must handle.
   Every action that issues credentials takes `min_token_size(r)?` and issues with
   `Iam::issue_at_least`, so `MinimumSessionTokenSize` works everywhere.
   An action whose request proves who is asking by itself (`AssumeRoleWithWebIdentity`,
   MinIO's `AssumeRoleWithLDAPIdentity`, `AssumeRoleWithCertificate` and
   `AssumeRoleWithCustomToken`) is answered
   unsigned: `Iam::proves_itself`
   picks it out in `crates/s3/src/iam_api.rs`, and `Iam::serve_self_proving` does the
   async part (fetching the provider's keys, asking the directory or the identity
   plugin, in `Iam::prove` after the action's own request check) before the sync handler
   runs as the anonymous identity; their answer reaches the handler as `Run.proved`
   (`Proved::Ldap`, `Proved::Plugin`, `Proved::UserInfo`), and the connection's client certificates as
   `Run.certificates`
   (from `Call::certificates`). Tests get a local identity provider from
   `oidc::keys::tests::publishing` (plain HTTP) or `publishing_with` and
   `oidc::tls::tests::Authority` (TLS, own CA), and a directory from
   `ldap::fake::FakeLdap` (feature `fake-ldap` outside the crate), and a plugin from
   `plugin::fake::FakePlugin` (feature `fake-plugin`). A query parameter that carries a
   proof goes in `SECRET_QUERY` in `crates/s3/src/audit.rs`.
   A MinIO action AWS doesn't have goes in `check_reference`'s `minio` list in
   `crates/iam/src/api/tests.rs`, which checks the others against AWS's reference.
6. **Tests**:
   - `every_parameter` in `crates/iam/src/api/tests.rs` needs the action's parameters,
     so `every_action_is_authorized` refuses it to a user without permissions;
   - API tests beside the others (`crates/iam/src/api/tests.rs`, STS in
     `crates/iam/src/api/tests/sessions.rs`), with AWS's error codes;
   - end to end with the AWS SDK: `crates/server/tests/iam_api.rs`, and
     `crates/server/tests/sts.rs` for credentials used against S3.
7. **Docs**: the IAM or STS row in `docs/COMPATIBILITY.md` (action count included),
   `README.md`'s support table, `docs/SECURITY_MODEL.md` for anything that changes who
   may do what, and `CHANGELOG.md`.
8. Run the `verifying-changes` skill, and try the action with `aws iam` or `aws sts`
   (`--endpoint-url`) against `teifs serve`.
