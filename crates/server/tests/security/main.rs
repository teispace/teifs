//! The security suite: one module per class of vulnerability found in S3 servers
//! (`docs/SECURITY_MODEL.md` lists them), each test named after what it prevents and
//! the advisories that found it elsewhere. Where another test file already proves a
//! rule, the module's documentation names that test instead of repeating it.
//!
//! Classes proved wholly elsewhere:
//! - 2, every endpoint declares what it authorizes: `control.rs`
//!   (`every_endpoint_refuses_anonymous_callers_and_users_without_permission`), `admin.rs`
//!   (`users_need_teifs_actions`, `only_the_root_user_sees_secrets_or_imports`).
//! - 4, credentials can't be escalated: `iam_api.rs` (`users_manage_their_own_keys`),
//!   `sts.rs`, `admin.rs` (`role_sessions_manage_the_drive_and_other_sessions_do_not`).
//! - 5, no default secrets: `crates/server/src/credentials.rs`.
//! - 8, only trusted proxies say who the client is: `proxy.rs`
//!   (`nobody_else_can_say_who_the_client_is`).
//! - 11, input is bounded: `limits.rs`.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../common/mod.rs"]
mod common;
mod sign;

mod abac;
mod cors;
mod disclosure;
mod logs;
mod paths;
mod policy;
mod signatures;
