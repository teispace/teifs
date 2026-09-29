//! The security suite: one module per class of vulnerability found in S3 servers
//! (`docs/SECURITY_MODEL.md` lists them), each test named after what it prevents and
//! the advisories that found it elsewhere. Where another test file already proves a
//! rule, the module's documentation names that test instead of repeating it.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../common/mod.rs"]
mod common;
mod sign;

mod cors;
mod disclosure;
mod paths;
mod policy;
mod signatures;
