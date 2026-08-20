//! The `lns.run/v1` document grammar, specified in `docs/sandbox-spec.md`, and
//! the machine locations every crate resolves the same way, specified in
//! `docs/cli-spec.md` §9.
//!
//! One definition per concept, below every crate that reads or writes one, so a
//! sandbox, a connector and a mixin cannot drift apart in what they mean by it.
//! This crate depends on nothing of ours, which is what lets both `lns-policy`
//! and `lns-ipc` share a definition without either depending on the other.

pub mod credential;
pub mod paths;

pub use paths::lns_home;

pub use credential::{
    Credential, InjectionDef, InjectionKind, is_legal_connector_id, is_legal_env_var_name,
    is_self_identifying,
};
