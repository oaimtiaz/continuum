//! Trust primitives for server pinning (known_hosts).

mod known_hosts;

pub use known_hosts::{evaluate_server_trust, KnownHosts, TrustDecision};
