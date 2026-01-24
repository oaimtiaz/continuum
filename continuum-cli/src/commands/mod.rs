//! CLI commands.

pub mod clients;
pub mod enroll;

pub use enroll::{
    check_status, compute_local_trust_proof, generate_token_remote, read_local_server_fingerprint,
    run_enrollment, run_local_enrollment, EnrollmentResult, IdentityStore,
};
