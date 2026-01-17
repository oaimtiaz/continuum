//! Continuum Protocol - Protobuf types for client-daemon communication

/// Generated protobuf types for main Continuum service
pub mod continuum {
    tonic::include_proto!("continuum");
}

/// Generated protobuf types for enrollment service
pub mod enrollment {
    pub mod v1 {
        tonic::include_proto!("continuum.enrollment.v1");
    }
}

pub use continuum::*;

/// File descriptor set for gRPC reflection
pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("continuum_descriptor");
