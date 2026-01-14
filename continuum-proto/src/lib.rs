//! Continuum Protocol - Protobuf types for client-daemon communication

/// Generated protobuf types
pub mod continuum {
    tonic::include_proto!("continuum");
}

pub use continuum::*;

/// File descriptor set for gRPC reflection
pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("continuum_descriptor");
