//! Protobuf definitions for shim↔daemon IPC.

pub mod shim {
    include!(concat!(env!("OUT_DIR"), "/continuum.shim.rs"));
}

pub use shim::*;
