//! Shared wire types and codec for the authn-scope protocol.

pub mod codec;
pub mod wire;

pub mod spiffe {
    pub mod workload {
        tonic::include_proto!("_");
    }
}
