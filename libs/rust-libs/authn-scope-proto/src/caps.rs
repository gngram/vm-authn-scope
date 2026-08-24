//! Capability and RBAC/CBAC data structures embedded in issued certificates.

use serde::{Deserialize, Serialize};

/// A single path with associated access rights.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathAccess {
    /// The resource path (e.g. "/api/v1/data").
    pub path: String,
    /// Access modes granted (e.g. ["read", "write"]).
    pub access: Vec<String>,
}

/// A capability grants the certificate holder permission to access
/// specific RPC modules, methods, and HTTP-style paths on a target VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Human-readable name of the target VM.
    pub target_vm: String,
    /// RPC service modules accessible on the target.
    pub rpc_modules: Vec<String>,
    /// Specific RPC methods accessible (format: "module.method").
    pub rpc_methods: Vec<String>,
    /// Path-based access rules.
    pub paths: Vec<PathAccess>,
}

/// JWT-style capability claim embedded as a custom X.509 extension.
///
/// This is the payload of the capability JWT that is embedded in issued
/// certificates under OID 1.3.6.1.4.1.99999.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapClaim {
    /// Issuer: always "authn-scope-ca".
    pub iss: String,
    /// Subject: the entity (service) name.
    pub sub: String,
    /// VM name of the certificate holder.
    pub vm: String,
    /// vsock CID of the certificate holder's VM.
    pub cid: u32,
    /// Issued-at timestamp (Unix seconds).
    pub iat: i64,
    /// Expiry timestamp (Unix seconds).
    pub exp: i64,
    /// The actual capability grants.
    pub caps: Vec<Capability>,
}
