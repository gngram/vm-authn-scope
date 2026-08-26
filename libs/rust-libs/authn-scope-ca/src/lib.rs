//! authn-scope CA engine — pure-Rust certificate authority.
//!
//! This crate provides:
//! - [`ca::CertificateAuthority`] — load/generate the CA key and certificate.
//! - [`signing::sign_csr`] — sign a PKCS#10 CSR.

pub mod ca;
pub mod error;
pub mod signing;

pub use ca::CertificateAuthority;
pub use error::CaError;
