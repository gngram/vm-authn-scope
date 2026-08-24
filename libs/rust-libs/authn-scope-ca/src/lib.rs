//! authn-scope CA engine — pure-Rust certificate authority.
//!
//! This crate provides:
//! - [`ca::CertificateAuthority`] — load/generate the CA key and certificate.
//! - [`signing::sign_csr`] — sign a PKCS#10 CSR and embed capability claims.
//! - [`jwt::CapJwtSigner`] — build and sign the capability JWT.

pub mod ca;
pub mod error;
pub mod jwt;
pub mod signing;

pub use ca::CertificateAuthority;
pub use error::CaError;
