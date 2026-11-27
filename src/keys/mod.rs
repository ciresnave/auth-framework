// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key management: one model for every key a client or server generates.
//!
//! KM1 (ROADMAP) is the model only: [`KeyKind`], [`Kid`], [`KeyState`] with its
//! legal transitions, the single RFC 7638 thumbprint ([`jwk_thumbprint`]), the
//! public export forms ([`PublicJwk`], [`JwkSet`], [`spki_pem`]) and the
//! [`Signer`] trait through which a key signs without its private bytes ever
//! being returned. Creation (KM2) and storage (KM3) build on these.

mod cert;
mod export;
mod generate;
mod kind;
mod rotation;
mod state;
mod store;
mod thumbprint;

pub use cert::{
    CertSubject, certificate_request_for_key, certificate_request_from_csr,
    certificate_signing_request, jwk_with_x5c, self_signed_certificate, x5t_s256,
};
pub use export::{JwkSet, PublicJwk, spki_pem};
pub use generate::{LocalKey, SigningAlg, SymmetricKey};
pub use kind::{KeyKind, Kid, Signer};
pub use rotation::{NewKey, compromise, due_for_rotation, retire_expired, revoke, rotate};
pub use state::KeyState;
#[cfg(feature = "key-agreement")]
pub use store::agree;
pub use store::{
    FileKeyStore, KeyInfo, KeyStore, MemoryKeyStore, RevokedKey, StoreCapabilities, publish_jwks,
    revocation_list, unix_now,
};
pub use thumbprint::{jwk_thumbprint, jwk_thumbprint_value};
