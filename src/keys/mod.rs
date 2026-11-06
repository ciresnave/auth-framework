//! Key management: one model for every key a client or server generates.
//!
//! KM1 (ROADMAP) is the model only: [`KeyKind`], [`Kid`], [`KeyState`] with its
//! legal transitions, the single RFC 7638 thumbprint ([`jwk_thumbprint`]), the
//! public export forms ([`PublicJwk`], [`JwkSet`], [`spki_pem`]) and the
//! [`Signer`] trait through which a key signs without its private bytes ever
//! being returned. Creation (KM2) and storage (KM3) build on these.

mod export;
mod generate;
mod kind;
mod state;
mod thumbprint;

pub use export::{JwkSet, PublicJwk, spki_pem};
pub use generate::{LocalKey, SigningAlg, SymmetricKey};
pub use kind::{KeyKind, Kid, Signer};
pub use state::KeyState;
pub use thumbprint::{jwk_thumbprint, jwk_thumbprint_value};
