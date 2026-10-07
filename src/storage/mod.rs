//! Storage backends for the authentication framework.
//!
//! This module provides the [`AuthStorage`] trait and multiple backend
//! implementations:
//!
//! | Backend | Feature flag | Module |
//! |---------|-------------|--------|
//! | In-memory (HashMap) | *(always available)* | [`memory`] |
//! | In-memory (DashMap) | *(always available)* | [`dashmap_memory`] |
//! | Redis | `redis-storage` | [`redis`] |
//! | PostgreSQL | `postgres-storage` | [`postgres`] |
//! | SQLite | `sqlite-storage` | [`sqlite`] |
//! | AES-256-GCM encrypted wrapper | *(always available)* | [`encryption`] |
//!
//! All backends implement [`AuthStorage`], so they can be used
//! interchangeably via `dyn AuthStorage` or generics.

pub mod core;
pub mod dashmap_memory; // DashMap-based storage proof-of-concept
pub mod encryption; // AES-256-GCM encryption for storage at rest
pub(crate) mod factory;
pub mod memory;
#[cfg(feature = "postgres-storage")]
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "sqlite-storage")]
pub mod sqlite;

// Performance optimized unified storage
#[cfg(feature = "performance-optimization")]
pub mod unified;

// Re-export the main storage traits and types
pub use core::*;
pub use encryption::{EncryptedStorage, StorageEncryption};

// Re-export unified storage when feature is enabled
#[cfg(feature = "performance-optimization")]
pub use unified::{StorageStats, UnifiedStorage, UnifiedStorageConfig};

// Convenience re-export for common trait
pub use crate::storage::core::AuthStorage;
