pub mod core;
pub mod dashmap_memory; // DashMap-based storage proof-of-concept
pub mod encryption; // AES-256-GCM encryption for storage at rest
pub mod memory;
#[cfg(feature = "mysql-storage")]
pub mod mysql;
#[cfg(feature = "postgres-storage")]
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;

// Re-export the main storage traits and types
pub use core::*;
pub use encryption::{EncryptedStorage, StorageEncryption};
