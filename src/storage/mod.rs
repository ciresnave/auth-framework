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


