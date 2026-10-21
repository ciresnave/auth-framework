//! Architecture enhancements for scalability and maintainability
//!
//! This module provides advanced architectural patterns including:
//! - Tiered storage with hot/cold data separation
//! - Event sourcing for comprehensive audit trails
//! - Configuration hot-reload for zero-downtime updates
//! - Advanced caching strategies
//! - Microservice-ready components

use crate::{
    errors::{AuthError, Result},
    storage::AuthStorage,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    fs,
    sync::{RwLock, broadcast},
    time::interval,
};

#[cfg(feature = "notify")]
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};

/// Tiered storage manager with hot/cold data separation
pub struct TieredStorageManager {
    /// Hot tier for frequently accessed data (in-memory)
    hot_tier: Arc<dyn AuthStorage + Send + Sync>,

    /// Warm tier for moderately accessed data (Redis/fast disk)
    warm_tier: Arc<dyn AuthStorage + Send + Sync>,

    /// Cold tier for archival data (disk/object storage)
    cold_tier: Arc<dyn AuthStorage + Send + Sync>,

    /// Access frequency tracking
    access_tracker: Arc<RwLock<HashMap<String, AccessMetadata>>>,

    /// Configuration
    config: TieredStorageConfig,

    /// Statistics
    stats: Arc<TieredStorageStats>,
}

/// Access metadata for intelligent tiering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessMetadata {
    pub access_count: u64,
    pub last_access: SystemTime,
    pub creation_time: SystemTime,
    pub current_tier: StorageTier,
    pub data_size: usize,
    pub access_frequency: f64, // accesses per hour
}

/// Storage tier levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,  // In-memory, ultra-fast access
    Warm, // Redis/SSD, fast access
    Cold, // Disk/object storage, slower access
}

/// Tiered storage configuration
#[derive(Debug, Clone)]
pub struct TieredStorageConfig {
    pub hot_tier_max_size: usize,
    pub warm_tier_max_size: usize,
    pub hot_tier_ttl: Duration,
    pub warm_tier_ttl: Duration,
    pub promotion_threshold: f64, // access frequency to promote
    pub demotion_threshold: f64,  // access frequency to demote
    pub cleanup_interval: Duration,
}

impl Default for TieredStorageConfig {
    fn default() -> Self {
        Self {
            hot_tier_max_size: 100_000,                 // 100k entries
            warm_tier_max_size: 1_000_000,              // 1M entries
            hot_tier_ttl: Duration::from_secs(3600),    // 1 hour
            warm_tier_ttl: Duration::from_secs(86400),  // 24 hours
            promotion_threshold: 10.0,                  // 10 accesses/hour
            demotion_threshold: 1.0,                    // 1 access/hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Tiered storage statistics
#[derive(Debug, Default)]
pub struct TieredStorageStats {
    pub hot_tier_hits: AtomicU64,
    pub warm_tier_hits: AtomicU64,
    pub cold_tier_hits: AtomicU64,
    pub promotions: AtomicU64,
    pub demotions: AtomicU64,
    pub total_requests: AtomicU64,
}

impl TieredStorageManager {
    pub fn new(
        hot_tier: Arc<dyn AuthStorage + Send + Sync>,
        warm_tier: Arc<dyn AuthStorage + Send + Sync>,
        cold_tier: Arc<dyn AuthStorage + Send + Sync>,
    ) -> Self {
        Self::with_config(
            hot_tier,
            warm_tier,
            cold_tier,
            TieredStorageConfig::default(),
        )
    }

    pub fn with_config(
        hot_tier: Arc<dyn AuthStorage + Send + Sync>,
        warm_tier: Arc<dyn AuthStorage + Send + Sync>,
        cold_tier: Arc<dyn AuthStorage + Send + Sync>,
        config: TieredStorageConfig,
    ) -> Self {
        let manager = Self {
            hot_tier,
            warm_tier,
            cold_tier,
            access_tracker: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(TieredStorageStats::default()),
        };

        manager.start_background_tasks();
        manager
    }

    fn start_background_tasks(&self) {
        self.start_tier_management();
        self.start_cleanup_task();
    }

    fn start_tier_management(&self) {
        let access_tracker = Arc::clone(&self.access_tracker);
        let hot_tier = Arc::clone(&self.hot_tier);
        let warm_tier = Arc::clone(&self.warm_tier);
        let cold_tier = Arc::clone(&self.cold_tier);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(config.cleanup_interval);

            loop {
                interval.tick().await;

                let mut tracker = access_tracker.write().await;
                let now = SystemTime::now();

                for (key, metadata) in tracker.iter_mut() {
                    // Calculate access frequency (per hour)
                    let hours_since_creation = now
                        .duration_since(metadata.creation_time)
                        .unwrap_or_default()
                        .as_secs_f64()
                        / 3600.0;

                    if hours_since_creation > 0.0 {
                        metadata.access_frequency =
                            metadata.access_count as f64 / hours_since_creation;
                    }

                    // Determine if tier change is needed
                    let should_promote = metadata.current_tier != StorageTier::Hot
                        && metadata.access_frequency > config.promotion_threshold;

                    let should_demote = metadata.current_tier == StorageTier::Hot
                        && metadata.access_frequency < config.demotion_threshold;

                    if should_promote {
                        // Promote to higher tier
                        Self::promote_data(
                            key, metadata, &hot_tier, &warm_tier, &cold_tier, &stats, &config,
                        )
                        .await;
                    } else if should_demote {
                        // Demote to lower tier
                        Self::demote_data(
                            key, metadata, &hot_tier, &warm_tier, &cold_tier, &stats, &config,
                        )
                        .await;
                    }
                }
            }
        });
    }

    fn start_cleanup_task(&self) {
        let access_tracker = Arc::clone(&self.access_tracker);
        let _config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Hourly cleanup

            loop {
                interval.tick().await;

                let mut tracker = access_tracker.write().await;
                let now = SystemTime::now();

                // Remove metadata for very old, inactive entries
                tracker.retain(|_, metadata| {
                    now.duration_since(metadata.last_access).unwrap_or_default()
                        < Duration::from_secs(86400 * 7) // Keep metadata for 7 days
                });
            }
        });
    }

    async fn promote_data(
        key: &str,
        metadata: &mut AccessMetadata,
        hot_tier: &Arc<dyn AuthStorage + Send + Sync>,
        warm_tier: &Arc<dyn AuthStorage + Send + Sync>,
        cold_tier: &Arc<dyn AuthStorage + Send + Sync>,
        stats: &Arc<TieredStorageStats>,
        config: &TieredStorageConfig,
    ) {
        let (source_tier, target_tier, target_ttl): (
            &Arc<dyn AuthStorage + Send + Sync>,
            &Arc<dyn AuthStorage + Send + Sync>,
            Duration,
        ) = match metadata.current_tier {
            StorageTier::Cold => (cold_tier, warm_tier, config.warm_tier_ttl),
            StorageTier::Warm => (warm_tier, hot_tier, config.hot_tier_ttl),
            StorageTier::Hot => return, // Already at highest tier
        };

        match source_tier.get_kv(key).await {
            Ok(Some(data)) => {
                if let Err(e) = target_tier.store_kv(key, &data, Some(target_ttl)).await {
                    tracing::warn!(
                        "Tier promotion: failed to write '{}' to target tier: {}",
                        key,
                        e
                    );
                    return;
                }
                if let Err(e) = source_tier.delete_kv(key).await {
                    // Data is already in the target tier; log and continue rather than abort.
                    tracing::warn!(
                        "Tier promotion: failed to delete '{}' from source tier (duplicate tolerated): {}",
                        key,
                        e
                    );
                }
                stats.promotions.fetch_add(1, Ordering::Relaxed);
                metadata.current_tier = match metadata.current_tier {
                    StorageTier::Cold => StorageTier::Warm,
                    StorageTier::Warm => StorageTier::Hot,
                    StorageTier::Hot => StorageTier::Hot,
                };
            }
            Ok(None) => {
                tracing::debug!(
                    "Tier promotion: key '{}' not found in source tier; skipping",
                    key
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Tier promotion: failed to read '{}' from source tier: {}",
                    key,
                    e
                );
            }
        }
    }

    async fn demote_data(
        key: &str,
        metadata: &mut AccessMetadata,
        hot_tier: &Arc<dyn AuthStorage + Send + Sync>,
        warm_tier: &Arc<dyn AuthStorage + Send + Sync>,
        cold_tier: &Arc<dyn AuthStorage + Send + Sync>,
        stats: &Arc<TieredStorageStats>,
        config: &TieredStorageConfig,
    ) {
        if metadata.current_tier == StorageTier::Cold {
            return; // Already at lowest tier
        }

        // Cold tier has no TTL (archival storage).
        let (source_tier, target_tier, target_ttl): (
            &Arc<dyn AuthStorage + Send + Sync>,
            &Arc<dyn AuthStorage + Send + Sync>,
            Option<Duration>,
        ) = match metadata.current_tier {
            StorageTier::Hot => (hot_tier, warm_tier, Some(config.warm_tier_ttl)),
            StorageTier::Warm => (warm_tier, cold_tier, None),
            StorageTier::Cold => return,
        };

        match source_tier.get_kv(key).await {
            Ok(Some(data)) => {
                if let Err(e) = target_tier.store_kv(key, &data, target_ttl).await {
                    tracing::warn!(
                        "Tier demotion: failed to write '{}' to target tier: {}",
                        key,
                        e
                    );
                    return;
                }
                if let Err(e) = source_tier.delete_kv(key).await {
                    tracing::warn!(
                        "Tier demotion: failed to delete '{}' from source tier (duplicate tolerated): {}",
                        key,
                        e
                    );
                }
                stats.demotions.fetch_add(1, Ordering::Relaxed);
                metadata.current_tier = match metadata.current_tier {
                    StorageTier::Hot => StorageTier::Warm,
                    StorageTier::Warm => StorageTier::Cold,
                    StorageTier::Cold => StorageTier::Cold,
                };
            }
            Ok(None) => {
                tracing::debug!(
                    "Tier demotion: key '{}' not found in source tier; skipping",
                    key
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Tier demotion: failed to read '{}' from source tier: {}",
                    key,
                    e
                );
            }
        }
    }

    async fn track_access(&self, key: &str, tier: StorageTier) {
        let mut tracker = self.access_tracker.write().await;
        let now = SystemTime::now();

        match tracker.get_mut(key) {
            Some(metadata) => {
                metadata.access_count += 1;
                metadata.last_access = now;
            }
            None => {
                tracker.insert(
                    key.to_string(),
                    AccessMetadata {
                        access_count: 1,
                        last_access: now,
                        creation_time: now,
                        current_tier: tier,
                        data_size: 0, // Would be set from actual data
                        access_frequency: 0.0,
                    },
                );
            }
        }

        // Update statistics
        match tier {
            StorageTier::Hot => self.stats.hot_tier_hits.fetch_add(1, Ordering::Relaxed),
            StorageTier::Warm => self.stats.warm_tier_hits.fetch_add(1, Ordering::Relaxed),
            StorageTier::Cold => self.stats.cold_tier_hits.fetch_add(1, Ordering::Relaxed),
        };

        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> TieredStorageStatsSummary {
        let hot_hits = self.stats.hot_tier_hits.load(Ordering::Relaxed);
        let warm_hits = self.stats.warm_tier_hits.load(Ordering::Relaxed);
        let cold_hits = self.stats.cold_tier_hits.load(Ordering::Relaxed);
        let total = self.stats.total_requests.load(Ordering::Relaxed);

        TieredStorageStatsSummary {
            hot_tier_hit_rate: if total > 0 {
                (hot_hits as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            warm_tier_hit_rate: if total > 0 {
                (warm_hits as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            cold_tier_hit_rate: if total > 0 {
                (cold_hits as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            total_requests: total,
            promotions: self.stats.promotions.load(Ordering::Relaxed),
            demotions: self.stats.demotions.load(Ordering::Relaxed),
        }
    }

    /// Retrieve data from hot tier with access tracking
    pub async fn get_from_hot(&self, key: &str) -> Option<Vec<u8>> {
        self.track_access(key, StorageTier::Hot).await;
        self.hot_tier.get_kv(key).await.ok().flatten()
    }

    /// Retrieve data from warm tier with access tracking
    pub async fn get_from_warm(&self, key: &str) -> Option<Vec<u8>> {
        self.track_access(key, StorageTier::Warm).await;
        self.warm_tier.get_kv(key).await.ok().flatten()
    }

    /// Retrieve data from cold tier with access tracking
    pub async fn get_from_cold(&self, key: &str) -> Option<Vec<u8>> {
        self.track_access(key, StorageTier::Cold).await;
        self.cold_tier.get_kv(key).await.ok().flatten()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredStorageStatsSummary {
    pub hot_tier_hit_rate: f64,
    pub warm_tier_hit_rate: f64,
    pub cold_tier_hit_rate: f64,
    pub total_requests: u64,
    pub promotions: u64,
    pub demotions: u64,
}

/// Event sourcing implementation for audit trails
pub struct EventSourcingManager {
    /// Event store
    event_store: Arc<RwLock<Vec<DomainEvent>>>,

    /// Event stream broadcasters
    event_broadcasters: HashMap<String, broadcast::Sender<DomainEvent>>,

    /// Snapshots for performance
    snapshots: Arc<RwLock<HashMap<String, EventSnapshot>>>,

    /// Configuration
    config: EventSourcingConfig,
}

/// Domain event for event sourcing
#[derive(Clone, Serialize, Deserialize)]
pub struct DomainEvent {
    pub event_id: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub event_version: u64,
    pub timestamp: SystemTime,
    pub data: serde_json::Value,
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Debug for DomainEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("DomainEvent");
        d.field("event_id", &self.event_id);
        d.field("aggregate_id", &self.aggregate_id);
        d.field("event_type", &self.event_type);
        d.field("event_version", &self.event_version);
        d.field("timestamp", &self.timestamp);
        d.field("data", &crate::utils::redact::redacted(&self.data));
        d.field("metadata", &self.metadata);
        d.finish()
    }
}

/// Event snapshot for performance optimization
#[derive(Clone, Serialize, Deserialize)]
pub struct EventSnapshot {
    pub aggregate_id: String,
    pub version: u64,
    pub timestamp: SystemTime,
    pub data: serde_json::Value,
}

impl std::fmt::Debug for EventSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("EventSnapshot");
        d.field("aggregate_id", &self.aggregate_id);
        d.field("version", &self.version);
        d.field("timestamp", &self.timestamp);
        d.field("data", &crate::utils::redact::redacted(&self.data));
        d.finish()
    }
}

/// Event sourcing configuration
#[derive(Debug, Clone)]
pub struct EventSourcingConfig {
    pub snapshot_interval: u64,
    pub max_events_in_memory: usize,
    pub event_retention_days: u64,
}

impl Default for EventSourcingConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: 100,
            max_events_in_memory: 10_000,
            event_retention_days: 365,
        }
    }
}

impl Default for EventSourcingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSourcingManager {
    pub fn new() -> Self {
        Self::with_config(EventSourcingConfig::default())
    }

    pub fn with_config(config: EventSourcingConfig) -> Self {
        Self {
            event_store: Arc::new(RwLock::new(Vec::new())),
            event_broadcasters: HashMap::new(),
            snapshots: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Append event to the event store
    pub async fn append_event(&self, event: DomainEvent) -> Result<()> {
        let mut store = self.event_store.write().await;
        store.push(event.clone());

        // Broadcast event to subscribers
        if let Some(broadcaster) = self.event_broadcasters.get(&event.aggregate_id) {
            let _ = broadcaster.send(event.clone());
        }

        // Check if snapshot is needed
        if event
            .event_version
            .is_multiple_of(self.config.snapshot_interval)
        {
            self.create_snapshot(&event.aggregate_id).await?;
        }

        Ok(())
    }

    /// Get events for an aggregate
    pub async fn get_events(
        &self,
        aggregate_id: &str,
        from_version: Option<u64>,
    ) -> Vec<DomainEvent> {
        let store = self.event_store.read().await;
        let from_version = from_version.unwrap_or(0);

        store
            .iter()
            .filter(|event| {
                event.aggregate_id == aggregate_id && event.event_version >= from_version
            })
            .cloned()
            .collect()
    }

    /// Create snapshot for performance
    async fn create_snapshot(&self, aggregate_id: &str) -> Result<()> {
        let events = self.get_events(aggregate_id, None).await;

        if let Some(latest_event) = events.last() {
            let first_version = events.first().map(|e| e.event_version).unwrap_or(0);
            let snapshot = EventSnapshot {
                aggregate_id: aggregate_id.to_string(),
                version: latest_event.event_version,
                timestamp: SystemTime::now(),
                data: serde_json::json!({
                    "event_count": events.len(),
                    "first_version": first_version,
                    "latest_version": latest_event.event_version,
                    "last_event_timestamp": latest_event.timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    "last_event_type": &latest_event.event_type,
                }),
            };

            let mut snapshots = self.snapshots.write().await;
            snapshots.insert(aggregate_id.to_string(), snapshot);
        }

        Ok(())
    }

    /// Subscribe to events for an aggregate
    pub fn subscribe_to_events(&mut self, aggregate_id: &str) -> broadcast::Receiver<DomainEvent> {
        let (tx, rx) = broadcast::channel(1000);
        self.event_broadcasters.insert(aggregate_id.to_string(), tx);
        rx
    }
}

/// Configuration hot-reload manager
pub struct ConfigHotReloadManager {
    /// Configuration file path
    config_path: String,

    /// Current configuration
    current_config: Arc<RwLock<serde_json::Value>>,

    /// Configuration change broadcaster
    config_broadcaster: broadcast::Sender<ConfigChangeEvent>,

    /// File watcher
    #[cfg(feature = "notify")]
    _watcher: Option<RecommendedWatcher>,
}

/// Configuration change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeEvent {
    pub timestamp: SystemTime,
    pub path: String,
    pub change_type: ConfigChangeType,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigChangeType {
    Added,
    Modified,
    Removed,
    Reloaded,
}

impl ConfigHotReloadManager {
    pub async fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_string_lossy().to_string();
        let (config_broadcaster, _) = broadcast::channel(100);

        // Load initial configuration
        let initial_config = Self::load_config(&config_path).await?;
        let current_config = Arc::new(RwLock::new(initial_config));

        let mut manager = Self {
            config_path: config_path.clone(),
            current_config,
            config_broadcaster,
            #[cfg(feature = "notify")]
            _watcher: None,
        };

        // Setup file watcher
        #[cfg(feature = "notify")]
        {
            manager.setup_file_watcher().await?;
        }

        Ok(manager)
    }

    async fn load_config(path: &str) -> Result<serde_json::Value> {
        let content = fs::read_to_string(path)
            .await
            .map_err(|e| AuthError::Configuration {
                message: format!("Failed to read config file: {}", e),
                source: Some(Box::new(e)),
                help: Some("Check that the config file exists and is readable".to_string()),
                docs_url: Some(
                    "https://docs.rs/auth-framework/latest/auth_framework/config/".to_string(),
                ),
                suggested_fix: Some("Verify file path and permissions".to_string()),
            })?;

        serde_json::from_str(&content).map_err(|e| AuthError::Configuration {
            message: format!("Failed to parse config: {}", e),
            source: Some(Box::new(e)),
            help: Some("Check that the config file contains valid JSON".to_string()),
            docs_url: Some(
                "https://docs.rs/auth-framework/latest/auth_framework/config/".to_string(),
            ),
            suggested_fix: Some("Validate JSON syntax using a JSON validator".to_string()),
        })
    }

    #[cfg(feature = "notify")]
    async fn setup_file_watcher(&mut self) -> Result<()> {
        use notify::Event;

        let config_path = self.config_path.clone();
        let current_config = Arc::clone(&self.current_config);
        let broadcaster = self.config_broadcaster.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    let config_path = config_path.clone();
                    let current_config = Arc::clone(&current_config);
                    let broadcaster = broadcaster.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_file_change(
                            event,
                            &config_path,
                            &current_config,
                            &broadcaster,
                        )
                        .await
                        {
                            tracing::error!("Error handling config file change: {}", e);
                        }
                    });
                }
            },
            Config::default(),
        )
        .map_err(|e| AuthError::Configuration {
            message: format!("Failed to create file watcher: {}", e),
            source: Some(Box::new(e)),
            help: Some("Check that the file system supports file watching".to_string()),
            docs_url: Some(
                "https://docs.rs/auth-framework/latest/auth_framework/config/".to_string(),
            ),
            suggested_fix: Some("Ensure the system has file watching capabilities".to_string()),
        })?;

        watcher
            .watch(Path::new(&self.config_path), RecursiveMode::NonRecursive)
            .map_err(|e| AuthError::Configuration {
                message: format!("Failed to watch config file: {}", e),
                source: Some(Box::new(e)),
                help: Some("Check that the config file path exists and is accessible".to_string()),
                docs_url: Some(
                    "https://docs.rs/auth-framework/latest/auth_framework/config/".to_string(),
                ),
                suggested_fix: Some("Verify the config file path is correct".to_string()),
            })?;

        self._watcher = Some(watcher);
        Ok(())
    }

    #[cfg(feature = "notify")]
    async fn handle_file_change(
        event: notify::Event,
        config_path: &str,
        current_config: &Arc<RwLock<serde_json::Value>>,
        broadcaster: &broadcast::Sender<ConfigChangeEvent>,
    ) -> Result<()> {
        use notify::EventKind;

        match event.kind {
            EventKind::Modify(_) | EventKind::Create(_) => {
                // Reload configuration
                match Self::load_config(config_path).await {
                    Ok(new_config) => {
                        let old_config = {
                            let mut config = current_config.write().await;
                            let old = config.clone();
                            *config = new_config.clone();
                            old
                        };

                        let change_event = ConfigChangeEvent {
                            timestamp: SystemTime::now(),
                            path: config_path.to_string(),
                            change_type: ConfigChangeType::Reloaded,
                            old_value: Some(old_config),
                            new_value: Some(new_config),
                        };

                        let _ = broadcaster.send(change_event);
                    }
                    Err(e) => {
                        tracing::error!("Failed to reload config: {}", e);
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> serde_json::Value {
        self.current_config.read().await.clone()
    }

    /// Subscribe to configuration changes
    pub fn subscribe_to_changes(&self) -> broadcast::Receiver<ConfigChangeEvent> {
        self.config_broadcaster.subscribe()
    }

    /// Manually reload configuration
    pub async fn reload(&self) -> Result<()> {
        let new_config = Self::load_config(&self.config_path).await?;
        let old_config = {
            let mut config = self.current_config.write().await;
            let old = config.clone();
            *config = new_config.clone();
            old
        };

        let change_event = ConfigChangeEvent {
            timestamp: SystemTime::now(),
            path: self.config_path.clone(),
            change_type: ConfigChangeType::Reloaded,
            old_value: Some(old_config),
            new_value: Some(new_config),
        };

        let _ = self.config_broadcaster.send(change_event);
        Ok(())
    }
}

impl Default for ConfigHotReloadManager {
    /// Creates a default `ConfigHotReloadManager` using a synchronous blocking call.
    ///
    /// # Panics
    /// Panics if called from within an async runtime (e.g. inside a Tokio task),
    /// because `block_on` cannot nest. Prefer calling `ConfigHotReloadManager::new()`
    /// directly in async contexts.
    fn default() -> Self {
        // Use tokio::runtime::Handle to detect if we're already in an async context.
        // If so, use spawn_blocking to avoid the block_on deadlock.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            std::thread::scope(|s| {
                s.spawn(|| {
                    handle.block_on(async {
                        Self::new("config.json")
                            .await
                            .expect("Failed to create config manager")
                    })
                })
                .join()
                .expect("ConfigHotReloadManager default thread panicked")
            })
        } else {
            futures::executor::block_on(async {
                Self::new("config.json")
                    .await
                    .expect("Failed to create config manager")
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::InMemoryStorage;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_tiered_storage_stats() {
        let hot_tier = Arc::new(InMemoryStorage::new()) as Arc<dyn AuthStorage + Send + Sync>;
        let warm_tier = Arc::new(InMemoryStorage::new()) as Arc<dyn AuthStorage + Send + Sync>;
        let cold_tier = Arc::new(InMemoryStorage::new()) as Arc<dyn AuthStorage + Send + Sync>;

        let manager = TieredStorageManager::new(hot_tier, warm_tier, cold_tier);

        // Simulate some access patterns
        manager.track_access("key1", StorageTier::Hot).await;
        manager.track_access("key2", StorageTier::Warm).await;
        manager.track_access("key3", StorageTier::Cold).await;

        let stats = manager.get_stats();
        assert_eq!(stats.total_requests, 3);
        assert!(stats.hot_tier_hit_rate > 0.0);
    }

    #[tokio::test]
    async fn test_tiered_storage_accessor_methods() {
        let hot_tier = Arc::new(InMemoryStorage::new()) as Arc<dyn AuthStorage + Send + Sync>;
        let warm_tier = Arc::new(InMemoryStorage::new()) as Arc<dyn AuthStorage + Send + Sync>;
        let cold_tier = Arc::new(InMemoryStorage::new()) as Arc<dyn AuthStorage + Send + Sync>;

        let manager = TieredStorageManager::new(hot_tier, warm_tier, cold_tier);

        // Test accessor methods with access tracking
        let _ = manager.get_from_hot("key1").await;
        let _ = manager.get_from_warm("key2").await;
        let _ = manager.get_from_cold("key3").await;

        let stats = manager.get_stats();
        assert_eq!(stats.total_requests, 3);

        // Use approximate equality for floating point comparisons
        let expected_rate = 100.0 / 3.0;
        let tolerance = 1e-10;
        assert!((stats.hot_tier_hit_rate - expected_rate).abs() < tolerance);
        assert!((stats.warm_tier_hit_rate - expected_rate).abs() < tolerance);
        assert!((stats.cold_tier_hit_rate - expected_rate).abs() < tolerance);
    }

    #[tokio::test]
    async fn test_event_sourcing() {
        let manager = EventSourcingManager::new();

        let event = DomainEvent {
            event_id: Uuid::new_v4().to_string(),
            aggregate_id: "user-123".to_string(),
            event_type: "UserCreated".to_string(),
            event_version: 1,
            timestamp: SystemTime::now(),
            data: serde_json::json!({"name": "John Doe"}),
            metadata: HashMap::new(),
        };

        manager.append_event(event.clone()).await.unwrap();

        let events = manager.get_events("user-123", None).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "UserCreated");
    }
}
