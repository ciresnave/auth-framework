// SPDX-License-Identifier: MIT OR Apache-2.0
//! RBAC Metrics Collection and Processing
//!
//! This module provides metrics collection, aggregation, and analysis
//! for RBAC system performance and usage patterns.
//!
//! > **Status:** Event persistence is wired up today, and higher-level metrics
//! > currently reflect the analytics events collected so far.

use super::{AnalyticsError, AnalyticsEvent};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Metrics collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Collection interval in seconds
    pub collection_interval: u64,

    /// Retention period in days
    pub retention_days: u32,

    /// Enable detailed metrics
    pub detailed_metrics: bool,

    /// Enable performance profiling
    pub performance_profiling: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            collection_interval: 60,
            retention_days: 90,
            detailed_metrics: true,
            performance_profiling: false,
        }
    }
}

/// Metrics collector
pub struct MetricsCollector {
    _config: MetricsConfig,
    storage: Arc<dyn AuthStorage>,
    current_metrics: HashMap<String, f64>,
}

impl MetricsCollector {
    /// Create new metrics collector
    pub fn new(config: MetricsConfig, storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            _config: config,
            storage,
            current_metrics: HashMap::new(),
        }
    }

    /// Collect metrics from events
    pub async fn collect_metrics(
        &mut self,
        events: &[AnalyticsEvent],
    ) -> Result<(), AnalyticsError> {
        for event in events {
            match event.event_type {
                crate::analytics::RbacEventType::PermissionCheck => {
                    *self
                        .current_metrics
                        .entry("permission_checks_total".to_string())
                        .or_insert(0.0) += 1.0;
                    if let Some(action) = &event.action {
                        if action == "Granted" {
                            *self
                                .current_metrics
                                .entry("permission_grants_total".to_string())
                                .or_insert(0.0) += 1.0;
                        } else {
                            *self
                                .current_metrics
                                .entry("permission_denies_total".to_string())
                                .or_insert(0.0) += 1.0;
                        }
                    }
                }
                crate::analytics::RbacEventType::RoleAssignment => {
                    *self
                        .current_metrics
                        .entry("role_assignments_total".to_string())
                        .or_insert(0.0) += 1.0;
                }
                _ => {
                    *self
                        .current_metrics
                        .entry("other_events_total".to_string())
                        .or_insert(0.0) += 1.0;
                }
            }
        }

        let json_data = serde_json::to_vec(&self.current_metrics).unwrap_or_default();
        let _ = self
            .storage
            .store_kv("current_metrics_snapshot", &json_data, None)
            .await;

        Ok(())
    }

    /// Get current metrics
    pub fn get_current_metrics(&self) -> &HashMap<String, f64> {
        &self.current_metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert_eq!(config.collection_interval, 60);
        assert_eq!(config.retention_days, 90);
        assert!(config.detailed_metrics);
        assert!(!config.performance_profiling);
    }

    #[test]
    fn test_metrics_collector_starts_empty() {
        let collector = MetricsCollector::new(
            MetricsConfig::default(),
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
        assert!(collector.get_current_metrics().is_empty());
    }

    #[tokio::test]
    async fn test_collect_metrics_no_op_succeeds() {
        let mut collector = MetricsCollector::new(
            MetricsConfig::default(),
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
        let result = collector.collect_metrics(&[]).await;
        assert!(result.is_ok());
        assert!(collector.get_current_metrics().is_empty());
    }
}
