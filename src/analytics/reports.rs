//! RBAC Analytics Reports
//!
//! This module provides comprehensive reporting capabilities
//! for RBAC analytics data.
//!
//! > **Status:** Report generation is available today using the analytics
//! > events and snapshots currently persisted by the framework.

use super::{AnalyticsError, ReportType, TimeRange};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Report generator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Output format
    pub format: ReportFormat,

    /// Include charts in reports
    pub include_charts: bool,

    /// Report template
    pub template: Option<String>,
}

/// Report output formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    Json,
    Html,
    Pdf,
    Csv,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Json,
            include_charts: true,
            template: None,
        }
    }
}

/// Report generator
pub struct ReportGenerator {
    _config: ReportConfig,
    storage: Arc<dyn AuthStorage>,
}

impl ReportGenerator {
    /// Create new report generator
    pub fn new(config: ReportConfig, storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            _config: config,
            storage,
        }
    }

    /// Generate report
    pub async fn generate_report(
        &self,
        report_type: ReportType,
        time_range: TimeRange,
    ) -> Result<String, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();

        let mut total_events: u64 = 0;
        let mut success_count: u64 = 0;
        let mut failure_count: u64 = 0;
        let mut event_types: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut total_duration_ms: f64 = 0.0;
        let mut duration_count: u64 = 0;

        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<crate::analytics::AnalyticsEvent>(&data)
            {
                // Filter by time range
                if event.timestamp < time_range.start || event.timestamp > time_range.end {
                    continue;
                }
                total_events += 1;
                match event.result {
                    crate::analytics::EventResult::Success => success_count += 1,
                    _ => failure_count += 1,
                }
                *event_types
                    .entry(format!("{:?}", event.event_type))
                    .or_insert(0) += 1;
                if let Some(d) = event.duration_ms {
                    total_duration_ms += d as f64;
                    duration_count += 1;
                }
            }
        }

        let avg_duration_ms = if duration_count > 0 {
            total_duration_ms / duration_count as f64
        } else {
            0.0
        };
        let success_rate = if total_events > 0 {
            (success_count as f64 / total_events as f64) * 100.0
        } else {
            0.0
        };

        let report = serde_json::json!({
            "report_type": format!("{:?}", report_type),
            "time_range": {
                "start": time_range.start.to_rfc3339(),
                "end": time_range.end.to_rfc3339(),
            },
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "summary": {
                "total_events": total_events,
                "success_count": success_count,
                "failure_count": failure_count,
                "success_rate_percent": (success_rate * 100.0).round() / 100.0,
                "avg_duration_ms": (avg_duration_ms * 100.0).round() / 100.0,
            },
            "event_type_breakdown": event_types,
        });

        serde_json::to_string_pretty(&report).map_err(AnalyticsError::SerializationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_config_default() {
        let config = ReportConfig::default();
        assert!(config.include_charts);
        assert!(config.template.is_none());
        assert!(matches!(config.format, ReportFormat::Json));
    }

    #[test]
    fn test_report_generator_creation() {
        let config = ReportConfig::default();
        let _gen = ReportGenerator::new(
            config,
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
    }

    #[tokio::test]
    async fn test_generate_report_returns_content() {
        let generator = ReportGenerator::new(
            ReportConfig::default(),
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
        let range = TimeRange::last_days(7);
        let report = generator
            .generate_report(ReportType::Daily, range)
            .await
            .unwrap();
        assert!(!report.is_empty());
    }
}
