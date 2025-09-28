//! RBAC Analytics Dashboard
//!
//! This module provides dashboard components for visualizing
//! RBAC analytics data and system performance metrics.

use super::{AnalyticsError, TimeRange};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Refresh interval for real-time data
    pub refresh_interval_seconds: u32,

    /// Default time range for widgets
    pub default_time_range_hours: u32,

    /// Enable real-time updates
    pub real_time_updates: bool,

    /// Maximum number of data points per chart
    pub max_chart_points: usize,

    /// Enable alerts and notifications
    pub alerts_enabled: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            refresh_interval_seconds: 30,
            default_time_range_hours: 24,
            real_time_updates: true,
            max_chart_points: 100,
            alerts_enabled: true,
        }
    }
}

/// Dashboard widget types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetType {
    /// Line chart for time series data
    LineChart,
    /// Bar chart for categorical data
    BarChart,
    /// Pie chart for distribution data
    PieChart,
    /// Single metric display
    MetricCard,
    /// Data table
    Table,
    /// Heat map
    HeatMap,
    /// Gauge/progress indicator
    Gauge,
}

/// Dashboard widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    /// Widget identifier
    pub id: String,

    /// Widget title
    pub title: String,

    /// Widget type
    pub widget_type: WidgetType,

    /// Data source query
    pub data_source: DataSource,

    /// Time range for data
    pub time_range: TimeRange,

    /// Widget position and size
    pub layout: WidgetLayout,

    /// Refresh interval override
    pub refresh_interval: Option<u32>,

    /// Alert thresholds
    pub alert_thresholds: Option<AlertThresholds>,
}

/// Widget layout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetLayout {
    /// X position (grid units)
    pub x: u32,

    /// Y position (grid units)
    pub y: u32,

    /// Width (grid units)
    pub width: u32,

    /// Height (grid units)
    pub height: u32,
}

/// Data source configuration for widgets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataSource {
    /// Role usage statistics
    RoleUsage {
        role_id: Option<String>,
        group_by: Option<String>,
    },
    /// Permission usage statistics
    PermissionUsage {
        permission_id: Option<String>,
        group_by: Option<String>,
    },
    /// Compliance metrics
    Compliance { metric_type: String },
    /// Performance metrics
    Performance { metric_type: String },
    /// Event count with filters
    EventCount {
        event_type: Option<String>,
        filters: HashMap<String, String>,
    },
    /// Custom query
    Custom {
        query: String,
        parameters: HashMap<String, String>,
    },
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Warning threshold
    pub warning: f64,

    /// Critical threshold
    pub critical: f64,

    /// Threshold comparison type
    pub comparison: ThresholdComparison,
}

/// Threshold comparison types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdComparison {
    GreaterThan,
    LessThan,
    Equals,
    NotEquals,
}

/// Dashboard data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    /// Timestamp (for time series)
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,

    /// Category label (for categorical data)
    pub label: Option<String>,

    /// Numeric value
    pub value: f64,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Chart data series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartSeries {
    /// Series name
    pub name: String,

    /// Data points
    pub data: Vec<DataPoint>,

    /// Series color
    pub color: Option<String>,

    /// Series type (for mixed charts)
    pub series_type: Option<String>,
}

/// Widget data response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetData {
    /// Widget ID
    pub widget_id: String,

    /// Last updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Chart series data
    pub series: Vec<ChartSeries>,

    /// Summary statistics
    pub summary: Option<WidgetSummary>,

    /// Alert status
    pub alert_status: AlertStatus,
}

/// Widget summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetSummary {
    /// Total count
    pub total: f64,

    /// Average value
    pub average: f64,

    /// Minimum value
    pub minimum: f64,

    /// Maximum value
    pub maximum: f64,

    /// Change from previous period
    pub change_percent: Option<f64>,
}

/// Alert status for widgets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    Normal,
    Warning,
    Critical,
    Unknown,
}

/// Complete dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    /// Dashboard identifier
    pub id: String,

    /// Dashboard title
    pub title: String,

    /// Dashboard description
    pub description: Option<String>,

    /// Dashboard configuration
    pub config: DashboardConfig,

    /// Widgets in this dashboard
    pub widgets: Vec<DashboardWidget>,

    /// Dashboard tags for organization
    pub tags: Vec<String>,

    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last modified timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Dashboard manager
pub struct DashboardManager {
    config: DashboardConfig,
    dashboards: HashMap<String, Dashboard>,
}

impl DashboardManager {
    /// Create new dashboard manager
    pub fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            dashboards: HashMap::new(),
        }
    }

    /// Create a new dashboard
    pub async fn create_dashboard(&mut self, dashboard: Dashboard) -> Result<(), AnalyticsError> {
        self.dashboards.insert(dashboard.id.clone(), dashboard);
        Ok(())
    }

    /// Get dashboard by ID
    pub async fn get_dashboard(
        &self,
        dashboard_id: &str,
    ) -> Result<Option<Dashboard>, AnalyticsError> {
        Ok(self.dashboards.get(dashboard_id).cloned())
    }

    /// List all dashboards
    pub async fn list_dashboards(&self) -> Result<Vec<Dashboard>, AnalyticsError> {
        Ok(self.dashboards.values().cloned().collect())
    }

    /// Update dashboard
    pub async fn update_dashboard(&mut self, dashboard: Dashboard) -> Result<(), AnalyticsError> {
        let mut updated_dashboard = dashboard;
        updated_dashboard.updated_at = chrono::Utc::now();
        self.dashboards
            .insert(updated_dashboard.id.clone(), updated_dashboard);
        Ok(())
    }

    /// Delete dashboard
    pub async fn delete_dashboard(&mut self, dashboard_id: &str) -> Result<bool, AnalyticsError> {
        Ok(self.dashboards.remove(dashboard_id).is_some())
    }

    /// Get widget data
    pub async fn get_widget_data(
        &self,
        widget: &DashboardWidget,
    ) -> Result<WidgetData, AnalyticsError> {
        let series = match &widget.data_source {
            DataSource::RoleUsage { role_id, group_by } => {
                self.get_role_usage_series(
                    role_id.as_deref(),
                    group_by.as_deref(),
                    &widget.time_range,
                )
                .await?
            }
            DataSource::PermissionUsage {
                permission_id,
                group_by,
            } => {
                self.get_permission_usage_series(
                    permission_id.as_deref(),
                    group_by.as_deref(),
                    &widget.time_range,
                )
                .await?
            }
            DataSource::Compliance { metric_type } => {
                self.get_compliance_series(metric_type, &widget.time_range)
                    .await?
            }
            DataSource::Performance { metric_type } => {
                self.get_performance_series(metric_type, &widget.time_range)
                    .await?
            }
            DataSource::EventCount {
                event_type,
                filters,
            } => {
                self.get_event_count_series(event_type.as_deref(), filters, &widget.time_range)
                    .await?
            }
            DataSource::Custom { query, parameters } => {
                self.get_custom_series(query, parameters, &widget.time_range)
                    .await?
            }
        };

        let summary = self.calculate_widget_summary(&series);
        let alert_status = self.check_alert_status(&summary, &widget.alert_thresholds);

        Ok(WidgetData {
            widget_id: widget.id.clone(),
            updated_at: chrono::Utc::now(),
            series,
            summary: Some(summary),
            alert_status,
        })
    }

    /// Create predefined RBAC overview dashboard
    pub async fn create_rbac_overview_dashboard(&mut self) -> Result<String, AnalyticsError> {
        let dashboard_id = uuid::Uuid::new_v4().to_string();

        let dashboard = Dashboard {
            id: dashboard_id.clone(),
            title: "RBAC Overview".to_string(),
            description: Some("Comprehensive RBAC system overview".to_string()),
            config: self.config.clone(),
            widgets: vec![
                // Permission checks over time
                DashboardWidget {
                    id: "permission_checks_timeline".to_string(),
                    title: "Permission Checks Over Time".to_string(),
                    widget_type: WidgetType::LineChart,
                    data_source: DataSource::EventCount {
                        event_type: Some("PermissionCheck".to_string()),
                        filters: HashMap::new(),
                    },
                    time_range: TimeRange::last_hours(24),
                    layout: WidgetLayout {
                        x: 0,
                        y: 0,
                        width: 6,
                        height: 3,
                    },
                    refresh_interval: None,
                    alert_thresholds: None,
                },
                // Role usage distribution
                DashboardWidget {
                    id: "role_usage_distribution".to_string(),
                    title: "Role Usage Distribution".to_string(),
                    widget_type: WidgetType::PieChart,
                    data_source: DataSource::RoleUsage {
                        role_id: None,
                        group_by: Some("role_name".to_string()),
                    },
                    time_range: TimeRange::last_hours(24),
                    layout: WidgetLayout {
                        x: 6,
                        y: 0,
                        width: 6,
                        height: 3,
                    },
                    refresh_interval: None,
                    alert_thresholds: None,
                },
                // Compliance score
                DashboardWidget {
                    id: "compliance_score".to_string(),
                    title: "Compliance Score".to_string(),
                    widget_type: WidgetType::Gauge,
                    data_source: DataSource::Compliance {
                        metric_type: "overall_compliance".to_string(),
                    },
                    time_range: TimeRange::last_hours(24),
                    layout: WidgetLayout {
                        x: 0,
                        y: 3,
                        width: 3,
                        height: 3,
                    },
                    refresh_interval: None,
                    alert_thresholds: Some(AlertThresholds {
                        warning: 85.0,
                        critical: 70.0,
                        comparison: ThresholdComparison::LessThan,
                    }),
                },
                // Average response time
                DashboardWidget {
                    id: "avg_response_time".to_string(),
                    title: "Average Response Time".to_string(),
                    widget_type: WidgetType::MetricCard,
                    data_source: DataSource::Performance {
                        metric_type: "avg_permission_check_latency".to_string(),
                    },
                    time_range: TimeRange::last_hours(24),
                    layout: WidgetLayout {
                        x: 3,
                        y: 3,
                        width: 3,
                        height: 3,
                    },
                    refresh_interval: None,
                    alert_thresholds: Some(AlertThresholds {
                        warning: 100.0,
                        critical: 200.0,
                        comparison: ThresholdComparison::GreaterThan,
                    }),
                },
                // Top accessed resources
                DashboardWidget {
                    id: "top_resources".to_string(),
                    title: "Top Accessed Resources".to_string(),
                    widget_type: WidgetType::BarChart,
                    data_source: DataSource::EventCount {
                        event_type: Some("PermissionCheck".to_string()),
                        filters: HashMap::from([("result".to_string(), "Success".to_string())]),
                    },
                    time_range: TimeRange::last_hours(24),
                    layout: WidgetLayout {
                        x: 6,
                        y: 3,
                        width: 6,
                        height: 3,
                    },
                    refresh_interval: None,
                    alert_thresholds: None,
                },
            ],
            tags: vec!["rbac".to_string(), "overview".to_string()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        self.create_dashboard(dashboard).await?;
        Ok(dashboard_id)
    }

    // Private helper methods for data series generation
    async fn get_role_usage_series(
        &self,
        _role_id: Option<&str>,
        _group_by: Option<&str>,
        _time_range: &TimeRange,
    ) -> Result<Vec<ChartSeries>, AnalyticsError> {
        // Implementation would query actual data
        Ok(vec![
            ChartSeries {
                name: "Admin".to_string(),
                data: vec![DataPoint {
                    timestamp: None,
                    label: Some("Admin".to_string()),
                    value: 45.0,
                    metadata: HashMap::new(),
                }],
                color: Some("#ff6b6b".to_string()),
                series_type: None,
            },
            ChartSeries {
                name: "User".to_string(),
                data: vec![DataPoint {
                    timestamp: None,
                    label: Some("User".to_string()),
                    value: 120.0,
                    metadata: HashMap::new(),
                }],
                color: Some("#4ecdc4".to_string()),
                series_type: None,
            },
        ])
    }

    async fn get_permission_usage_series(
        &self,
        _permission_id: Option<&str>,
        _group_by: Option<&str>,
        _time_range: &TimeRange,
    ) -> Result<Vec<ChartSeries>, AnalyticsError> {
        // Implementation would query actual data
        Ok(vec![])
    }

    async fn get_compliance_series(
        &self,
        _metric_type: &str,
        _time_range: &TimeRange,
    ) -> Result<Vec<ChartSeries>, AnalyticsError> {
        // Implementation would query actual data
        Ok(vec![ChartSeries {
            name: "Compliance Score".to_string(),
            data: vec![DataPoint {
                timestamp: None,
                label: None,
                value: 92.5,
                metadata: HashMap::new(),
            }],
            color: Some("#45b7d1".to_string()),
            series_type: None,
        }])
    }

    async fn get_performance_series(
        &self,
        _metric_type: &str,
        _time_range: &TimeRange,
    ) -> Result<Vec<ChartSeries>, AnalyticsError> {
        // Implementation would query actual data
        Ok(vec![ChartSeries {
            name: "Response Time".to_string(),
            data: vec![DataPoint {
                timestamp: None,
                label: None,
                value: 15.5,
                metadata: HashMap::new(),
            }],
            color: Some("#96ceb4".to_string()),
            series_type: None,
        }])
    }

    async fn get_event_count_series(
        &self,
        _event_type: Option<&str>,
        _filters: &HashMap<String, String>,
        _time_range: &TimeRange,
    ) -> Result<Vec<ChartSeries>, AnalyticsError> {
        // Implementation would query actual data
        Ok(vec![])
    }

    async fn get_custom_series(
        &self,
        _query: &str,
        _parameters: &HashMap<String, String>,
        _time_range: &TimeRange,
    ) -> Result<Vec<ChartSeries>, AnalyticsError> {
        // Implementation would execute custom query
        Ok(vec![])
    }

    fn calculate_widget_summary(&self, series: &[ChartSeries]) -> WidgetSummary {
        let all_values: Vec<f64> = series
            .iter()
            .flat_map(|s| s.data.iter().map(|d| d.value))
            .collect();

        let total = all_values.iter().sum();
        let count = all_values.len() as f64;
        let average = if count > 0.0 { total / count } else { 0.0 };
        let minimum = all_values.iter().copied().fold(f64::INFINITY, f64::min);
        let maximum = all_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        WidgetSummary {
            total,
            average,
            minimum: if minimum.is_infinite() { 0.0 } else { minimum },
            maximum: if maximum.is_infinite() { 0.0 } else { maximum },
            change_percent: None, // Would calculate from historical data
        }
    }

    fn check_alert_status(
        &self,
        summary: &WidgetSummary,
        thresholds: &Option<AlertThresholds>,
    ) -> AlertStatus {
        let Some(thresholds) = thresholds else {
            return AlertStatus::Normal;
        };

        let value = summary.average; // Use average for threshold comparison

        let exceeds_critical = match thresholds.comparison {
            ThresholdComparison::GreaterThan => value > thresholds.critical,
            ThresholdComparison::LessThan => value < thresholds.critical,
            ThresholdComparison::Equals => (value - thresholds.critical).abs() < f64::EPSILON,
            ThresholdComparison::NotEquals => (value - thresholds.critical).abs() > f64::EPSILON,
        };

        let exceeds_warning = match thresholds.comparison {
            ThresholdComparison::GreaterThan => value > thresholds.warning,
            ThresholdComparison::LessThan => value < thresholds.warning,
            ThresholdComparison::Equals => (value - thresholds.warning).abs() < f64::EPSILON,
            ThresholdComparison::NotEquals => (value - thresholds.warning).abs() > f64::EPSILON,
        };

        if exceeds_critical {
            AlertStatus::Critical
        } else if exceeds_warning {
            AlertStatus::Warning
        } else {
            AlertStatus::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_config_default() {
        let config = DashboardConfig::default();
        assert_eq!(config.refresh_interval_seconds, 30);
        assert!(config.real_time_updates);
        assert!(config.alerts_enabled);
    }

    #[tokio::test]
    async fn test_dashboard_manager_creation() {
        let config = DashboardConfig::default();
        let manager = DashboardManager::new(config);
        assert_eq!(manager.dashboards.len(), 0);
    }

    #[tokio::test]
    async fn test_create_rbac_overview_dashboard() {
        let config = DashboardConfig::default();
        let mut manager = DashboardManager::new(config);

        let dashboard_id = manager.create_rbac_overview_dashboard().await.unwrap();
        assert!(!dashboard_id.is_empty());

        let dashboard = manager.get_dashboard(&dashboard_id).await.unwrap().unwrap();
        assert_eq!(dashboard.title, "RBAC Overview");
        assert_eq!(dashboard.widgets.len(), 5);
    }

    #[test]
    fn test_alert_status_checking() {
        let config = DashboardConfig::default();
        let manager = DashboardManager::new(config);

        let summary = WidgetSummary {
            total: 100.0,
            average: 150.0,
            minimum: 100.0,
            maximum: 200.0,
            change_percent: None,
        };

        let thresholds = AlertThresholds {
            warning: 100.0,
            critical: 200.0,
            comparison: ThresholdComparison::GreaterThan,
        };

        let status = manager.check_alert_status(&summary, &Some(thresholds));
        assert_eq!(status, AlertStatus::Warning);
    }
}
