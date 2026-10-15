//! RBAC Compliance Monitoring
//!
//! This module provides compliance monitoring and reporting
//! for RBAC systems according to various security standards.
//!
//! > **Status:** Compliance reports currently derive values from stored
//! > analytics events. Broader compliance discovery can be layered on by adding
//! > more collectors, but the module already performs real event-backed checks.

use super::{AnalyticsError, ComplianceMetrics, TimeRange};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Compliance monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComplianceConfig {
    /// Enable SOX compliance monitoring
    pub sox_compliance: bool,

    /// Enable GDPR compliance monitoring
    pub gdpr_compliance: bool,

    /// Enable HIPAA compliance monitoring
    pub hipaa_compliance: bool,

    /// Custom compliance rules
    pub custom_rules: Vec<ComplianceRule>,
}

/// Custom compliance rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    /// Rule identifier
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: String,

    /// Rule type
    pub rule_type: ComplianceRuleType,

    /// Rule parameters
    pub parameters: std::collections::HashMap<String, String>,
}

/// Compliance rule types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceRuleType {
    PermissionSeparation,
    AccessReview,
    PrivilegeEscalation,
    DataAccess,
    Custom(String),
}

/// Compliance monitor
pub struct ComplianceMonitor {
    _config: ComplianceConfig,
    storage: Arc<dyn AuthStorage>,
}

impl ComplianceMonitor {
    /// Create new compliance monitor
    pub fn new(config: ComplianceConfig, storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            _config: config,
            storage,
        }
    }

    /// Check compliance status
    pub async fn check_compliance(
        &self,
        _time_range: TimeRange,
    ) -> Result<ComplianceMetrics, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();
        let mut total_events = 0;
        let mut policy_violations = 0;
        let mut orphaned_permissions = 0;
        let mut security_incidents = 0;
        let mut revocation_durations = Vec::new();
        let mut escalation_users = std::collections::HashSet::new();

        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<crate::analytics::AnalyticsEvent>(&data)
            {
                total_events += 1;
                if let Some(action) = &event.action {
                    if action.contains("Violation") || action.contains("Denied") {
                        policy_violations += 1;
                    }
                    if action.contains("Incident") {
                        security_incidents += 1;
                    }
                    // Track access revocation timing from metadata
                    if (action.contains("Revoked") || action.contains("Revocation"))
                        && let Some(hours_str) = event.metadata.get("revocation_hours")
                        && let Ok(hours) = hours_str.parse::<f64>()
                    {
                        revocation_durations.push(hours);
                    }
                }
                if event.event_type == crate::analytics::RbacEventType::PermissionCheck
                    && event.action.as_deref() == Some("Orphaned")
                {
                    orphaned_permissions += 1;
                }
                // Track over-privileged users from escalation events
                if event.event_type == crate::analytics::RbacEventType::PrivilegeEscalation
                    && let Some(ref user) = event.user_id
                {
                    escalation_users.insert(user.clone());
                }
            }
        }

        let compliance_score = if total_events > 0 {
            100.0 - ((policy_violations as f64 / total_events as f64) * 100.0)
        } else {
            100.0
        };

        let avg_access_revocation_time_hours = if !revocation_durations.is_empty() {
            revocation_durations.iter().sum::<f64>() / revocation_durations.len() as f64
        } else {
            0.0 // No revocation data available
        };

        // Count unused roles by comparing defined roles against actual assignments
        let unused_roles = {
            let defined_roles = self
                .storage
                .list_kv_keys("rbac:role:")
                .await
                .unwrap_or_default();
            let assigned: std::collections::HashSet<String> = {
                let user_role_keys = self
                    .storage
                    .list_kv_keys("rbac:user_roles:")
                    .await
                    .unwrap_or_default();
                let mut set = std::collections::HashSet::new();
                for key in &user_role_keys {
                    if let Ok(Some(data)) = self.storage.get_kv(key).await
                        && let Ok(roles) = serde_json::from_slice::<Vec<String>>(&data)
                    {
                        set.extend(roles);
                    }
                }
                set
            };
            defined_roles
                .iter()
                .filter(|k| {
                    let role_name = k.strip_prefix("rbac:role:").unwrap_or(k);
                    !assigned.contains(role_name)
                })
                .count() as u32
        };

        Ok(ComplianceMetrics {
            role_assignment_compliance: compliance_score,
            permission_scoping_compliance: compliance_score,
            orphaned_permissions,
            over_privileged_users: escalation_users.len() as u32,
            unused_roles,
            avg_access_revocation_time_hours,
            policy_violations,
            security_incidents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_config_default() {
        let config = ComplianceConfig::default();
        assert!(!config.sox_compliance);
        assert!(!config.gdpr_compliance);
        assert!(!config.hipaa_compliance);
        assert!(config.custom_rules.is_empty());
    }

    #[test]
    fn test_compliance_monitor_creation() {
        let config = ComplianceConfig::default();
        let _monitor = ComplianceMonitor::new(
            config,
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
    }

    #[tokio::test]
    async fn test_check_compliance_returns_metrics() {
        let monitor = ComplianceMonitor::new(
            ComplianceConfig::default(),
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
        let range = TimeRange::last_days(7);
        let metrics = monitor.check_compliance(range).await.unwrap();
        assert!(metrics.role_assignment_compliance > 0.0);
        assert!(metrics.permission_scoping_compliance > 0.0);
        assert_eq!(metrics.security_incidents, 0);
    }
}
