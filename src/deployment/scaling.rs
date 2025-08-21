// Auto-scaling system for production deployment
// Dynamic resource scaling based on metrics and load

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScalingError {
    #[error("Scaling policy error: {0}")]
    Policy(String),
    #[error("Resource error: {0}")]
    Resource(String),
    #[error("Metric collection error: {0}")]
    Metrics(String),
    #[error("Scaling operation error: {0}")]
    Operation(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Scaling policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingPolicy {
    pub name: String,
    pub enabled: bool,
    pub min_instances: u32,
    pub max_instances: u32,
    pub target_cpu_utilization: f64,
    pub target_memory_utilization: f64,
    pub scale_up_cooldown: Duration,
    pub scale_down_cooldown: Duration,
    pub metrics_window: Duration,
}

/// Scaling metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingMetrics {
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
    pub request_count: u64,
    pub response_time: Duration,
    pub error_rate: f64,
    pub timestamp: u64,
}

/// Scaling action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScalingAction {
    ScaleUp(u32),   // Scale up by N instances
    ScaleDown(u32), // Scale down by N instances
    NoAction,
}

/// Scaling decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingDecision {
    pub action: ScalingAction,
    pub reason: String,
    pub current_instances: u32,
    pub target_instances: u32,
    pub timestamp: u64,
    pub metrics: ScalingMetrics,
}

/// Auto-scaling manager
pub struct AutoScaler {
    policy: ScalingPolicy,
    current_instances: u32,
    last_scale_up: Option<SystemTime>,
    last_scale_down: Option<SystemTime>,
    metrics_history: Vec<ScalingMetrics>,
}

impl AutoScaler {
    /// Create new auto-scaler
    pub fn new(policy: ScalingPolicy) -> Self {
        Self {
            current_instances: policy.min_instances,
            policy,
            last_scale_up: None,
            last_scale_down: None,
            metrics_history: Vec::new(),
        }
    }

    /// Add metrics sample
    pub fn add_metrics(&mut self, metrics: ScalingMetrics) {
        self.metrics_history.push(metrics);

        // Keep only recent metrics within the window
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - self.policy.metrics_window.as_secs();

        self.metrics_history.retain(|m| m.timestamp > cutoff);
    }

    /// Make scaling decision based on current metrics
    pub fn make_scaling_decision(&self) -> Result<ScalingDecision, ScalingError> {
        if !self.policy.enabled {
            return Ok(ScalingDecision {
                action: ScalingAction::NoAction,
                reason: "Auto-scaling is disabled".to_string(),
                current_instances: self.current_instances,
                target_instances: self.current_instances,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                metrics: self.get_average_metrics()?,
            });
        }

        let avg_metrics = self.get_average_metrics()?;
        let now = SystemTime::now();

        // Check if we should scale up
        if avg_metrics.cpu_utilization > self.policy.target_cpu_utilization
            || avg_metrics.memory_utilization > self.policy.target_memory_utilization
        {
            // Check cooldown period
            if let Some(last_scale_up) = self.last_scale_up
                && now.duration_since(last_scale_up).unwrap() < self.policy.scale_up_cooldown
            {
                return Ok(ScalingDecision {
                    action: ScalingAction::NoAction,
                    reason: "Scale up cooldown period not yet elapsed".to_string(),
                    current_instances: self.current_instances,
                    target_instances: self.current_instances,
                    timestamp: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    metrics: avg_metrics,
                });
            }

            // Scale up if not at max capacity
            if self.current_instances < self.policy.max_instances {
                let scale_amount = self.calculate_scale_up_amount(&avg_metrics);
                let target_instances =
                    (self.current_instances + scale_amount).min(self.policy.max_instances);

                return Ok(ScalingDecision {
                    action: ScalingAction::ScaleUp(target_instances - self.current_instances),
                    reason: format!(
                        "High resource utilization: CPU: {:.1}%, Memory: {:.1}%",
                        avg_metrics.cpu_utilization * 100.0,
                        avg_metrics.memory_utilization * 100.0
                    ),
                    current_instances: self.current_instances,
                    target_instances,
                    timestamp: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    metrics: avg_metrics,
                });
            }
        }

        // Check if we should scale down
        if avg_metrics.cpu_utilization < self.policy.target_cpu_utilization * 0.5
            && avg_metrics.memory_utilization < self.policy.target_memory_utilization * 0.5
        {
            // Check cooldown period
            if let Some(last_scale_down) = self.last_scale_down
                && now.duration_since(last_scale_down).unwrap() < self.policy.scale_down_cooldown
            {
                return Ok(ScalingDecision {
                    action: ScalingAction::NoAction,
                    reason: "Scale down cooldown period not yet elapsed".to_string(),
                    current_instances: self.current_instances,
                    target_instances: self.current_instances,
                    timestamp: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    metrics: avg_metrics,
                });
            }

            // Scale down if not at min capacity
            if self.current_instances > self.policy.min_instances {
                let scale_amount = self.calculate_scale_down_amount(&avg_metrics);
                let target_instances =
                    (self.current_instances - scale_amount).max(self.policy.min_instances);

                return Ok(ScalingDecision {
                    action: ScalingAction::ScaleDown(self.current_instances - target_instances),
                    reason: format!(
                        "Low resource utilization: CPU: {:.1}%, Memory: {:.1}%",
                        avg_metrics.cpu_utilization * 100.0,
                        avg_metrics.memory_utilization * 100.0
                    ),
                    current_instances: self.current_instances,
                    target_instances,
                    timestamp: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    metrics: avg_metrics,
                });
            }
        }

        // No action needed
        Ok(ScalingDecision {
            action: ScalingAction::NoAction,
            reason: "Resource utilization within target range".to_string(),
            current_instances: self.current_instances,
            target_instances: self.current_instances,
            timestamp: now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            metrics: avg_metrics,
        })
    }

    /// Apply scaling decision
    pub async fn apply_scaling_decision(
        &mut self,
        decision: &ScalingDecision,
    ) -> Result<(), ScalingError> {
        match &decision.action {
            ScalingAction::ScaleUp(amount) => {
                self.scale_up(*amount).await?;
                self.last_scale_up = Some(SystemTime::now());
            }
            ScalingAction::ScaleDown(amount) => {
                self.scale_down(*amount).await?;
                self.last_scale_down = Some(SystemTime::now());
            }
            ScalingAction::NoAction => {
                // No action needed
            }
        }

        self.current_instances = decision.target_instances;
        Ok(())
    }

    /// Scale up by specified amount
    async fn scale_up(&self, _amount: u32) -> Result<(), ScalingError> {
        // Implement actual scaling logic
        Ok(())
    }

    /// Scale down by specified amount
    async fn scale_down(&self, _amount: u32) -> Result<(), ScalingError> {
        // Implement actual scaling logic
        Ok(())
    }

    /// Calculate how much to scale up
    fn calculate_scale_up_amount(&self, metrics: &ScalingMetrics) -> u32 {
        // Simple algorithm: scale up by 1 instance at a time
        // More sophisticated algorithms could consider utilization levels
        if metrics.cpu_utilization > 0.9 || metrics.memory_utilization > 0.9 {
            2 // Scale more aggressively under high load
        } else {
            1
        }
    }

    /// Calculate how much to scale down
    fn calculate_scale_down_amount(&self, _metrics: &ScalingMetrics) -> u32 {
        // Conservative scale down: 1 instance at a time
        1
    }

    /// Get average metrics over the window
    fn get_average_metrics(&self) -> Result<ScalingMetrics, ScalingError> {
        if self.metrics_history.is_empty() {
            return Err(ScalingError::Metrics("No metrics available".to_string()));
        }

        let count = self.metrics_history.len() as f64;
        let sum_cpu = self
            .metrics_history
            .iter()
            .map(|m| m.cpu_utilization)
            .sum::<f64>();
        let sum_memory = self
            .metrics_history
            .iter()
            .map(|m| m.memory_utilization)
            .sum::<f64>();
        let sum_requests = self
            .metrics_history
            .iter()
            .map(|m| m.request_count)
            .sum::<u64>();
        let sum_response_time = self
            .metrics_history
            .iter()
            .map(|m| m.response_time.as_millis() as u64)
            .sum::<u64>();
        let sum_error_rate = self
            .metrics_history
            .iter()
            .map(|m| m.error_rate)
            .sum::<f64>();

        Ok(ScalingMetrics {
            cpu_utilization: sum_cpu / count,
            memory_utilization: sum_memory / count,
            request_count: sum_requests / count as u64,
            response_time: Duration::from_millis(sum_response_time / count as u64),
            error_rate: sum_error_rate / count,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Get current instance count
    pub fn get_current_instances(&self) -> u32 {
        self.current_instances
    }

    /// Get scaling policy
    pub fn get_policy(&self) -> &ScalingPolicy {
        &self.policy
    }
}

impl Default for ScalingPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            enabled: true,
            min_instances: 1,
            max_instances: 10,
            target_cpu_utilization: 0.7,
            target_memory_utilization: 0.7,
            scale_up_cooldown: Duration::from_secs(300), // 5 minutes
            scale_down_cooldown: Duration::from_secs(600), // 10 minutes
            metrics_window: Duration::from_secs(300),    // 5 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_scaler_creation() {
        let policy = ScalingPolicy::default();
        let scaler = AutoScaler::new(policy.clone());

        assert_eq!(scaler.current_instances, policy.min_instances);
        assert_eq!(scaler.policy.name, "default");
    }

    #[test]
    fn test_metrics_addition() {
        let policy = ScalingPolicy::default();
        let mut scaler = AutoScaler::new(policy);

        let metrics = ScalingMetrics {
            cpu_utilization: 0.5,
            memory_utilization: 0.6,
            request_count: 100,
            response_time: Duration::from_millis(50),
            error_rate: 0.01,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        scaler.add_metrics(metrics);
        assert_eq!(scaler.metrics_history.len(), 1);
    }

    #[test]
    fn test_scaling_decision_no_action() {
        let policy = ScalingPolicy::default();
        let mut scaler = AutoScaler::new(policy);

        // Add normal metrics
        let metrics = ScalingMetrics {
            cpu_utilization: 0.5,    // Below target
            memory_utilization: 0.5, // Below target
            request_count: 100,
            response_time: Duration::from_millis(50),
            error_rate: 0.01,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        scaler.add_metrics(metrics);

        let decision = scaler.make_scaling_decision().unwrap();
        assert!(matches!(decision.action, ScalingAction::NoAction));
    }

    #[test]
    fn test_scaling_decision_scale_up() {
        let policy = ScalingPolicy::default();
        let mut scaler = AutoScaler::new(policy);

        // Add high utilization metrics
        let metrics = ScalingMetrics {
            cpu_utilization: 0.9,    // Above target
            memory_utilization: 0.8, // Above target
            request_count: 1000,
            response_time: Duration::from_millis(200),
            error_rate: 0.05,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        scaler.add_metrics(metrics);

        let decision = scaler.make_scaling_decision().unwrap();
        assert!(matches!(decision.action, ScalingAction::ScaleUp(_)));
    }

    #[tokio::test]
    async fn test_apply_scaling_decision() {
        let policy = ScalingPolicy::default();
        let mut scaler = AutoScaler::new(policy);

        let decision = ScalingDecision {
            action: ScalingAction::ScaleUp(2),
            reason: "Test scale up".to_string(),
            current_instances: 1,
            target_instances: 3,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metrics: ScalingMetrics {
                cpu_utilization: 0.9,
                memory_utilization: 0.8,
                request_count: 1000,
                response_time: Duration::from_millis(200),
                error_rate: 0.05,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        };

        let result = scaler.apply_scaling_decision(&decision).await;
        assert!(result.is_ok());
        assert_eq!(scaler.current_instances, 3);
    }
}


