// Comprehensive tests for ABAC and delegation
#[cfg(test)]
mod tests {
    
    use crate::permissions::{AbacPolicy, AbacRule, Delegation, Permission, PermissionChecker};
    use chrono::Utc;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_abac_grant() {
        let checker = PermissionChecker::default();
        let write_permission = Permission::new("write", "documents");
        let abac_policy = AbacPolicy {
            attributes: HashMap::new(),
            rules: vec![AbacRule {
                attribute: "department".to_string(),
                expected_value: json!("engineering"),
                permission: write_permission.clone(),
            }],
        };
        let mut attrs = HashMap::new();
        attrs.insert("department".to_string(), json!("engineering"));
        assert!(checker.check_abac(&attrs, &write_permission, &abac_policy));
    }

    #[test]
    fn test_abac_deny() {
        let checker = PermissionChecker::default();
        let write_permission = Permission::new("write", "documents");
        let abac_policy = AbacPolicy {
            attributes: HashMap::new(),
            rules: vec![AbacRule {
                attribute: "department".to_string(),
                expected_value: json!("engineering"),
                permission: write_permission.clone(),
            }],
        };
        let mut attrs = HashMap::new();
        attrs.insert("department".to_string(), json!("sales"));
        assert!(!checker.check_abac(&attrs, &write_permission, &abac_policy));
    }

    #[test]
    fn test_delegation_grant() {
        let checker = PermissionChecker::default();
        let read_permission = Permission::new("read", "documents");
        let delegations = vec![Delegation {
            delegator: "admin".to_string(),
            delegatee: "user1".to_string(),
            permissions: HashSet::from([read_permission.clone()]),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        }];
        assert!(checker.check_delegation("user1", &read_permission, &delegations));
    }

    #[test]
    fn test_delegation_expired() {
        let checker = PermissionChecker::default();
        let read_permission = Permission::new("read", "documents");
        let delegations = vec![Delegation {
            delegator: "admin".to_string(),
            delegatee: "user1".to_string(),
            permissions: HashSet::from([read_permission.clone()]),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        }];
        assert!(!checker.check_delegation("user1", &read_permission, &delegations));
    }
}
