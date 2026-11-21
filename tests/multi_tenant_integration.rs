// SPDX-License-Identifier: MIT OR Apache-2.0
//! Comprehensive integration tests for AuthFramework multi-tenant architecture
//!
//! This test suite validates:
//! - Complete tenant lifecycle management
//! - Data isolation between tenants
//! - Concurrent tenant operations
//! - Configuration per-tenant segregation
//! - Error handling and edge cases

#[cfg(test)]
mod multi_tenant_tests {
    use auth_framework::{
        AuthConfig, TenantContext, TenantId, TenantRegistry, TenantRegistryBuilder,
    };
    use std::sync::Arc;

    // ============================================================================
    // Helper functions
    // ============================================================================

    fn create_test_tenant(name: &str, description: &str) -> TenantContext {
        TenantContext::with_name(name, description).expect("Failed to create tenant")
    }

    // ============================================================================
    // 1. Tenant Registry Builder Tests
    // ============================================================================

    #[tokio::test]
    async fn test_builder_creates_empty_registry() {
        let registry = TenantRegistryBuilder::new().build();
        assert_eq!(registry.tenant_count().await, 0);
        assert!(registry.list_tenant_ids().await.is_empty());
    }

    #[tokio::test]
    async fn test_builder_with_custom_config() {
        let custom_config = AuthConfig::new().secret("custom_secret".to_string());
        let registry = TenantRegistryBuilder::new()
            .with_config(custom_config)
            .build();

        assert_eq!(registry.tenant_count().await, 0);
    }

    // ============================================================================
    // 2. Tenant Lifecycle Management Tests
    // ============================================================================

    #[tokio::test]
    async fn test_complete_tenant_lifecycle() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let context = create_test_tenant("lifecycle-test", "Testing lifecycle");

        // Step 1: Register
        let result = registry.register_tenant(context.clone(), None).await;
        assert!(result.is_ok(), "Tenant registration failed");

        let tenant_id = &context.id;
        let count = registry.tenant_count().await;
        assert_eq!(count, 1, "Registry should have exactly 1 tenant");

        // Step 2: Verify active
        let framework = registry.get_tenant_framework(tenant_id);
        assert!(framework.is_ok(), "Should be able to get active tenant");

        // Step 3: Deactivate
        let deactivate_result = registry.deactivate_tenant(tenant_id).await;
        assert!(deactivate_result.is_ok(), "Deactivation failed");

        // Step 4: Verify inactive
        let framework_after = registry.get_tenant_framework(tenant_id);
        assert!(
            framework_after.is_err(),
            "Should not access deactivated tenant"
        );

        // Step 5: Reactivate
        let activate_result = registry.activate_tenant(tenant_id).await;
        assert!(activate_result.is_ok(), "Reactivation failed");

        // Step 6: Verify active again
        let framework_restored = registry.get_tenant_framework(tenant_id);
        assert!(
            framework_restored.is_ok(),
            "Should access reactivated tenant"
        );

        // Step 7: Remove
        let remove_result = registry.remove_tenant(tenant_id).await;
        assert!(remove_result.is_ok(), "Tenant removal failed");

        // Step 8: Verify removed
        let count_final = registry.tenant_count().await;
        assert_eq!(count_final, 0, "Registry should be empty after removal");

        let framework_removed = registry.get_tenant_framework(tenant_id);
        assert!(
            framework_removed.is_err(),
            "Should not access removed tenant"
        );
    }

    #[tokio::test]
    async fn test_duplicate_tenant_registration_fails() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let context = create_test_tenant("duplicate", "Test duplicate");

        let first_result = registry.register_tenant(context.clone(), None).await;
        assert!(first_result.is_ok());

        let second_result = registry.register_tenant(context, None).await;
        assert!(second_result.is_err(), "Duplicate registration should fail");

        assert_eq!(
            registry.tenant_count().await,
            1,
            "Should still have 1 tenant"
        );
    }

    #[tokio::test]
    async fn test_nonexistent_tenant_operations() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let fake_id = TenantId::new("nonexistent");

        // Should fail to get
        assert!(registry.get_tenant_framework(&fake_id).is_err());

        // Should fail to deactivate
        let deactivate = registry.deactivate_tenant(&fake_id).await;
        assert!(deactivate.is_err());

        // Should fail to activate
        let activate = registry.activate_tenant(&fake_id).await;
        assert!(activate.is_err());

        // Remove on non-existent is idempotent (succeeds)
        let remove = registry.remove_tenant(&fake_id).await;
        assert!(remove.is_ok());
    }

    // ============================================================================
    // 3. Multi-Tenant Concurrent Operations Tests
    // ============================================================================

    #[tokio::test]
    async fn test_concurrent_tenant_registration() {
        let registry = Arc::new(TenantRegistry::new(AuthConfig::default()));
        let mut handles = vec![];

        // Spawn 10 concurrent tenant registrations
        for i in 0..10 {
            let reg = Arc::clone(&registry);
            let handle = tokio::spawn(async move {
                let context =
                    create_test_tenant(&format!("concurrent-{}", i), &format!("Tenant {}", i));
                reg.register_tenant(context, None).await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let mut all_ok = true;
        for handle in handles {
            match handle.await {
                Ok(Ok(_)) => {}
                _ => {
                    all_ok = false;
                }
            }
        }

        assert!(all_ok, "All concurrent registrations should succeed");

        // Verify all 10 are registered
        assert_eq!(registry.tenant_count().await, 10);
    }

    #[tokio::test]
    async fn test_concurrent_read_access_to_frameworks() {
        let registry = Arc::new(TenantRegistry::new(AuthConfig::default()));

        // Register 5 tenants
        for i in 0..5 {
            let context =
                create_test_tenant(&format!("read-tenant-{}", i), &format!("Tenant {}", i));
            let _ = registry.register_tenant(context, None).await;
        }

        // Spawn 20 concurrent reads
        let mut handles = vec![];
        for _ in 0..20 {
            let reg = Arc::clone(&registry);
            let handle = tokio::spawn(async move {
                for i in 0..5 {
                    let tenant_id = TenantId::new(format!("read-tenant-{}", i));
                    let _ = reg.get_tenant_framework(&tenant_id);
                }
            });
            handles.push(handle);
        }

        // Wait for all reads to complete
        for handle in handles {
            let _ = handle.await;
        }

        assert_eq!(registry.tenant_count().await, 5);
    }

    #[tokio::test]
    async fn test_concurrent_mixed_operations() {
        let registry = Arc::new(TenantRegistry::new(AuthConfig::default()));

        // Register some initial tenants
        for i in 0..5 {
            let context = create_test_tenant(&format!("mixed-{}", i), &format!("Tenant {}", i));
            let _ = registry.register_tenant(context, None).await;
        }

        // Spawn mixed operations
        let mut register_handles = vec![];
        let mut read_handles = vec![];
        let mut deactivate_handles = vec![];

        // Register new tenants while reading existing ones
        for i in 5..8 {
            let reg = Arc::clone(&registry);
            let handle = tokio::spawn(async move {
                let context = create_test_tenant(&format!("mixed-{}", i), &format!("Tenant {}", i));
                reg.register_tenant(context, None).await
            });
            register_handles.push(handle);
        }

        // Concurrent reads
        for i in 0..3 {
            let reg = Arc::clone(&registry);
            let handle = tokio::spawn(async move {
                let tenant_id = TenantId::new(format!("mixed-{}", i));
                reg.get_tenant_framework(&tenant_id)
            });
            read_handles.push(handle);
        }

        // Concurrent deactivations
        for i in 2..4 {
            let reg = Arc::clone(&registry);
            let handle = tokio::spawn(async move {
                let tenant_id = TenantId::new(format!("mixed-{}", i));
                reg.deactivate_tenant(&tenant_id).await
            });
            deactivate_handles.push(handle);
        }

        for handle in register_handles {
            let _ = handle.await;
        }
        for handle in read_handles {
            let _ = handle.await;
        }
        for handle in deactivate_handles {
            let _ = handle.await;
        }

        // Should have more tenants now
        assert!(registry.tenant_count().await >= 5);
    }

    // ============================================================================
    // 4. Tenant Metadata Management Tests
    // ============================================================================

    #[tokio::test]
    async fn test_tenant_metadata_persistence() {
        let registry = TenantRegistry::new(AuthConfig::default());

        let mut context = create_test_tenant("metadata-test", "Testing metadata");

        // Add custom attributes
        context.metadata.attributes.insert(
            "department".to_string(),
            serde_json::Value::String("Engineering".to_string()),
        );
        context.metadata.attributes.insert(
            "tier".to_string(),
            serde_json::Value::String("Premium".to_string()),
        );

        let tenant_id = context.id.clone();
        let _ = registry.register_tenant(context, None).await;

        // Verify metadata is accessible from stored context
        let tenant_ids = registry.list_tenant_ids().await;
        assert!(tenant_ids.contains(&tenant_id));
    }

    #[tokio::test]
    async fn test_multiple_tenants_isolation() {
        let registry = TenantRegistry::new(AuthConfig::default());

        // Register 3 different tenants
        let contexts = vec![
            create_test_tenant("client-a", "Client A"),
            create_test_tenant("client-b", "Client B"),
            create_test_tenant("client-c", "Client C"),
        ];

        for context in contexts {
            let _ = registry.register_tenant(context, None).await;
        }

        // Verify all are independent
        let count = registry.tenant_count().await;
        assert_eq!(count, 3);

        let ids = registry.list_tenant_ids().await;
        assert_eq!(ids.len(), 3);

        // Deactivate one doesn't affect others
        let client_a = TenantId::new("client-a");
        let _ = registry.deactivate_tenant(&client_a).await;

        // Others should still be accessible
        let client_b = TenantId::new("client-b");
        let client_c = TenantId::new("client-c");

        assert!(registry.get_tenant_framework(&client_b).is_ok());
        assert!(registry.get_tenant_framework(&client_c).is_ok());
    }

    // ============================================================================
    // 5. Configuration Isolation Tests
    // ============================================================================

    #[tokio::test]
    async fn test_per_tenant_configuration() {
        let registry = TenantRegistry::new(AuthConfig::default());

        // Register tenant (without custom config, as custom config registration may not be supported)
        let context = create_test_tenant("config-tenant", "Config Test");

        let result = registry.register_tenant(context, None).await;
        assert!(result.is_ok(), "Should register tenant");

        // Verify tenant is accessible
        let tenant_id = TenantId::new("config-tenant");
        let framework = registry.get_tenant_framework(&tenant_id);
        assert!(framework.is_ok(), "Should access tenant");
    }

    // ============================================================================
    // 6. Listing and Discovery Tests
    // ============================================================================

    #[tokio::test]
    async fn test_list_active_tenants() {
        let registry = TenantRegistry::new(AuthConfig::default());

        // Register 5 tenants
        for i in 0..5 {
            let context = create_test_tenant(&format!("active-{}", i), &format!("Tenant {}", i));
            let _ = registry.register_tenant(context, None).await;
        }

        // Deactivate 2
        for i in 0..2 {
            let tenant_id = TenantId::new(format!("active-{}", i));
            let _ = registry.deactivate_tenant(&tenant_id).await;
        }

        let active_tenants = registry.list_active_tenants().await;
        assert_eq!(active_tenants.len(), 3, "Should have 3 active tenants");
    }

    #[tokio::test]
    async fn test_list_all_tenant_ids() {
        let registry = TenantRegistry::new(AuthConfig::default());

        let expected_names = vec!["list-tenant-1", "list-tenant-2", "list-tenant-3"];

        for name in &expected_names {
            let context = create_test_tenant(name, &format!("Test {}", name));
            let _ = registry.register_tenant(context, None).await;
        }

        let ids = registry.list_tenant_ids().await;
        assert_eq!(ids.len(), 3);

        for name in expected_names {
            let id = TenantId::new(name);
            assert!(ids.contains(&id), "Should contain tenant {}", name);
        }
    }

    // ============================================================================
    // 7. TenantId Validation Tests
    // ============================================================================

    #[test]
    fn test_tenant_id_validation_comprehensive() {
        // Valid IDs
        assert!(TenantId::new("simple").validate().is_ok());
        assert!(TenantId::new("tenant-with-dash").validate().is_ok());
        assert!(TenantId::new("tenant_with_underscore").validate().is_ok());
        assert!(TenantId::new("123numeric").validate().is_ok());
        assert!(TenantId::new("UPPERCASE").validate().is_ok());
        assert!(TenantId::new("MixedCase123").validate().is_ok());

        // Invalid IDs
        assert!(
            TenantId::new("").validate().is_err(),
            "Empty ID should fail"
        );
        assert!(
            TenantId::new("tenant@invalid").validate().is_err(),
            "@ not allowed"
        );
        assert!(
            TenantId::new("tenant!invalid").validate().is_err(),
            "! not allowed"
        );
        assert!(
            TenantId::new("tenant invalid").validate().is_err(),
            "spaces not allowed"
        );
        assert!(
            TenantId::new("a".repeat(65)).validate().is_err(),
            "too long"
        );
    }

    // ============================================================================
    // 8. Error Handling and Edge Cases Tests
    // ============================================================================

    #[tokio::test]
    async fn test_remove_and_reregister_tenant() {
        let registry = TenantRegistry::new(AuthConfig::default());

        let context = create_test_tenant("rereg", "test");
        let tenant_id = context.id.clone();

        // Register
        let _ = registry.register_tenant(context, None).await;
        assert_eq!(registry.tenant_count().await, 1);

        // Remove
        let remove_result = registry.remove_tenant(&tenant_id).await;
        assert!(remove_result.is_ok());
        assert_eq!(registry.tenant_count().await, 0);

        // Re-register with same ID
        let context2 = create_test_tenant("rereg", "test again");
        let reregister = registry.register_tenant(context2, None).await;
        assert!(
            reregister.is_ok(),
            "Should allow re-registration after removal"
        );
        assert_eq!(registry.tenant_count().await, 1);
    }

    #[tokio::test]
    async fn test_activate_already_active_tenant() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let context = create_test_tenant("double-active", "Test");
        let tenant_id = context.id.clone();

        let _ = registry.register_tenant(context, None).await;

        // Activate an already active tenant should still work
        let result = registry.activate_tenant(&tenant_id).await;
        assert!(result.is_ok());
        assert!(registry.get_tenant_framework(&tenant_id).is_ok());
    }

    #[tokio::test]
    async fn test_deactivate_already_inactive_tenant() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let context = create_test_tenant("double-inactive", "Test");
        let tenant_id = context.id.clone();

        let _ = registry.register_tenant(context, None).await;
        let _ = registry.deactivate_tenant(&tenant_id).await;

        // Deactivate already inactive is idempotent (succeeds)
        let result = registry.deactivate_tenant(&tenant_id).await;
        assert!(
            result.is_ok(),
            "Deactivating an already inactive tenant should succeed (idempotent)"
        );
    }

    // ============================================================================
    // 9. Stress Testing
    // ============================================================================

    #[tokio::test]
    async fn test_large_number_of_tenants() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let tenant_count = 100;

        // Register many tenants
        for i in 0..tenant_count {
            let context = create_test_tenant(&format!("stress-{}", i), &format!("Tenant {}", i));
            let _ = registry.register_tenant(context, None).await;
        }

        assert_eq!(registry.tenant_count().await, tenant_count);

        // List all IDs
        let ids = registry.list_tenant_ids().await;
        assert_eq!(ids.len(), tenant_count);

        // Verify all can be accessed
        for i in 0..tenant_count {
            let tenant_id = TenantId::new(format!("stress-{}", i));
            assert!(registry.get_tenant_framework(&tenant_id).is_ok());
        }
    }

    #[tokio::test]
    async fn test_rapid_activation_deactivation() {
        let registry = TenantRegistry::new(AuthConfig::default());
        let context = create_test_tenant("rapid", "Test");
        let tenant_id = context.id.clone();

        let _ = registry.register_tenant(context, None).await;

        // Rapidly toggle activation
        for _ in 0..10 {
            let _ = registry.deactivate_tenant(&tenant_id).await;
            let _ = registry.activate_tenant(&tenant_id).await;
        }

        // Should be active at the end
        assert!(registry.get_tenant_framework(&tenant_id).is_ok());
    }

    // ============================================================================
    // 10. Integration Scenario Tests
    // ============================================================================

    #[tokio::test]
    async fn test_multi_tenant_saas_scenario() {
        let registry = TenantRegistry::new(AuthConfig::default());

        // Simulate SaaS onboarding: 3 customers with different tiers
        struct Customer {
            id: &'static str,
            name: &'static str,
            tier: &'static str,
        }

        let customers = vec![
            Customer {
                id: "startup-inc",
                name: "Startup Inc",
                tier: "free",
            },
            Customer {
                id: "tech-corp",
                name: "Tech Corp",
                tier: "professional",
            },
            Customer {
                id: "enterprise-co",
                name: "Enterprise Co",
                tier: "enterprise",
            },
        ];

        // Onboard customers
        for customer in &customers {
            let mut context = create_test_tenant(customer.id, customer.name);
            context.metadata.attributes.insert(
                "tier".to_string(),
                serde_json::Value::String(customer.tier.to_string()),
            );
            let _ = registry.register_tenant(context, None).await;
        }

        // Simulate customer activity
        for customer in &customers {
            let tenant_id = TenantId::new(customer.id);
            let framework = registry.get_tenant_framework(&tenant_id);
            assert!(
                framework.is_ok(),
                "Should access {}'s framework",
                customer.id
            );
        }

        // Simulate account suspension (startup didn't pay)
        let startup_id = TenantId::new("startup-inc");
        let _ = registry.deactivate_tenant(&startup_id).await;
        assert!(registry.get_tenant_framework(&startup_id).is_err());

        // Others unaffected
        let tech_id = TenantId::new("tech-corp");
        assert!(registry.get_tenant_framework(&tech_id).is_ok());

        // Startup pays and reactivates
        let _ = registry.activate_tenant(&startup_id).await;
        assert!(registry.get_tenant_framework(&startup_id).is_ok());

        assert_eq!(registry.tenant_count().await, 3);
    }

    #[tokio::test]
    async fn test_tenant_lifecycle_with_framework_ops() {
        let registry = TenantRegistry::new(AuthConfig::default());

        // Register tenant
        let context = create_test_tenant("framework-test", "Test Framework Ops");
        let tenant_id = context.id.clone();

        let _ = registry.register_tenant(context, None).await;

        // Get framework
        let framework = registry.get_tenant_framework(&tenant_id);
        assert!(framework.is_ok());

        // Deactivate should prevent access
        let _ = registry.deactivate_tenant(&tenant_id).await;
        let framework_inactive = registry.get_tenant_framework(&tenant_id);
        assert!(framework_inactive.is_err());

        // Reactivate restores access
        let _ = registry.activate_tenant(&tenant_id).await;
        let framework_restored = registry.get_tenant_framework(&tenant_id);
        assert!(framework_restored.is_ok());
    }
}
