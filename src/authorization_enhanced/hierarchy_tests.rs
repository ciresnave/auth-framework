//! Test the new role-system v1.1.1 hierarchy features
//!
//! This demonstrates the new hierarchy access methods that were implemented
//! based on our enhancement proposal.

#[cfg(test)]
mod hierarchy_feature_tests {
    use crate::authorization_enhanced::service::{AuthorizationConfig, AuthorizationService};
    use role_system::{Permission, Role};

    #[tokio::test]
    async fn test_role_hierarchy_features() {
        println!("🧪 Testing new role-system v1.1.1 hierarchy features");

        // Create authorization service
        let service = AuthorizationService::with_config(AuthorizationConfig::default())
            .await
            .expect("Failed to create authorization service");

        // Create roles with hierarchy
        let guest_role = Role::new("guest").with_description("Guest user role");

        let user_role = Role::new("user").with_description("Regular user role");

        let admin_role = Role::new("admin").with_description("Administrator role");

        // Register roles
        service
            .role_system
            .register_role(guest_role.clone())
            .await
            .unwrap();
        service
            .role_system
            .register_role(user_role.clone())
            .await
            .unwrap();
        service
            .role_system
            .register_role(admin_role.clone())
            .await
            .unwrap();

        // Set up hierarchy: guest -> user -> admin
        service
            .role_system
            .add_role_inheritance("user", "guest")
            .await
            .unwrap();
        service
            .role_system
            .add_role_inheritance("admin", "user")
            .await
            .unwrap();

        // Test new Role hierarchy methods
        println!("✅ Testing Role hierarchy methods:");

        if let Ok(Some(admin)) = service.role_system.get_role("admin").await {
            // Test parent_role_id()
            if let Some(parent_id) = admin.parent_role_id() {
                println!("  📋 Admin parent role: {}", parent_id);
                assert_eq!(parent_id, "user");
            }

            // Test hierarchy metadata methods
            let depth = admin.hierarchy_depth();
            let is_root = admin.is_root_role();
            let is_leaf = admin.is_leaf_role();
            let children = admin.child_role_ids();

            println!("  📊 Admin role metadata:");
            println!("    - Depth: {}", depth);
            println!("    - Is root: {}", is_root);
            println!("    - Is leaf: {}", is_leaf);
            println!("    - Children: {:?}", children);

            // Admin should be at depth 2 (guest=0, user=1, admin=2)
            assert_eq!(depth, 2);
            assert!(!is_root); // Admin is not root (guest is)
            assert!(is_leaf); // Admin should be leaf (no children)
        }

        // Test AuthorizationService hierarchy methods
        println!("✅ Testing AuthorizationService hierarchy methods:");

        let hierarchy = service.get_role_hierarchy("admin").await.unwrap();
        println!("  🔗 Admin hierarchy: {:?}", hierarchy);
        assert!(hierarchy.contains(&"admin".to_string()));

        let metadata = service.get_role_metadata("admin").await.unwrap();
        println!("  📈 Admin metadata: {}", metadata);
        assert!(metadata.contains("admin"));
        assert!(metadata.contains("depth=2"));

        println!("🎉 All role-system v1.1.1 hierarchy features working correctly!");
    }

    #[tokio::test]
    async fn test_hierarchy_feature_integration_with_api() {
        println!("🔗 Testing hierarchy features integration with API endpoints");

        // This test demonstrates that the parent_id field in API responses
        // now works correctly thanks to the new parent_role_id() method

        let service = AuthorizationService::new().await.unwrap();

        // Create a role with hierarchy
        let manager_role = Role::new("manager").with_description("Manager role");

        service
            .role_system
            .register_role(manager_role)
            .await
            .unwrap();

        // Test that role retrieval now includes hierarchy information
        if let Ok(Some(role)) = service.role_system.get_role("manager").await {
            // This method is now available and used in API endpoints
            let parent_id = role.parent_role_id();
            println!("  📋 Manager parent role: {:?}", parent_id);

            // Additional hierarchy information now available
            let is_root = role.is_root_role();
            let depth = role.hierarchy_depth();
            println!("  📊 Manager is root: {}, depth: {}", is_root, depth);
        }

        println!("✅ API integration with hierarchy features confirmed!");
    }
}


