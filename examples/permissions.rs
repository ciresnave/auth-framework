use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::JwtMethod;
use auth_framework::permissions::{Permission, Role, PermissionChecker};
use auth_framework::storage::MemoryStorage;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🛡️  Auth Framework - Permissions & Authorization Example");
    println!("========================================================");

    // 1. Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_rbac(true)
        .enable_abac(true);

    let storage = Arc::new(MemoryStorage::new());
    let mut auth = AuthFramework::new(config).with_storage(storage);

    // 2. Register authentication method
    let jwt_method = JwtMethod::new()
        .secret_key("very-secure-jwt-secret-key-for-permissions")
        .issuer("auth-framework-permissions-demo")
        .audience("api-service");

    auth.register_method("jwt", Box::new(jwt_method));
    auth.initialize().await?;
    println!("✅ Auth framework initialized");

    // 3. Set up role-based access control (RBAC)
    setup_rbac_system(&auth).await?;

    // 4. Set up attribute-based access control (ABAC)
    setup_abac_system(&auth).await?;

    // 5. Demonstrate permission checking
    demonstrate_basic_permissions(&auth).await?;
    demonstrate_role_inheritance(&auth).await?;
    demonstrate_resource_hierarchy(&auth).await?;
    demonstrate_dynamic_permissions(&auth).await?;
    demonstrate_permission_delegation(&auth).await?;
    demonstrate_audit_logging(&auth).await?;

    println!("\n🎉 Permissions example completed successfully!");
    println!("Next steps:");
    println!("- Try the middleware example: cargo run --example middleware");
    println!("- Review the security features in your implementation");

    Ok(())
}

async fn setup_rbac_system(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n👥 Setting up Role-Based Access Control (RBAC):");
    println!("===============================================");

    // Define roles with their permissions
    let roles = vec![
        (
            "guest",
            "Guest User",
            vec![
                "content:read",
                "profile:view",
            ]
        ),
        (
            "user",
            "Regular User", 
            vec![
                "content:read",
                "content:comment",
                "profile:view",
                "profile:edit",
                "messages:send",
                "messages:read",
            ]
        ),
        (
            "moderator",
            "Content Moderator",
            vec![
                "content:read",
                "content:edit",
                "content:moderate",
                "content:delete",
                "users:view",
                "reports:handle",
            ]
        ),
        (
            "admin",
            "Administrator",
            vec![
                "users:create",
                "users:edit",
                "users:delete",
                "users:view",
                "content:manage",
                "system:configure",
                "logs:view",
                "reports:generate",
            ]
        ),
        (
            "super_admin",
            "Super Administrator",
            vec![
                "system:full_access",
                "security:manage",
                "audit:view",
                "backup:manage",
                "users:impersonate",
            ]
        ),
    ];

    // Create roles in the system
    for (role_name, description, permissions) in roles {
        let role = Role::new(role_name, description)
            .with_permissions(permissions.iter().map(|p| Permission::new(p)).collect());
        
        auth.create_role(role).await?;
        println!("📋 Created role '{}': {}", role_name, description);
        println!("   Permissions: {:?}", permissions);
    }

    // Set up role hierarchy (inheritance)
    auth.set_role_inheritance("user", "guest").await?;
    auth.set_role_inheritance("moderator", "user").await?;
    auth.set_role_inheritance("admin", "moderator").await?;
    auth.set_role_inheritance("super_admin", "admin").await?;

    println!("\n🏗️  Role hierarchy established:");
    println!("   super_admin → admin → moderator → user → guest");

    Ok(())
}

async fn setup_abac_system(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎯 Setting up Attribute-Based Access Control (ABAC):");
    println!("====================================================");

    // Define attribute-based policies
    let policies = vec![
        // Time-based access
        ("time_restricted_access", 
         "Allow access only during business hours (9 AM - 5 PM)"),
        
        // Location-based access
        ("location_restricted_access",
         "Allow admin actions only from office IP ranges"),
        
        // Resource-based access
        ("document_owner_access",
         "Allow users to edit only documents they own"),
        
        // Department-based access
        ("department_access",
         "Allow access to department-specific resources"),
        
        // Project-based access
        ("project_member_access",
         "Allow access only to project members"),
    ];

    for (policy_name, description) in policies {
        auth.create_abac_policy(policy_name, description).await?;
        println!("📜 Created ABAC policy '{}': {}", policy_name, description);
    }

    // Set up attribute mappings
    auth.map_user_attribute("user_123", "department", "engineering").await?;
    auth.map_user_attribute("user_123", "location", "office").await?;
    auth.map_user_attribute("user_123", "clearance_level", "3").await?;

    auth.map_user_attribute("user_456", "department", "marketing").await?;
    auth.map_user_attribute("user_456", "location", "remote").await?;
    auth.map_user_attribute("user_456", "clearance_level", "2").await?;

    println!("👤 User attributes configured for contextual access control");

    Ok(())
}

async fn demonstrate_basic_permissions(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Basic Permission Checking:");
    println!("============================");

    // Create test users with different roles
    let users = vec![
        ("guest_user", "guest"),
        ("regular_user", "user"),
        ("mod_user", "moderator"),
        ("admin_user", "admin"),
    ];

    // Assign roles to users
    for (user_id, role) in &users {
        auth.assign_role(user_id, role).await?;
        println!("👤 Assigned '{}' role to {}", role, user_id);
    }

    // Test various permissions
    let test_permissions = vec![
        ("content:read", "Reading content"),
        ("content:edit", "Editing content"),
        ("content:delete", "Deleting content"),
        ("users:view", "Viewing users"),
        ("system:configure", "System configuration"),
    ];

    println!("\n📊 Permission Test Results:");
    println!("----------------------------");

    for (permission, description) in test_permissions {
        println!("\n🔐 Testing: {} ({})", permission, description);
        
        for (user_id, role) in &users {
            let has_permission = auth.check_permission(user_id, permission, "default").await?;
            let status = if has_permission { "✅ ALLOWED" } else { "❌ DENIED" };
            println!("   {} ({}): {}", user_id, role, status);
        }
    }

    Ok(())
}

async fn demonstrate_role_inheritance(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔗 Role Inheritance:");
    println!("===================");

    let test_user = "inheritance_test_user";
    
    // Assign moderator role (should inherit user and guest permissions)
    auth.assign_role(test_user, "moderator").await?;
    println!("👤 Assigned 'moderator' role to {}", test_user);

    // Test inherited permissions
    let inherited_permissions = vec![
        ("content:read", "guest"),      // From guest role
        ("profile:edit", "user"),       // From user role
        ("content:moderate", "moderator"), // Direct permission
    ];

    println!("\n🧬 Testing inherited permissions:");
    for (permission, source_role) in inherited_permissions {
        let has_permission = auth.check_permission(test_user, permission, "default").await?;
        let status = if has_permission { "✅ INHERITED" } else { "❌ NOT INHERITED" };
        println!("   {} (from {}): {}", permission, source_role, status);
    }

    // Get effective permissions (all permissions user has)
    let effective_permissions = auth.get_effective_permissions(test_user).await?;
    println!("\n📋 All effective permissions for {}:", test_user);
    for permission in effective_permissions {
        println!("   • {}", permission);
    }

    Ok(())
}

async fn demonstrate_resource_hierarchy(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🏗️  Resource Hierarchy:");
    println!("======================");

    // Set up resource hierarchy
    // company/department/team/project/document
    let resources = vec![
        "company",
        "company/engineering",
        "company/engineering/backend",
        "company/engineering/backend/auth_project",
        "company/engineering/backend/auth_project/design_doc.md",
        "company/marketing",
        "company/marketing/campaigns",
        "company/marketing/campaigns/q4_campaign",
    ];

    for resource in &resources {
        auth.create_resource(resource).await?;
    }
    println!("🗂️  Created resource hierarchy with {} resources", resources.len());

    // Assign permissions at different levels
    let user_id = "hierarchy_test_user";
    
    // Give read access to entire engineering department
    auth.grant_permission(user_id, "content:read", "company/engineering").await?;
    println!("🔑 Granted 'content:read' on 'company/engineering' to {}", user_id);
    
    // Give write access to specific project
    auth.grant_permission(user_id, "content:edit", "company/engineering/backend/auth_project").await?;
    println!("🔑 Granted 'content:edit' on 'auth_project' to {}", user_id);

    // Test hierarchical permissions
    let test_resources = vec![
        "company/engineering/backend/auth_project/design_doc.md",
        "company/engineering/frontend/ui_project/wireframes.pdf",
        "company/marketing/campaigns/q4_campaign",
    ];

    println!("\n🔍 Testing hierarchical access:");
    for resource in test_resources {
        let can_read = auth.check_permission(user_id, "content:read", resource).await?;
        let can_edit = auth.check_permission(user_id, "content:edit", resource).await?;
        
        println!("   📄 {}:", resource);
        println!("      Read: {}", if can_read { "✅ YES" } else { "❌ NO" });
        println!("      Edit: {}", if can_edit { "✅ YES" } else { "❌ NO" });
    }

    Ok(())
}

async fn demonstrate_dynamic_permissions(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ Dynamic Permissions (Context-Aware):");
    println!("=====================================");

    let user_id = "dynamic_user";
    
    // Test time-based permissions
    println!("🕐 Time-based permissions:");
    let current_hour = chrono::Utc::now().hour();
    
    if current_hour >= 9 && current_hour <= 17 {
        println!("   ✅ Current time ({:02}:xx) is within business hours", current_hour);
        println!("   🔓 Administrative actions allowed");
    } else {
        println!("   ❌ Current time ({:02}:xx) is outside business hours", current_hour);
        println!("   🔒 Administrative actions restricted");
    }

    // Test location-based permissions
    println!("\n📍 Location-based permissions:");
    let user_ip = "192.168.1.100"; // Simulate office IP
    let is_office_ip = user_ip.starts_with("192.168.1.");
    
    if is_office_ip {
        println!("   ✅ IP {} is from office network", user_ip);
        println!("   🔓 Sensitive operations allowed");
    } else {
        println!("   ❌ IP {} is not from office network", user_ip);
        println!("   🔒 Sensitive operations restricted");
    }

    // Test attribute-based permissions
    println!("\n🏷️  Attribute-based permissions:");
    let user_department = auth.get_user_attribute(user_id, "department").await?;
    let user_clearance = auth.get_user_attribute(user_id, "clearance_level").await?;
    
    println!("   👤 User department: {:?}", user_department);
    println!("   🔰 User clearance level: {:?}", user_clearance);

    // Simulate dynamic permission evaluation
    let contexts = vec![
        ("financial_data", "Department: finance, Clearance: 4+"),
        ("engineering_docs", "Department: engineering, Clearance: 2+"),
        ("public_content", "No restrictions"),
    ];

    for (resource, requirements) in contexts {
        let has_access = auth.check_dynamic_permission(
            user_id, 
            "content:read", 
            resource,
            &[
                ("time", &current_hour.to_string()),
                ("ip", user_ip),
                ("department", &user_department.unwrap_or_default()),
                ("clearance", &user_clearance.unwrap_or_default()),
            ]
        ).await?;

        println!("   📄 {}: {} ({})", 
                resource, 
                if has_access { "✅ ALLOWED" } else { "❌ DENIED" },
                requirements);
    }

    Ok(())
}

async fn demonstrate_permission_delegation(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🤝 Permission Delegation:");
    println!("========================");

    let manager_id = "manager_123";
    let delegate_id = "assistant_456";
    
    // Manager has admin permissions
    auth.assign_role(manager_id, "admin").await?;
    println!("👔 Manager {} has admin role", manager_id);

    // Delegate specific permissions temporarily
    let delegated_permissions = vec![
        "users:view",
        "reports:generate",
        "content:moderate",
    ];

    for permission in &delegated_permissions {
        auth.delegate_permission(
            manager_id,
            delegate_id,
            permission,
            "project_documents",
            Some(Duration::from_secs(3600)), // 1 hour
        ).await?;
    }

    println!("🔄 Delegated permissions from {} to {} for 1 hour:", manager_id, delegate_id);
    for permission in &delegated_permissions {
        println!("   • {}", permission);
    }

    // Test delegated permissions
    println!("\n🧪 Testing delegated access:");
    for permission in &delegated_permissions {
        let has_permission = auth.check_permission(delegate_id, permission, "project_documents").await?;
        println!("   {}: {}", permission, if has_permission { "✅ DELEGATED" } else { "❌ NOT AVAILABLE" });
    }

    // Test non-delegated permission
    let non_delegated = "system:configure";
    let has_non_delegated = auth.check_permission(delegate_id, non_delegated, "project_documents").await?;
    println!("   {} (not delegated): {}", non_delegated, if has_non_delegated { "❌ UNEXPECTED" } else { "✅ PROPERLY RESTRICTED" });

    // Show delegation audit trail
    let delegations = auth.get_active_delegations(delegate_id).await?;
    println!("\n📋 Active delegations for {}:", delegate_id);
    for delegation in delegations {
        println!("   • {} (expires: {})", delegation.permission, delegation.expires_at);
    }

    Ok(())
}

async fn demonstrate_audit_logging(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📝 Permission Audit Logging:");
    println!("===========================");

    let audit_user = "audit_test_user";
    
    // Perform various permission operations that should be logged
    let operations = vec![
        ("content:read", "document_123", true),
        ("content:edit", "document_123", false),
        ("users:delete", "user_456", false),
        ("system:backup", "database", true),
    ];

    println!("🔍 Performing audited operations:");
    for (permission, resource, should_succeed) in operations {
        let result = auth.check_permission(audit_user, permission, resource).await?;
        let status = if result == should_succeed { "✅ EXPECTED" } else { "⚠️ UNEXPECTED" };
        
        println!("   {} on {}: {} {}", permission, resource, 
                if result { "ALLOWED" } else { "DENIED" }, status);
    }

    // Retrieve audit logs
    println!("\n📊 Audit Log Summary:");
    let audit_logs = auth.get_permission_audit_logs(Some(audit_user), None, Some(10)).await?;
    
    for log_entry in audit_logs {
        println!("   🕐 {} - {} {} {} on {} ({})", 
                log_entry.timestamp.format("%H:%M:%S"),
                log_entry.user_id,
                if log_entry.granted { "GRANTED" } else { "DENIED" },
                log_entry.permission,
                log_entry.resource,
                log_entry.reason.unwrap_or_default());
    }

    // Security metrics
    println!("\n📈 Security Metrics:");
    let metrics = auth.get_permission_metrics().await?;
    println!("   Total permission checks: {}", metrics.total_checks);
    println!("   Granted: {} ({:.1}%)", metrics.granted_count, 
            (metrics.granted_count as f64 / metrics.total_checks as f64) * 100.0);
    println!("   Denied: {} ({:.1}%)", metrics.denied_count,
            (metrics.denied_count as f64 / metrics.total_checks as f64) * 100.0);
    println!("   Most checked permission: {}", metrics.most_checked_permission);
    println!("   Most accessed resource: {}", metrics.most_accessed_resource);

    Ok(())
}
