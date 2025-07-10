use auth_framework::{AuthFramework, AuthConfig, AuthResult};
use auth_framework::methods::JwtMethod;
use auth_framework::permissions::{Permission, Role};
use auth_framework::credentials::Credential;
use auth_framework::tokens::AuthToken;
use std::time::Duration;
use chrono::Timelike;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("🔐 Auth Framework - Permissions & RBAC Example");
    println!("===============================================");

    // 1. Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .enable_rbac(true);

    let mut auth = AuthFramework::new(config);

    // 2. Register authentication method
    let jwt_method = JwtMethod::new()
        .secret_key("very-secure-jwt-secret-key-for-permissions-demo")
        .issuer("auth-framework-permissions-demo")
        .audience("secure-service");

    auth.register_method("jwt", Box::new(jwt_method));

    auth.initialize().await?;
    println!("✅ Auth framework initialized with RBAC support");

    // 3. Set up roles and permissions
    setup_roles_and_permissions(&mut auth).await?;

    // 4. Demonstrate permission checking
    demonstrate_basic_permissions(&auth).await?;
    demonstrate_role_based_access(&auth).await?;
    demonstrate_resource_permissions(&auth).await?;
    demonstrate_time_based_access(&auth).await?;

    println!("\n🎉 Permissions example completed successfully!");
    Ok(())
}

/// Helper function to authenticate a user and return the token
async fn authenticate_user(auth: &AuthFramework, user_id: &str) -> Result<AuthToken, Box<dyn std::error::Error>> {
    let credential = Credential::Password {
        username: user_id.to_string(),
        password: "password123".to_string(),
    };
    
    let auth_result = auth.authenticate("jwt", credential).await?;
    match auth_result {
        AuthResult::Success(token) => Ok(*token),
        AuthResult::MfaRequired(challenge) => {
            Err(format!("MFA required for user {}: {:?}", user_id, challenge).into())
        }
        AuthResult::Failure(reason) => {
            Err(format!("Authentication failed for {}: {}", user_id, reason).into())
        }
    }
}

async fn setup_roles_and_permissions(_auth: &mut AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📋 Setting up Roles and Permissions");
    println!("===================================");

    // Define roles
    let _admin_role = Role::new("admin");
    let _editor_role = Role::new("editor");
    let _viewer_role = Role::new("viewer");
    let _guest_role = Role::new("guest");

    println!("✅ Created roles: admin, editor, viewer, guest");

    // Define permissions
    let permissions = vec![
        Permission::new("read", "content"),
        Permission::new("write", "content"),
        Permission::new("delete", "content"),
        Permission::new("manage", "users"),
        Permission::new("view", "analytics"),
        Permission::new("configure", "system"),
    ];

    println!("✅ Created {} permissions", permissions.len());
    for permission in &permissions {
        println!("   - {}", permission.action);
    }

    Ok(())
}

async fn demonstrate_basic_permissions(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Basic Permission Checking");
    println!("============================");

    // Create a test user token using password authentication
    let user_id = "test_user";
    let credential = Credential::Password {
        username: user_id.to_string(),
        password: "password123".to_string(),
    };
    
    let auth_result = auth.authenticate("jwt", credential).await?;
    let token = match auth_result {
        AuthResult::Success(token) => *token,
        AuthResult::MfaRequired(challenge) => {
            println!("MFA required for user: {:?}", challenge);
            return Ok(());
        }
        AuthResult::Failure(reason) => {
            println!("Authentication failed: {}", reason);
            return Ok(());
        }
    };

    // Test various permissions
    let permissions_to_test = vec![
        ("read", "content"),
        ("write", "content"),
        ("delete", "content"),
        ("manage", "users"),
        ("configure", "system"),
    ];

    for (action, resource) in permissions_to_test {
        let has_permission = auth.check_permission(&token, action, resource).await?;
        let status = if has_permission { "✅ GRANTED" } else { "❌ DENIED" };
        println!("   {}:{} → {}", action, resource, status);
    }

    Ok(())
}

async fn demonstrate_role_based_access(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n👥 Role-Based Access Control");
    println!("=============================");

    // Simulate different user roles
    let test_users = vec![
        ("admin_user", vec!["admin"]),
        ("editor_user", vec!["editor"]),
        ("viewer_user", vec!["viewer"]),
        ("guest_user", vec!["guest"]),
    ];

    for (user_id, roles) in test_users {
        println!("\n👤 Testing user: {} (roles: {:?})", user_id, roles);
        
        // Authenticate user using helper function
        let token = authenticate_user(auth, user_id).await?;
        
        // Test key permissions
        let test_permissions = vec![
            ("read", "content"),
            ("write", "content"),
            ("delete", "content"),
            ("manage", "users"),
        ];

        for (action, resource) in test_permissions {
            let has_permission = auth.check_permission(&token, action, resource).await?;
            let status = if has_permission { "✅" } else { "❌" };
            println!("   {}:{} → {}", action, resource, status);
        }
    }

    Ok(())
}

async fn demonstrate_resource_permissions(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📂 Resource-Specific Permissions");
    println!("================================");

    let user_id = "content_manager";
    let token = authenticate_user(auth, user_id).await?;

    // Test permissions on different resources
    let resources = vec![
        "blog/posts",
        "blog/comments", 
        "users/profiles",
        "admin/settings",
        "analytics/reports",
    ];

    for resource in resources {
        println!("\n📁 Resource: {}", resource);
        
        let actions = vec!["read", "write", "delete"];
        for action in actions {
            let can_read = auth.check_permission(&token, action, &resource).await?;
            let status = if can_read { "✅ Allowed" } else { "❌ Denied" };
            println!("   {}: {}", action, status);
        }
    }

    Ok(())
}

async fn demonstrate_time_based_access(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⏰ Time-Based Access Control");
    println!("============================");

    let user_id = "time_restricted_user";
    let token = authenticate_user(auth, user_id).await?;
    
    // Get current time
    let current_hour = chrono::Utc::now().hour();
    println!("⏰ Current hour (UTC): {}", current_hour);

    // Simulate business hours check (9 AM to 5 PM UTC)
    let is_business_hours = current_hour >= 9 && current_hour < 17;
    
    println!("🏢 Business hours (9-17 UTC): {}", 
             if is_business_hours { "✅ Yes" } else { "❌ No" });

    // Test time-sensitive operations
    let sensitive_operations = vec![
        "financial_transfer",
        "user_deletion",
        "system_backup",
        "data_export",
    ];

    for operation in sensitive_operations {
        // In a real system, you'd check time-based rules in permission logic
        let can_perform = auth.check_permission(&token, "execute", operation).await?;
        let time_allowed = is_business_hours; // Simplified time check
        let final_permission = can_perform && time_allowed;
        
        let status = if final_permission { "✅ Allowed" } else { "❌ Denied" };
        let reason = if !can_perform {
            "(no permission)"
        } else if !time_allowed {
            "(outside business hours)"
        } else {
            ""
        };
        
        println!("   {}: {} {}", operation, status, reason);
    }

    Ok(())
}
