// Simple test to verify module structure is working
use auth_framework::{auth::Auth, errors::AuthError, server::jwt_access_tokens};

fn main() {
    println!("Module structure test passed!");
    println!("Auth module: {:?}", std::any::type_name::<Auth>());
    println!("AuthError module: {:?}", std::any::type_name::<AuthError>());
}
