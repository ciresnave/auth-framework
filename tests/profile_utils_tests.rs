//! Unit tests for profile utility functions and token-to-profile conversion

// Standard library imports for Rust 2024 edition
use std::{
    assert, assert_eq,
    boxed::Box,
    format,
    option::Option::{None, Some},
};

use auth_framework::profile_utils::ExtractProfile;
use auth_framework::providers::{OAuthProvider, UserProfile};
use base64::Engine;
use serde_json::json;

#[test]
fn test_user_profile_builder() {
    let profile = UserProfile::new()
        .with_id("123456")
        .with_provider("github")
        .with_username(Some("testuser"))
        .with_name(Some("Test User"))
        .with_email(Some("test@example.com"))
        .with_email_verified(true)
        .with_picture(Some("https://example.com/pic.jpg"))
        .with_locale(Some("en-US"))
        .with_additional_data("custom_field", json!("custom_value"));

    assert_eq!(profile.id, Some("123456".to_string()));
    assert_eq!(profile.provider, Some("github".to_string()));
    assert_eq!(profile.username, Some("testuser".to_string()));
    assert_eq!(profile.name, Some("Test User".to_string()));
    assert_eq!(profile.email, Some("test@example.com".to_string()));
    assert_eq!(profile.email_verified, Some(true));
    assert_eq!(
        profile.picture,
        Some("https://example.com/pic.jpg".to_string())
    );
    assert_eq!(profile.locale, Some("en-US".to_string()));

    let custom_value = profile.additional_data.get("custom_field").unwrap();
    assert_eq!(custom_value.as_str().unwrap(), "custom_value");
}

#[test]
fn test_extract_profile_github() {
    let provider = OAuthProvider::GitHub;
    let json_response = json!({
        "id": "12345",
        "login": "testuser",
        "name": "Test User",
        "email": "test@example.com",
        "avatar_url": "https://github.com/avatar.png"
    });

    let profile = provider
        .extract_profile(&provider, json_response.clone())
        .unwrap();

    assert_eq!(profile.id, Some("12345".to_string()));
    assert_eq!(profile.username, Some("testuser".to_string()));
    assert_eq!(profile.name, Some("Test User".to_string()));
    assert_eq!(profile.email, Some("test@example.com".to_string()));
    assert_eq!(
        profile.picture,
        Some("https://github.com/avatar.png".to_string())
    );

    // Check raw profile storage
    let raw_profile = profile.additional_data.get("raw_profile").unwrap();
    assert_eq!(raw_profile, &json_response);
}

#[test]
fn test_extract_profile_google() {
    let provider = OAuthProvider::Google;
    let json_response = json!({
        "sub": "987654321",
        "name": "Test Google User",
        "email": "google@example.com",
        "email_verified": true,
        "picture": "https://google.com/photo.jpg",
        "locale": "en"
    });

    let profile = provider.extract_profile(&provider, json_response).unwrap();

    assert_eq!(profile.id, Some("987654321".to_string()));
    assert_eq!(profile.name, Some("Test Google User".to_string()));
    assert_eq!(profile.email, Some("google@example.com".to_string()));
    assert_eq!(profile.email_verified, Some(true));
    assert_eq!(
        profile.picture,
        Some("https://google.com/photo.jpg".to_string())
    );
    assert_eq!(profile.locale, Some("en".to_string()));
}

#[test]
fn test_extract_profile_custom() {
    let config = OAuthProvider::GitHub.config();
    let provider = OAuthProvider::Custom {
        name: "CustomProvider".to_string(),
        config: Box::new(config),
    };

    let json_response = json!({
        "id": "custom123",
        "username": "custom_user",
        "display_name": "Custom User",
        "email": "custom@example.com",
        "avatar": "https://custom.com/avatar.png"
    });

    let profile = provider.extract_profile(&provider, json_response).unwrap();

    assert_eq!(profile.id, Some("custom123".to_string()));
    assert_eq!(profile.username, Some("custom_user".to_string()));
    assert_eq!(profile.name, Some("Custom User".to_string()));
    assert_eq!(profile.email, Some("custom@example.com".to_string()));
    assert_eq!(
        profile.picture,
        Some("https://custom.com/avatar.png".to_string())
    );
}

#[tokio::test]
async fn test_from_id_token() {
    // Use a valid JWT with correct base64url encoding and claims
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload =
        URL_SAFE_NO_PAD.encode(r#"{"sub":"12345","name":"John Doe","email":"john@example.com"}"#);
    let id_token = format!("{}.{}.{}", header, payload, "dummy_signature");

    let profile = UserProfile::from_id_token(&id_token).unwrap();
    assert_eq!(profile.id, Some("12345".to_string()));
    assert_eq!(profile.name, Some("John Doe".to_string()));
    assert_eq!(profile.email, Some("john@example.com".to_string()));
}

#[test]
fn test_user_profile_display_name() {
    // Test with name present
    let profile1 = UserProfile::new()
        .with_name(Some("Display Name"))
        .with_username(Some("username"));
    assert_eq!(profile1.display_name(), Some("Display Name"));

    // Test fallback to username
    let profile2 = UserProfile::new().with_username(Some("username"));
    assert_eq!(profile2.display_name(), Some("username"));

    // Test with neither present
    let profile3 = UserProfile::new();
    assert_eq!(profile3.display_name(), None);
}

#[test]
fn test_to_auth_token() {
    let profile = UserProfile::new()
        .with_id("12345")
        .with_provider("github")
        .with_name(Some("Test User"))
        .with_email(Some("test@example.com"));

    let token = profile.to_auth_token("access_token_value".to_string());

    assert_eq!(token.token_value(), "access_token_value");
    let token_type = token.token_type().unwrap_or_default().to_lowercase();
    assert!(
        token_type == "bearer",
        "token_type should be 'bearer', got: {}",
        token_type
    );
    // The subject should match the id field
    assert_eq!(token.subject, Some("12345".to_string()));
    assert_eq!(token.issuer, Some("github".to_string()));

    // Check the embedded profile
    let embedded_profile = token.user_profile.unwrap();
    assert_eq!(embedded_profile.id, Some("12345".to_string()));
    assert_eq!(embedded_profile.name, Some("Test User".to_string()));
}
