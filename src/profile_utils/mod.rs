//! Utilities for token-to-profile conversion and user profile management.

use crate::errors::{AuthError, OAuthProviderError, Result};
use crate::providers::{OAuthProvider, OAuthTokenResponse, UserProfile};
use crate::tokens::AuthToken;
#[cfg(feature = "reqwest")]
use reqwest::Client;
use serde_json::Value;
// HashMap is used for token metadata

/// Trait for converting tokens to user profiles
#[allow(async_fn_in_trait)]
pub trait TokenToProfile {
    /// Convert a token to a user profile
    async fn to_profile(&self, provider: &OAuthProvider) -> Result<UserProfile>;
}

/// Trait for automatic extraction of user profiles from responses
pub trait ExtractProfile {
    /// Extract a user profile from a JSON response
    fn extract_profile(
        &self,
        provider: &OAuthProvider,
        json_response: Value,
    ) -> Result<UserProfile>;
}

impl TokenToProfile for OAuthTokenResponse {
    async fn to_profile(&self, provider: &OAuthProvider) -> Result<UserProfile> {
        let config = provider.config();
        let userinfo_url = config.userinfo_url.clone().ok_or_else(|| {
            AuthError::OAuthProvider(OAuthProviderError::UnsupportedFeature {
                provider: format!("{:?}", provider),
                feature: "userinfo endpoint".to_string(),
            })
        })?;

        let client = Client::new();
        let response = client
            .get(&userinfo_url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(format!("Failed to fetch user profile: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AuthError::NetworkError(format!(
                "Failed to fetch user profile. Status code: {}",
                status
            )));
        }

        let json_response = response.json::<Value>().await.map_err(|e| {
            AuthError::ParseError(format!("Failed to parse user profile response: {}", e))
        })?;

        provider.extract_profile(provider, json_response)
    }
}

impl ExtractProfile for OAuthProvider {
    fn extract_profile(
        &self,
        _provider: &OAuthProvider,
        json_response: Value,
    ) -> Result<UserProfile> {
        // Default extractor attempts to map standard fields based on provider
        let mut profile = UserProfile::new();

        // Get ID field based on provider
        match self {
            OAuthProvider::GitHub => {
                profile = profile.with_id(extract_string(&json_response, "id")?);
                profile = profile.with_username(extract_string_optional(&json_response, "login"));
                profile = profile.with_name(extract_string_optional(&json_response, "name"));
                profile = profile.with_email(extract_string_optional(&json_response, "email"));
                profile =
                    profile.with_picture(extract_string_optional(&json_response, "avatar_url"));
            }
            OAuthProvider::Google => {
                profile = profile.with_id(extract_string(&json_response, "sub")?);
                profile = profile.with_email(extract_string_optional(&json_response, "email"));
                profile = profile.with_name(extract_string_optional(&json_response, "name"));
                profile = profile.with_picture(extract_string_optional(&json_response, "picture"));
                profile = profile.with_locale(extract_string_optional(&json_response, "locale"));

                if let Some(email_verified) = json_response
                    .get("email_verified")
                    .and_then(|v| v.as_bool())
                {
                    profile = profile.with_email_verified(email_verified);
                }
            }
            OAuthProvider::Microsoft => {
                profile = profile.with_id(extract_string(&json_response, "id")?);
                profile = profile.with_email(
                    extract_string_optional(&json_response, "userPrincipalName")
                        .or_else(|| extract_string_optional(&json_response, "mail")),
                );
                profile = profile.with_name(extract_string_optional(&json_response, "displayName"));

                // Microsoft Graph API might have these in different formats
                if let Some(photo) = json_response.get("photo") {
                    profile = profile.with_picture(photo.as_str().map(String::from));
                }
            }
            OAuthProvider::Discord => {
                profile = profile.with_id(extract_string(&json_response, "id")?);
                profile =
                    profile.with_username(extract_string_optional(&json_response, "username"));
                profile = profile.with_email(extract_string_optional(&json_response, "email"));

                if let Some(avatar) = extract_string_optional(&json_response, "avatar") {
                    let id = extract_string_optional(&json_response, "id").unwrap_or_default();
                    let avatar_url =
                        format!("https://cdn.discordapp.com/avatars/{}/{}.png", id, avatar);
                    profile = profile.with_picture(Some(avatar_url));
                }
            }
            OAuthProvider::GitLab => {
                profile = profile.with_id(extract_string(&json_response, "id")?);
                profile =
                    profile.with_username(extract_string_optional(&json_response, "username"));
                profile = profile.with_name(extract_string_optional(&json_response, "name"));
                profile = profile.with_email(extract_string_optional(&json_response, "email"));
                profile =
                    profile.with_picture(extract_string_optional(&json_response, "avatar_url"));
            }
            OAuthProvider::Twitter => {
                // Twitter API v2 has a different structure
                if let Some(data) = json_response.get("data") {
                    profile = profile.with_id(extract_string_from_value(data, "id")?);
                    profile =
                        profile.with_username(extract_string_optional_from_value(data, "username"));
                    profile = profile.with_name(extract_string_optional_from_value(data, "name"));
                } else {
                    profile = profile.with_id(extract_string(&json_response, "id")?);
                    profile = profile
                        .with_username(extract_string_optional(&json_response, "screen_name"));
                    profile = profile.with_name(extract_string_optional(&json_response, "name"));
                    profile = profile.with_picture(extract_string_optional(
                        &json_response,
                        "profile_image_url_https",
                    ));
                }
            }
            OAuthProvider::Facebook => {
                profile = profile.with_id(extract_string(&json_response, "id")?);
                profile = profile.with_name(extract_string_optional(&json_response, "name"));
                profile = profile.with_email(extract_string_optional(&json_response, "email"));
                // Facebook requires requesting the picture separately or with fields parameter
                if let Some(id) = extract_string_optional(&json_response, "id") {
                    let picture_url =
                        format!("https://graph.facebook.com/{}/picture?type=large", id);
                    profile = profile.with_picture(Some(picture_url));
                }
            }
            OAuthProvider::LinkedIn => {
                profile = profile.with_id(extract_string(&json_response, "id")?);
                // LinkedIn API structure is complex, try to navigate it
                if let Some(name) = json_response
                    .get("localizedFirstName")
                    .and_then(|f| f.as_str())
                    .zip(
                        json_response
                            .get("localizedLastName")
                            .and_then(|l| l.as_str()),
                    )
                {
                    profile = profile.with_name(Some(format!("{} {}", name.0, name.1)));
                }
                // For LinkedIn, email requires a separate API call with r_emailaddress permission
            }
            OAuthProvider::Custom { name, .. } => {
                // For custom providers, try some common ID field names
                let id = extract_string_optional(&json_response, "id")
                    .or_else(|| extract_string_optional(&json_response, "sub"))
                    .or_else(|| extract_string_optional(&json_response, "user_id"));

                if let Some(id) = id {
                    profile = profile.with_id(id);
                } else {
                    return Err(AuthError::validation(format!(
                        "Could not find ID field in response from custom provider {}",
                        name
                    )));
                }

                // Try common fields
                profile = profile.with_email(extract_string_optional(&json_response, "email"));
                profile = profile.with_name(
                    extract_string_optional(&json_response, "name")
                        .or_else(|| extract_string_optional(&json_response, "display_name")),
                );
                profile = profile.with_username(
                    extract_string_optional(&json_response, "username")
                        .or_else(|| extract_string_optional(&json_response, "login")),
                );
                profile = profile.with_picture(
                    extract_string_optional(&json_response, "picture")
                        .or_else(|| extract_string_optional(&json_response, "avatar"))
                        .or_else(|| extract_string_optional(&json_response, "avatar_url")),
                );
            }
        }

        // Store the full response in additional_data for access to all fields
        profile = profile.with_additional_data("raw_profile", json_response);
        Ok(profile)
    }
}

impl TokenToProfile for AuthToken {
    async fn to_profile(&self, _provider: &OAuthProvider) -> Result<UserProfile> {
        // Create a basic profile from the token data
        let mut profile = UserProfile::new();

        // Use the user ID as the profile ID
        profile = profile.with_id(self.user_id.clone());

        // Use the auth method as the provider if available
        profile = profile.with_provider(self.auth_method.clone());

        // Add custom metadata if available
        if let Some(name) = self.metadata.custom.get("name").and_then(|v| v.as_str()) {
            profile = profile.with_name(Some(name.to_string()));
        }

        if let Some(email) = self.metadata.custom.get("email").and_then(|v| v.as_str()) {
            profile = profile.with_email(Some(email.to_string()));
        }

        // We can add more information later if needed

        Ok(profile)
    }
}

/// Helper function to extract a required string from a JSON response
fn extract_string(json: &Value, field: &str) -> Result<String> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            AuthError::validation(format!("Field '{}' not found or not a string", field))
        })
}

/// Helper function to extract an optional string from a JSON response
fn extract_string_optional(json: &Value, field: &str) -> Option<String> {
    json.get(field).and_then(|v| v.as_str()).map(String::from)
}

/// Helper function to extract a required string from a JSON value
fn extract_string_from_value(json: &Value, field: &str) -> Result<String> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            AuthError::validation(format!("Field '{}' not found or not a string", field))
        })
}

/// Helper function to extract an optional string from a JSON value
fn extract_string_optional_from_value(json: &Value, field: &str) -> Option<String> {
    json.get(field).and_then(|v| v.as_str()).map(String::from)
}

// Include tests
// #[cfg(test)]
// mod tests;
