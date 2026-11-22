// SPDX-License-Identifier: MIT OR Apache-2.0
//! Breached password detection using the Have I Been Pwned (HIBP) k-anonymity API.
//!
//! This module checks passwords against known data breaches without sending the
//! full password or its hash over the network. Only the first 5 characters of the
//! SHA-1 hash are transmitted, preserving password privacy through k-anonymity.

use crate::errors::{AuthError, Result};
use sha1::{Digest, Sha1};

/// Check if a password has appeared in known data breaches using the HIBP
/// k-anonymity range API.
///
/// Returns `Ok(true)` if the password has been seen in at least one breach,
/// `Ok(false)` if it has not, or an error if the HIBP API is unreachable.
///
/// The check transmits only the first 5 hex characters of the SHA-1 hash,
/// so the full password is never exposed to the remote service.
pub async fn is_password_breached(password: &str) -> Result<bool> {
    let hash = hex::encode(Sha1::digest(password.as_bytes())).to_uppercase();
    let (prefix, suffix) = hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| AuthError::internal(format!("HTTP client error: {e}")))?
        .get(&url)
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("HIBP API request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(AuthError::internal(format!(
            "HIBP API returned status {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to read HIBP response: {e}")))?;

    // Each line is "HASH_SUFFIX:COUNT". Check if our suffix appears.
    let breached = body.lines().any(|line| line.trim().starts_with(suffix));

    Ok(breached)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_prefix_suffix_split() {
        // "password" SHA-1 = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let hash = hex::encode(Sha1::digest(b"password")).to_uppercase();
        assert_eq!(&hash[..5], "5BAA6");
        assert_eq!(hash.len(), 40);
    }
}
