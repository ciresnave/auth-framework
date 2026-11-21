// SPDX-License-Identifier: MIT OR Apache-2.0
//! String utility functions for the AuthFramework.

use rand::{RngExt, rng};

/// Generate a random ID with optional prefix
pub fn generate_id(prefix: Option<&str>) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789";
    let random_part: String = (0..16)
        .map(|_| {
            let idx = rng().random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    match prefix {
        Some(p) => format!("{}_{}", p, random_part),
        None => random_part,
    }
}
/// Generate a UUID-like string
pub fn generate_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Sanitize a string for safe use in IDs or filenames
pub fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id = generate_id(None);
        assert_eq!(id.len(), 16);

        let prefixed_id = generate_id(Some("test"));
        assert!(prefixed_id.starts_with("test_"));
        assert_eq!(prefixed_id.len(), 21); // "test_" + 16 chars
    }

    #[test]
    fn test_generate_uuid() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36); // Standard UUID length
        assert!(uuid.contains('-'));
    }

    #[test]
    fn test_sanitize_string() {
        let input = "hello@world!#$%";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "helloworld");
    }
}
