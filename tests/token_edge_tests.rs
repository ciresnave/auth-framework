// Comprehensive tests for AuthToken edge cases
use auth_framework::tokens::AuthToken;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_expiry() {
        let token = AuthToken::new("user1", "token1", Duration::from_secs(1), "jwt");
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(token.is_expired());
    }

    #[test]
    fn test_token_revocation() {
        let mut token = AuthToken::new("user1", "token1", Duration::from_secs(3600), "jwt");
        token.metadata.revoked = true;
        assert!(token.is_revoked());
    }

    #[test]
    fn test_token_type_and_subject() {
        let token = AuthToken::new("user1", "token1", Duration::from_secs(3600), "jwt");
        assert_eq!(token.token_type(), Some("Bearer"));
        assert!(token.subject().is_none());
    }
}
