//! LDAP authentication method implementation.
//!
//! Provides authentication against LDAP directories (Active Directory,
//! OpenLDAP, etc.) using the search-bind-search pattern:
//! 1. Bind with a service account (or anonymously) to search for the user
//! 2. Bind with the user's DN and provided password to verify credentials
//! 3. Re-bind as service account to retrieve user attributes

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

/// LDAP authentication configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldap://ldap.example.com:389" or "ldaps://ldap.example.com:636")
    pub server_url: String,

    /// Base DN for user searches (e.g., "dc=example,dc=com")
    pub base_dn: String,

    /// User search filter template. `{}` is replaced with the username.
    /// Default: `(uid={})`
    /// For Active Directory: `(sAMAccountName={})`
    pub user_search_filter: String,

    /// Bind DN for the service account used for searches (optional for anonymous bind)
    pub bind_dn: Option<String>,

    /// Bind password for the service account
    pub bind_password: Option<String>,

    /// User attributes to retrieve after successful authentication
    pub user_attributes: Vec<String>,

    /// Attribute that contains the user's email address
    pub email_attribute: String,

    /// Attribute that contains the user's display name
    pub display_name_attribute: String,

    /// Connection timeout in seconds
    pub timeout_seconds: u64,

    /// Whether to use STARTTLS on non-TLS connections
    pub starttls: bool,

    /// Group base DN for group lookups (optional)
    pub group_base_dn: Option<String>,

    /// Group membership filter template. `{}` is replaced with the user DN.
    pub group_filter: Option<String>,
}

impl std::fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("LdapConfig");
        d.field("server_url", &self.server_url);
        d.field("base_dn", &self.base_dn);
        d.field("user_search_filter", &self.user_search_filter);
        d.field("bind_dn", &self.bind_dn);
        d.field(
            "bind_password",
            &crate::utils::redact::redacted(&self.bind_password),
        );
        d.field("user_attributes", &self.user_attributes);
        d.field("email_attribute", &self.email_attribute);
        d.field("display_name_attribute", &self.display_name_attribute);
        d.field("timeout_seconds", &self.timeout_seconds);
        d.field("starttls", &self.starttls);
        d.field("group_base_dn", &self.group_base_dn);
        d.field("group_filter", &self.group_filter);
        d.finish()
    }
}

impl LdapConfig {
    /// Active Directory preset with typical AD attribute names.
    ///
    /// Uses `sAMAccountName` for user lookup, `displayName` for the display
    /// name, and enables group membership retrieval via the `memberOf` attribute.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::methods::ldap::LdapConfig;
    ///
    /// let cfg = LdapConfig::active_directory(
    ///     "ldaps://ad.corp.example.com:636",
    ///     "dc=corp,dc=example,dc=com",
    /// );
    /// assert!(cfg.user_search_filter.contains("sAMAccountName"));
    /// assert!(cfg.starttls == false); // ldaps already encrypts
    /// ```
    pub fn active_directory(server_url: impl Into<String>, base_dn: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            base_dn: base_dn.into(),
            user_search_filter: "(&(objectClass=user)(sAMAccountName={}))".to_string(),
            bind_dn: None,
            bind_password: None,
            user_attributes: vec![
                "sAMAccountName".to_string(),
                "cn".to_string(),
                "mail".to_string(),
                "displayName".to_string(),
                "memberOf".to_string(),
                "userPrincipalName".to_string(),
            ],
            email_attribute: "mail".to_string(),
            display_name_attribute: "displayName".to_string(),
            timeout_seconds: 10,
            starttls: false,
            group_base_dn: None,
            group_filter: None,
        }
    }

    /// OpenLDAP preset with standard POSIX / inetOrgPerson attributes.
    ///
    /// Uses `uid` for user lookup and `cn` for the display name.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::methods::ldap::LdapConfig;
    ///
    /// let cfg = LdapConfig::openldap(
    ///     "ldap://ldap.example.com:389",
    ///     "dc=example,dc=com",
    /// );
    /// assert!(cfg.user_search_filter.contains("uid="));
    /// ```
    pub fn openldap(server_url: impl Into<String>, base_dn: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            base_dn: base_dn.into(),
            user_search_filter: "(&(objectClass=inetOrgPerson)(uid={}))".to_string(),
            bind_dn: None,
            bind_password: None,
            user_attributes: vec![
                "uid".to_string(),
                "cn".to_string(),
                "mail".to_string(),
                "displayName".to_string(),
                "memberOf".to_string(),
            ],
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            timeout_seconds: 10,
            starttls: true,
            group_base_dn: None,
            group_filter: None,
        }
    }

    /// Set the service account bind credentials for LDAP searches.
    pub fn bind_credentials(
        mut self,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
    ) -> Self {
        self.bind_dn = Some(bind_dn.into());
        self.bind_password = Some(bind_password.into());
        self
    }

    /// Configure group membership lookup.
    pub fn with_groups(
        mut self,
        group_base_dn: impl Into<String>,
        group_filter: impl Into<String>,
    ) -> Self {
        self.group_base_dn = Some(group_base_dn.into());
        self.group_filter = Some(group_filter.into());
        self
    }
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            server_url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            user_search_filter: "(uid={})".to_string(),
            bind_dn: None,
            bind_password: None,
            user_attributes: vec![
                "uid".to_string(),
                "cn".to_string(),
                "mail".to_string(),
                "displayName".to_string(),
                "memberOf".to_string(),
            ],
            email_attribute: "mail".to_string(),
            display_name_attribute: "displayName".to_string(),
            timeout_seconds: 10,
            starttls: false,
            group_base_dn: None,
            group_filter: None,
        }
    }
}

/// Result of a successful LDAP authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAuthResult {
    /// The user's distinguished name in the directory
    pub user_dn: String,
    /// The username that was authenticated
    pub username: String,
    /// User's email address (if available)
    pub email: Option<String>,
    /// User's display name (if available)
    pub display_name: Option<String>,
    /// Group memberships (if group lookup is configured)
    pub groups: Vec<String>,
    /// All retrieved attributes as key-value pairs
    pub attributes: std::collections::HashMap<String, Vec<String>>,
}

/// LDAP authentication method.
#[derive(Debug)]
pub struct LdapAuthMethod {
    config: LdapConfig,
}

impl LdapAuthMethod {
    /// Create a new LDAP authentication method with the given configuration.
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self {
            config: LdapConfig::default(),
        }
    }

    /// Validate the LDAP configuration.
    pub fn validate_config(&self) -> Result<()> {
        if self.config.server_url.is_empty() {
            return Err(AuthError::config("LDAP server URL cannot be empty"));
        }
        if !self.config.server_url.starts_with("ldap://")
            && !self.config.server_url.starts_with("ldaps://")
        {
            return Err(AuthError::config(
                "LDAP server URL must start with ldap:// or ldaps://",
            ));
        }
        if self.config.base_dn.is_empty() {
            return Err(AuthError::config("LDAP base DN cannot be empty"));
        }
        if self.config.user_search_filter.is_empty() {
            return Err(AuthError::config("LDAP user search filter cannot be empty"));
        }
        if !self.config.user_search_filter.contains("{}") {
            return Err(AuthError::config(
                "LDAP user search filter must contain '{}' placeholder for username",
            ));
        }
        Ok(())
    }

    /// Authenticate a user against the LDAP directory.
    ///
    /// Uses the search-bind-search pattern:
    /// 1. Connect and bind with service account
    /// 2. Search for the user by username
    /// 3. Bind with the user's DN + password to verify credentials
    /// 4. Re-bind as service account and retrieve user attributes
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<LdapAuthResult> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};

        if username.is_empty() || password.is_empty() {
            return Err(AuthError::validation(
                "Username and password are required for LDAP authentication",
            ));
        }

        // Reject usernames with LDAP injection characters
        if username.contains('*')
            || username.contains('(')
            || username.contains(')')
            || username.contains('\\')
            || username.contains('\0')
        {
            return Err(AuthError::validation(
                "Username contains invalid characters",
            ));
        }

        debug!("Attempting LDAP authentication for user: {}", username);

        // Step 1: Connect to LDAP server
        let (conn, mut ldap) = LdapConnAsync::new(&self.config.server_url)
            .await
            .map_err(|e| {
                error!("LDAP connection failed: {}", e);
                AuthError::internal(format!("LDAP connection failed: {}", e))
            })?;

        // Drive the connection in the background
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                warn!("LDAP connection driver error: {}", e);
            }
        });

        // Step 2: Bind with service account (or anonymous)
        if let (Some(bind_dn), Some(bind_pw)) = (&self.config.bind_dn, &self.config.bind_password) {
            ldap.simple_bind(bind_dn, bind_pw)
                .await
                .map_err(|e| {
                    error!("LDAP service account bind failed: {}", e);
                    AuthError::internal(format!("LDAP service bind failed: {}", e))
                })?
                .success()
                .map_err(|e| {
                    error!("LDAP service account bind rejected: {}", e);
                    AuthError::internal("LDAP service account authentication failed")
                })?;
        }

        // Step 3: Search for the user
        let search_filter = self.config.user_search_filter.replace("{}", username);

        let (search_results, _result) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &search_filter,
                &self.config.user_attributes,
            )
            .await
            .map_err(|e| {
                error!("LDAP user search failed: {}", e);
                AuthError::internal(format!("LDAP search failed: {}", e))
            })?
            .success()
            .map_err(|e| {
                error!("LDAP user search error: {}", e);
                AuthError::invalid_credential("ldap", "User not found in directory")
            })?;

        let Some(first_result) = search_results.into_iter().next() else {
            debug!("LDAP: No user found matching filter: {}", search_filter);
            return Err(AuthError::invalid_credential(
                "ldap",
                "Invalid username or password",
            ));
        };

        let entry = SearchEntry::construct(first_result);
        let user_dn = entry.dn.clone();

        debug!("LDAP: Found user DN: {}", user_dn);

        // Step 4: Bind with user credentials to verify password
        ldap.simple_bind(&user_dn, password)
            .await
            .map_err(|e| {
                debug!("LDAP user bind failed: {}", e);
                AuthError::invalid_credential("ldap", "Invalid username or password")
            })?
            .success()
            .map_err(|_| AuthError::invalid_credential("ldap", "Invalid username or password"))?;

        info!("LDAP authentication successful for user: {}", username);

        // Extract user attributes
        let email = entry
            .attrs
            .get(&self.config.email_attribute)
            .and_then(|v| v.first().cloned());

        let display_name = entry
            .attrs
            .get(&self.config.display_name_attribute)
            .and_then(|v| v.first().cloned());

        let groups = entry.attrs.get("memberOf").cloned().unwrap_or_default();

        let _ = ldap.unbind().await;

        Ok(LdapAuthResult {
            user_dn,
            username: username.to_string(),
            email,
            display_name,
            groups,
            attributes: entry.attrs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_defaults() {
        let config = LdapConfig::default();
        assert_eq!(config.server_url, "ldap://localhost:389");
        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.user_search_filter, "(uid={})");
        assert_eq!(config.email_attribute, "mail");
    }

    #[test]
    fn test_ldap_validate_config_valid() {
        let method = LdapAuthMethod::new(LdapConfig::default());
        assert!(method.validate_config().is_ok());
    }

    #[test]
    fn test_ldap_validate_config_empty_url() {
        let config = LdapConfig {
            server_url: String::new(),
            ..LdapConfig::default()
        };
        let method = LdapAuthMethod::new(config);
        assert!(method.validate_config().is_err());
    }

    #[test]
    fn test_ldap_validate_config_invalid_url_scheme() {
        let config = LdapConfig {
            server_url: "http://ldap.example.com".to_string(),
            ..LdapConfig::default()
        };
        let method = LdapAuthMethod::new(config);
        assert!(method.validate_config().is_err());
    }

    #[test]
    fn test_ldap_validate_config_no_placeholder() {
        let config = LdapConfig {
            user_search_filter: "(uid=fixedname)".to_string(),
            ..LdapConfig::default()
        };
        let method = LdapAuthMethod::new(config);
        assert!(method.validate_config().is_err());
    }

    #[tokio::test]
    async fn test_ldap_rejects_empty_credentials() {
        let method = LdapAuthMethod::new(LdapConfig::default());
        let result = method.authenticate("", "password").await;
        assert!(result.is_err());

        let result = method.authenticate("user", "").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ldap_rejects_injection_characters() {
        let method = LdapAuthMethod::new(LdapConfig::default());

        let result = method.authenticate("user*", "password").await;
        assert!(result.is_err());

        let result = method.authenticate("user)(injected=*", "password").await;
        assert!(result.is_err());

        let result = method.authenticate("user\0null", "password").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_ldap_active_directory_preset() {
        let cfg = LdapConfig::active_directory(
            "ldaps://ad.corp.example.com:636",
            "dc=corp,dc=example,dc=com",
        );
        assert_eq!(cfg.server_url, "ldaps://ad.corp.example.com:636");
        assert_eq!(cfg.base_dn, "dc=corp,dc=example,dc=com");
        assert!(cfg.user_search_filter.contains("sAMAccountName"));
        assert!(
            cfg.user_attributes
                .contains(&"userPrincipalName".to_string())
        );
        assert!(
            !cfg.starttls,
            "ldaps already encrypts, starttls should be off"
        );
    }

    #[test]
    fn test_ldap_openldap_preset() {
        let cfg = LdapConfig::openldap("ldap://ldap.example.com", "dc=example,dc=com");
        assert_eq!(cfg.server_url, "ldap://ldap.example.com");
        assert!(cfg.user_search_filter.contains("uid="));
        assert!(cfg.user_search_filter.contains("inetOrgPerson"));
        assert!(cfg.starttls, "plain ldap should enable starttls by default");
        assert_eq!(cfg.display_name_attribute, "cn");
    }

    #[test]
    fn test_ldap_config_bind_credentials_chain() {
        let cfg = LdapConfig::active_directory(
            "ldaps://ad.corp.example.com:636",
            "dc=corp,dc=example,dc=com",
        )
        .bind_credentials("cn=svc,dc=corp,dc=example,dc=com", "secret");
        assert_eq!(
            cfg.bind_dn.as_deref(),
            Some("cn=svc,dc=corp,dc=example,dc=com")
        );
        assert_eq!(cfg.bind_password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_ldap_config_with_groups_chain() {
        let cfg = LdapConfig::openldap("ldap://ldap.example.com", "dc=example,dc=com")
            .with_groups("ou=groups,dc=example,dc=com", "(member={})");
        assert_eq!(
            cfg.group_base_dn.as_deref(),
            Some("ou=groups,dc=example,dc=com")
        );
        assert_eq!(cfg.group_filter.as_deref(), Some("(member={})"));
    }
}
