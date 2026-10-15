//! User context and authentication state management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Represents authenticated user context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub scopes: crate::types::Scopes,
    pub authenticated_at: std::time::SystemTime,
    pub session_id: String,
    pub attributes: crate::types::UserAttributesString,
}

impl UserContext {
    pub fn new(user_id: String, username: String, email: Option<String>) -> Self {
        Self {
            user_id,
            username,
            email,
            scopes: crate::types::Scopes::empty(),
            authenticated_at: std::time::SystemTime::now(),
            session_id: Uuid::new_v4().to_string(),
            attributes: crate::types::UserAttributesString::empty(),
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into();
        self
    }

    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

/// Session store for managing user authentication state
impl UserContext {
    /// Create a new builder for UserContext
    pub fn builder(user_id: impl Into<String>, username: impl Into<String>) -> UserContextBuilder {
        UserContextBuilder::new(user_id.into(), username.into())
    }
}

/// A builder for UserContext
pub struct UserContextBuilder {
    user_id: String,
    username: String,
    email: Option<String>,
    scopes: Vec<String>,
    attributes: HashMap<String, String>,
}

impl UserContextBuilder {
    pub fn new(user_id: String, username: String) -> Self {
        Self {
            user_id,
            username,
            email: None,
            scopes: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> UserContext {
        let mut ctx = UserContext::new(self.user_id, self.username, self.email);
        ctx.scopes = self.scopes.into();
        ctx.attributes = self.attributes.into();
        ctx
    }
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: std::collections::HashMap<String, UserContext>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn create_session(&mut self, user_context: UserContext) -> String {
        let session_id = user_context.session_id.clone();
        self.sessions.insert(session_id.clone(), user_context);
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<&UserContext> {
        self.sessions.get(session_id)
    }

    pub fn invalidate_session(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    pub fn validate_session(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
