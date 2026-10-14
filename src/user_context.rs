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
    pub scopes: Vec<String>,
    pub authenticated_at: std::time::SystemTime,
    pub session_id: String,
    pub attributes: HashMap<String, String>,
}

impl UserContext {
    pub fn new(user_id: String, username: String, email: Option<String>) -> Self {
        Self {
            user_id,
            username,
            email,
            scopes: Vec::new(),
            authenticated_at: std::time::SystemTime::now(),
            session_id: Uuid::new_v4().to_string(),
            attributes: HashMap::new(),
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string())
    }
}

/// Session store for managing user authentication state
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
