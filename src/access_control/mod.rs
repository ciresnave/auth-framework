// SPDX-License-Identifier: MIT OR Apache-2.0
//! Access-control engine: deny-wins decisions over principal, action and object.
//!
//! A consumer registers its actions in an [`ActionRegistry`], issues [`Grant`]s,
//! and asks an [`Authorizer`] to [`decide`](Authorizer::decide). The default is
//! deny; a matching deny grant beats any allow grant; an unregistered action is
//! denied. Actions are separate: holding one implies nothing about another.

use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Whether a grant allows or denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// The grant permits the action.
    Allow,
    /// The grant forbids the action and beats any allow.
    Deny,
}

/// How fresh a decision must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// A result at most 60 s old is acceptable.
    Cached,
    /// Checked live from the source.
    Live,
}

/// The outcome of a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted, by the named grant.
    Allow {
        /// Id of the grant that allowed it.
        grant_ref: String,
    },
    /// Refused.
    Deny {
        /// Why.
        reason: DenyReason,
    },
}

/// Why a decision was a deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// The action was never registered.
    UnregisteredAction,
    /// A deny grant matched.
    ExplicitDeny {
        /// Id of the deny grant.
        grant_ref: String,
    },
    /// Nothing allowed it (default deny).
    NoMatchingGrant,
}

impl Decision {
    /// True for [`Decision::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

/// A rule: `principal` may (or may not) do `action` to `object`.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Unique id, used in decisions and for removal.
    pub id: String,
    /// Exact principal id, or `*` for everyone.
    pub principal: String,
    /// Exact action name, or `*`.
    pub action: String,
    /// Object pattern; see [`object_matches`].
    pub object: String,
    /// Allow or deny.
    pub effect: Effect,
    /// The grant stops applying at this instant.
    pub expires: Option<DateTime<Utc>>,
    /// Marked sensitive by its issuer: consumers check it live.
    pub sensitive: bool,
}

impl Grant {
    /// A non-expiring, non-sensitive grant.
    pub fn new(
        id: impl Into<String>,
        principal: impl Into<String>,
        action: impl Into<String>,
        object: impl Into<String>,
        effect: Effect,
    ) -> Self {
        Self {
            id: id.into(),
            principal: principal.into(),
            action: action.into(),
            object: object.into(),
            effect,
            expires: None,
            sensitive: false,
        }
    }

    fn applies(&self, principal: &str, action: &str, object: &str, now: DateTime<Utc>) -> bool {
        self.expires.is_none_or(|e| now < e)
            && (self.principal == "*" || self.principal == principal)
            && (self.action == "*" || self.action == action)
            && object_matches(&self.object, object)
    }
}

/// Match `pattern` against `object`. `*` spans any characters except `@`, so
/// `agent:*@acct` cannot reach into another account; a pattern of just `*`
/// matches everything.
pub fn object_matches(pattern: &str, object: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    fn go(p: &[u8], o: &[u8]) -> bool {
        match p.split_first() {
            None => o.is_empty(),
            Some((b'*', rest)) => {
                let mut i = 0;
                loop {
                    if go(rest, &o[i..]) {
                        return true;
                    }
                    if i < o.len() && o[i] != b'@' {
                        i += 1;
                    } else {
                        return false;
                    }
                }
            }
            Some((c, rest)) => o.first() == Some(c) && go(rest, &o[1..]),
        }
    }
    go(pattern.as_bytes(), object.as_bytes())
}

/// Actions a consumer has registered, with their sensitivity default.
#[derive(Debug, Default, Clone)]
pub struct ActionRegistry {
    actions: HashMap<String, bool>,
}

impl ActionRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an action. Re-registering may raise sensitivity, never lower it.
    pub fn register(&mut self, action: impl Into<String>, sensitive: bool) {
        *self.actions.entry(action.into()).or_insert(false) |= sensitive;
    }

    /// Whether the action is known.
    pub fn is_registered(&self, action: &str) -> bool {
        self.actions.contains_key(action)
    }

    /// Whether the action is sensitive by default (false if unknown).
    pub fn is_sensitive(&self, action: &str) -> bool {
        self.actions.get(action).copied().unwrap_or(false)
    }
}

/// What a consumer calls to ask whether something is allowed.
pub trait Authorizer {
    /// Decide whether `principal` may do `action` to `object`.
    fn decide(&self, principal: &str, action: &str, object: &str, freshness: Freshness)
    -> Decision;
}

/// In-memory engine: a registry plus a list of grants.
#[derive(Debug, Default, Clone)]
pub struct InMemoryEngine {
    /// The registered actions.
    pub registry: ActionRegistry,
    grants: Vec<Grant>,
}

impl InMemoryEngine {
    /// An engine with no grants (deny all).
    pub fn new(registry: ActionRegistry) -> Self {
        Self {
            registry,
            grants: Vec::new(),
        }
    }

    /// Add a grant.
    pub fn add_grant(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Remove every grant with this id.
    pub fn remove_grant(&mut self, id: &str) {
        self.grants.retain(|g| g.id != id);
    }

    /// Decide at a given instant (deterministic for tests).
    pub fn decide_at(
        &self,
        principal: &str,
        action: &str,
        object: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        if !self.registry.is_registered(action) {
            return Decision::Deny {
                reason: DenyReason::UnregisteredAction,
            };
        }
        let mut allow: Option<&Grant> = None;
        for g in self
            .grants
            .iter()
            .filter(|g| g.applies(principal, action, object, now))
        {
            match g.effect {
                Effect::Deny => {
                    return Decision::Deny {
                        reason: DenyReason::ExplicitDeny {
                            grant_ref: g.id.clone(),
                        },
                    };
                }
                Effect::Allow => allow = allow.or(Some(g)),
            }
        }
        match allow {
            Some(g) => Decision::Allow {
                grant_ref: g.id.clone(),
            },
            None => Decision::Deny {
                reason: DenyReason::NoMatchingGrant,
            },
        }
    }
}

impl Authorizer for InMemoryEngine {
    fn decide(&self, principal: &str, action: &str, object: &str, _f: Freshness) -> Decision {
        self.decide_at(principal, action, object, Utc::now())
    }
}
