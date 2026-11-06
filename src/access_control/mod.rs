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
    /// The grant this one was delegated from; it dies with its source.
    pub parent: Option<String>,
    /// 0 for a root grant, parent's depth + 1 for a delegation.
    pub depth: u8,
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
            parent: None,
            depth: 0,
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

/// Default longest delegation chain below a root grant.
pub const DEFAULT_MAX_DELEGATION_DEPTH: u8 = 3;

/// Why a delegation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// The source grant does not exist.
    UnknownGrant,
    /// A grant with the new id already exists.
    DuplicateId,
    /// The delegator is not the holder of the source grant.
    NotHolder,
    /// Only allow grants can be delegated.
    NotAnAllowGrant,
    /// The source grant (or something above it) has expired or been revoked.
    SourceInactive,
    /// The action is not within the source grant's action.
    ActionWidens,
    /// The object is not within the source grant's object.
    ObjectWidens,
    /// The delegation would outlive its source.
    ExpiryWidens,
    /// The chain would be longer than the engine allows.
    TooDeep {
        /// The configured limit.
        max: u8,
    },
}

/// A request to share (a subset of) a grant with another principal.
#[derive(Debug, Clone)]
pub struct DelegationRequest {
    /// Id for the new grant.
    pub id: String,
    /// Id of the grant being shared from.
    pub from: String,
    /// Who is sharing; must hold `from`.
    pub delegator: String,
    /// Who receives the new grant.
    pub delegatee: String,
    /// Action; must be within the source's.
    pub action: String,
    /// Object pattern; must be within the source's.
    pub object: String,
    /// Expiry; must not be later than the source's, and is required if the
    /// source expires.
    pub expires: Option<DateTime<Utc>>,
    /// Mark the new grant sensitive (it inherits the source's mark regardless).
    pub sensitive: bool,
}

/// True when every object matched by `child` is matched by `parent`.
///
/// The child pattern is matched as a literal string against the parent: a `*`
/// in the child can only be covered by a `*` in the parent (which spans any
/// non-`@` text), so this errs towards refusing, never towards widening.
pub fn object_within(parent: &str, child: &str) -> bool {
    parent == "*" || parent == child || object_matches(parent, child)
}

/// In-memory engine: a registry plus a list of grants.
#[derive(Debug, Clone)]
pub struct InMemoryEngine {
    /// The registered actions.
    pub registry: ActionRegistry,
    grants: Vec<Grant>,
    max_depth: u8,
    account_holder: Option<String>,
}

impl Default for InMemoryEngine {
    fn default() -> Self {
        Self::new(ActionRegistry::default())
    }
}

impl InMemoryEngine {
    /// An engine with no grants (deny all).
    pub fn new(registry: ActionRegistry) -> Self {
        Self {
            registry,
            grants: Vec::new(),
            max_depth: DEFAULT_MAX_DELEGATION_DEPTH,
            account_holder: None,
        }
    }

    /// Set the longest delegation chain (default 3).
    pub fn with_max_delegation_depth(mut self, max: u8) -> Self {
        self.max_depth = max;
        self
    }

    /// Name the account holder: allowed every registered action on every
    /// object, and not blockable by any deny grant.
    pub fn with_account_holder(mut self, principal: impl Into<String>) -> Self {
        self.account_holder = Some(principal.into());
        self
    }

    /// Add a root grant.
    pub fn add_grant(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Remove the grant with this id and, transitively, everything delegated
    /// from it.
    pub fn remove_grant(&mut self, id: &str) {
        let mut dead: Vec<String> = vec![id.to_string()];
        let mut i = 0;
        while i < dead.len() {
            let cur = dead[i].clone();
            for g in &self.grants {
                if g.parent.as_deref() == Some(cur.as_str()) && !dead.contains(&g.id) {
                    dead.push(g.id.clone());
                }
            }
            i += 1;
        }
        self.grants.retain(|g| !dead.contains(&g.id));
    }

    /// Look a grant up by id.
    pub fn grant(&self, id: &str) -> Option<&Grant> {
        self.find(id)
    }

    fn find(&self, id: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| g.id == id)
    }

    /// A grant is alive if it and every ancestor exists and is unexpired.
    fn chain_alive(&self, g: &Grant, now: DateTime<Utc>) -> bool {
        let mut cur = g;
        for _ in 0..=self.grants.len() {
            if cur.expires.is_some_and(|e| now >= e) {
                return false;
            }
            match &cur.parent {
                None => return true,
                Some(p) => match self.find(p) {
                    Some(next) => cur = next,
                    None => return false,
                },
            }
        }
        false
    }

    /// Share a subset of a grant the delegator holds. Checked at issue (here)
    /// and at every use (`decide_at` requires the whole chain to be alive).
    pub fn delegate(&mut self, req: DelegationRequest) -> Result<(), DelegationError> {
        self.delegate_at(req, Utc::now())
    }

    /// [`delegate`](Self::delegate) at a given instant.
    pub fn delegate_at(
        &mut self,
        req: DelegationRequest,
        now: DateTime<Utc>,
    ) -> Result<(), DelegationError> {
        if self.find(&req.id).is_some() {
            return Err(DelegationError::DuplicateId);
        }
        let src = self
            .find(&req.from)
            .cloned()
            .ok_or(DelegationError::UnknownGrant)?;
        if src.effect != Effect::Allow {
            return Err(DelegationError::NotAnAllowGrant);
        }
        if src.principal != req.delegator {
            return Err(DelegationError::NotHolder);
        }
        if !self.chain_alive(&src, now) {
            return Err(DelegationError::SourceInactive);
        }
        if src.action != "*" && src.action != req.action {
            return Err(DelegationError::ActionWidens);
        }
        if req.action != "*" && !self.registry.is_registered(&req.action) {
            return Err(DelegationError::ActionWidens);
        }
        if !object_within(&src.object, &req.object) {
            return Err(DelegationError::ObjectWidens);
        }
        match (src.expires, req.expires) {
            (Some(_), None) => return Err(DelegationError::ExpiryWidens),
            (Some(s), Some(c)) if c > s => return Err(DelegationError::ExpiryWidens),
            _ => {}
        }
        let depth = src.depth.saturating_add(1);
        if depth > self.max_depth {
            return Err(DelegationError::TooDeep {
                max: self.max_depth,
            });
        }
        let g = Grant {
            id: req.id,
            principal: req.delegatee,
            action: req.action,
            object: req.object,
            effect: Effect::Allow,
            expires: req.expires,
            sensitive: src.sensitive || req.sensitive,
            parent: Some(req.from),
            depth,
        };
        self.grants.push(g);
        Ok(())
    }

    /// A principal (agent or room) has just been created by `creator`. The
    /// creator is issued ordinary root grants for just the listed actions on
    /// `object`; nobody else gets anything, so until a rule says otherwise the
    /// new object is visible to the creator and the account holder only. The
    /// creator can later hide it further with deny grants; the account holder
    /// cannot be hidden from. Returns the new grant ids.
    pub fn register_new_principal(
        &mut self,
        creator: &str,
        object: &str,
        actions: &[&str],
    ) -> Result<Vec<String>, DelegationError> {
        if actions.iter().any(|a| !self.registry.is_registered(a)) {
            return Err(DelegationError::ActionWidens);
        }
        let mut ids = Vec::new();
        for a in actions {
            let id = format!("creator:{object}:{a}");
            if self.find(&id).is_some() {
                return Err(DelegationError::DuplicateId);
            }
            ids.push(id.clone());
            self.grants
                .push(Grant::new(id, creator, *a, object, Effect::Allow));
        }
        Ok(ids)
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
        if self.account_holder.as_deref() == Some(principal) {
            return Decision::Allow {
                grant_ref: "account-holder".into(),
            };
        }
        let mut allow: Option<&Grant> = None;
        for g in self
            .grants
            .iter()
            .filter(|g| g.applies(principal, action, object, now) && self.chain_alive(g, now))
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
