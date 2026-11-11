// SPDX-License-Identifier: MIT OR Apache-2.0
//! Access-control engine: deny-wins decisions over principal, action and object.
//!
//! A consumer registers its actions in an [`ActionRegistry`], issues [`Grant`]s,
//! and asks an [`Authorizer`] to [`decide`](Authorizer::decide). The default is
//! deny; a matching deny grant beats any allow grant; an unregistered action is
//! denied. Actions are separate: holding one implies nothing about another.

pub mod gnap;
pub mod principal;
pub mod rules;

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

pub use principal::{Lifecycle, Principal, PrincipalError, PrincipalKind, PrincipalRegistry};
pub use rules::{AuditEntry, AuditOp, RuleError};

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
    /// The source of truth could not be reached; unreachability never widens access.
    SourceUnreachable,
    /// A principal registry is attached and the principal is unknown, suspended or retired
    /// (or one of its owners is).
    PrincipalInactive,
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
    /// Who added or shared it (none for a grant added directly with `add_grant`).
    pub issuer: Option<String>,
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
            issuer: None,
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
    // Dynamic programming over (pattern, object) prefixes: O(len(p) * len(o)),
    // so an adversarial pattern cannot blow up. `*` spans anything but `@`.
    let (p, o) = (pattern.as_bytes(), object.as_bytes());
    // row[j]: does p[..i] match o[..j]?
    let mut row = vec![false; o.len() + 1];
    row[0] = true;
    for &pc in p {
        let mut next = vec![false; o.len() + 1];
        if pc == b'*' {
            next[0] = row[0];
            for j in 1..=o.len() {
                // star consumes o[j-1] (not `@`) or has already matched o[..j]
                next[j] = row[j] || (next[j - 1] && o[j - 1] != b'@');
            }
        } else {
            for j in 1..=o.len() {
                next[j] = row[j - 1] && o[j - 1] == pc;
            }
        }
        row = next;
    }
    row[o.len()]
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
    /// A grant added directly must be a root grant: no parent, depth 0.
    NotRootGrant,
    /// The action was never registered.
    UnregisteredAction,
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
    registry: ActionRegistry,
    generation: u64,
    grants: Vec<Grant>,
    max_depth: u8,
    account_holder: Option<String>,
    sensitive_objects: Vec<String>,
    principals: Option<PrincipalRegistry>,
    edit_action: Option<String>,
    audit: Vec<AuditEntry>,
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
            generation: 0,
            grants: Vec::new(),
            max_depth: DEFAULT_MAX_DELEGATION_DEPTH,
            account_holder: None,
            sensitive_objects: Vec::new(),
            principals: None,
            edit_action: None,
            audit: Vec::new(),
        }
    }

    /// The registered actions.
    pub fn registry(&self) -> &ActionRegistry {
        &self.registry
    }

    /// The registered actions, for registering more. Counts as a change.
    pub fn registry_mut(&mut self) -> &mut ActionRegistry {
        self.generation += 1;
        &mut self.registry
    }

    /// A number that changes whenever anything that can change an answer
    /// changes (grants, delegations, sensitivity marks, actions, principals).
    pub fn generation(&self) -> u64 {
        self.generation
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

    /// Attach a principal registry: from then on only effectively active
    /// principals can be allowed anything. Without one, any id is accepted.
    pub fn with_principals(mut self, registry: PrincipalRegistry) -> Self {
        self.principals = Some(registry);
        self.generation += 1;
        self
    }

    /// The attached registry, if any.
    pub fn principals(&self) -> Option<&PrincipalRegistry> {
        self.principals.as_ref()
    }

    /// The attached registry, for creating principals and changing lifecycle.
    pub fn principals_mut(&mut self) -> Option<&mut PrincipalRegistry> {
        self.generation += 1;
        self.principals.as_mut()
    }

    /// Add a root grant. Refused if the id is already taken (a second grant with
    /// the same id would be enforced by `decide` but invisible to lookup and
    /// removal) or if the grant claims a parent or a depth (a forged chain
    /// position could outrun the delegation limit).
    pub fn add_grant(&mut self, grant: Grant) -> Result<(), DelegationError> {
        if grant.parent.is_some() || grant.depth != 0 {
            return Err(DelegationError::NotRootGrant);
        }
        if self.find(&grant.id).is_some() {
            return Err(DelegationError::DuplicateId);
        }
        self.generation += 1;
        self.grants.push(grant);
        Ok(())
    }

    /// Remove the grant with this id and, transitively, everything delegated
    /// from it.
    pub fn remove_grant(&mut self, id: &str) {
        self.generation += 1;
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

    /// [`delegate`](Self::delegate) at a given instant. A refusal is recorded
    /// in the audit trail (actor: the delegator; rule: the id that was asked
    /// for; chain: the source grant's chain, if it exists).
    pub fn delegate_at(
        &mut self,
        req: DelegationRequest,
        now: DateTime<Utc>,
    ) -> Result<(), DelegationError> {
        let (delegator, id, from) = (req.delegator.clone(), req.id.clone(), req.from.clone());
        let r = self.try_delegate_at(req, now);
        if r.is_err() {
            let chain = if self.find(&from).is_some() {
                self.chain_of(&from)
            } else {
                Vec::new()
            };
            self.record(now, &delegator, AuditOp::Refused, &id, chain);
        }
        r
    }

    fn try_delegate_at(
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
        let delegator = req.delegator.clone();
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
            issuer: Some(delegator.clone()),
        };
        self.generation += 1;
        let id = g.id.clone();
        self.grants.push(g);
        let chain = self.chain_of(&id);
        self.record(now, &delegator, AuditOp::Delegated, &id, chain);
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
            return Err(DelegationError::UnregisteredAction);
        }
        // All or nothing: check every id before pushing any grant.
        let ids: Vec<String> = actions
            .iter()
            .map(|a| format!("creator:{object}:{a}"))
            .collect();
        for (i, id) in ids.iter().enumerate() {
            if self.find(id).is_some() || ids[..i].contains(id) {
                return Err(DelegationError::DuplicateId);
            }
        }
        self.generation += 1;
        for (id, a) in ids.iter().zip(actions) {
            let mut g = Grant::new(id.clone(), creator, *a, object, Effect::Allow);
            g.issuer = Some(creator.to_string());
            self.grants.push(g);
        }
        Ok(ids)
    }

    /// Mark every object matching `pattern` sensitive: decisions about it are
    /// always checked live.
    pub fn mark_object_sensitive(&mut self, pattern: impl Into<String>) {
        self.generation += 1;
        self.sensitive_objects.push(pattern.into());
    }

    /// Decide at a given instant (deterministic for tests).
    pub fn decide_at(
        &self,
        principal: &str,
        action: &str,
        object: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        self.answer_at(principal, action, object, now).decision
    }

    /// Decide and also say whether the answer is sensitive (action registered
    /// sensitive, object on the sensitive list, or any grant that applied is
    /// marked sensitive).
    pub fn answer_at(
        &self,
        principal: &str,
        action: &str,
        object: &str,
        now: DateTime<Utc>,
    ) -> Answer {
        if !self.registry.is_registered(action) {
            return Answer {
                decision: Decision::Deny {
                    reason: DenyReason::UnregisteredAction,
                },
                sensitive: false,
            };
        }
        if let Some(reg) = &self.principals
            && !reg.is_active(principal)
        {
            // Identity state changes are security events: never cached.
            return Answer {
                decision: Decision::Deny {
                    reason: DenyReason::PrincipalInactive,
                },
                sensitive: true,
            };
        }
        let mut sensitive = self.registry.is_sensitive(action)
            || self
                .sensitive_objects
                .iter()
                .any(|p| object_matches(p, object));
        if self.account_holder.as_deref() == Some(principal) {
            return Answer {
                decision: Decision::Allow {
                    grant_ref: "account-holder".into(),
                },
                sensitive,
            };
        }
        let mut allow: Option<&Grant> = None;
        let mut deny: Option<&Grant> = None;
        for g in self
            .grants
            .iter()
            .filter(|g| g.applies(principal, action, object, now) && self.chain_alive(g, now))
        {
            sensitive |= g.sensitive;
            match g.effect {
                Effect::Deny => deny = deny.or(Some(g)),
                Effect::Allow => allow = allow.or(Some(g)),
            }
        }
        let decision = match (deny, allow) {
            (Some(g), _) => Decision::Deny {
                reason: DenyReason::ExplicitDeny {
                    grant_ref: g.id.clone(),
                },
            },
            (None, Some(g)) => Decision::Allow {
                grant_ref: g.id.clone(),
            },
            (None, None) => Decision::Deny {
                reason: DenyReason::NoMatchingGrant,
            },
        };
        Answer {
            decision,
            sensitive,
        }
    }
}

impl Authorizer for InMemoryEngine {
    fn decide(&self, principal: &str, action: &str, object: &str, _f: Freshness) -> Decision {
        self.decide_at(principal, action, object, Utc::now())
    }
}

/// A decision plus whether it must be checked live every time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The decision.
    pub decision: Decision,
    /// Sensitive answers are never cached.
    pub sensitive: bool,
}

/// The source could not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceUnavailable;

/// The source of truth a [`CachedAuthorizer`] fronts. It may be remote, so a
/// query can fail.
pub trait Source {
    /// Ask the source, at `now`.
    fn query(
        &self,
        principal: &str,
        action: &str,
        object: &str,
        now: DateTime<Utc>,
    ) -> Result<Answer, SourceUnavailable>;

    /// A number that changes whenever anything that can change an answer
    /// changes. The cache reuses an entry only while this is unchanged, so a
    /// change (a new sensitive deny, a revocation) is seen at once instead of
    /// after the 60 s ttl. The default returns a fresh number on every call,
    /// which never matches a cached entry: a source that cannot tell is never
    /// served from cache. Override it only if you can honour the contract.
    fn generation(&self) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1 << 63);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }
}

impl Source for InMemoryEngine {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn query(
        &self,
        principal: &str,
        action: &str,
        object: &str,
        now: DateTime<Utc>,
    ) -> Result<Answer, SourceUnavailable> {
        Ok(self.answer_at(principal, action, object, now))
    }
}

/// The longest a cached decision may be reused.
pub const MAX_CACHE_TTL: Duration = Duration::seconds(60);

type CacheKey = (String, String, String);

/// A cached decision, when it was stored, and the source generation it was read at.
type CacheEntry = (Decision, DateTime<Utc>, u64);

/// Caches decisions from a [`Source`] for at most 60 s, never caches
/// sensitive answers, and fails closed when the source is unreachable.
pub struct CachedAuthorizer<S: Source> {
    source: S,
    ttl: Duration,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl<S: Source> CachedAuthorizer<S> {
    /// Front `source` with the 60 s cache.
    pub fn new(source: S) -> Self {
        Self {
            source,
            ttl: MAX_CACHE_TTL,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Use a shorter lifetime; anything above 60 s is clamped to 60 s.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl.min(MAX_CACHE_TTL).max(Duration::zero());
        self
    }

    /// The source, for reading.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// The source, for changing grants.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Drop every cached decision (a revocation that must apply now).
    pub fn invalidate(&self) {
        self.lock().clear();
    }

    /// Decide at a given instant (deterministic for tests).
    ///
    /// `Cached` reuses a decision younger than the ttl and read at the source's current generation; `Live` always asks the
    /// source. A sensitive answer is never stored. If the source cannot be
    /// reached the answer is a deny: a stale entry is not served.
    pub fn decide_at(
        &self,
        principal: &str,
        action: &str,
        object: &str,
        freshness: Freshness,
        now: DateTime<Utc>,
    ) -> Decision {
        let key = (
            principal.to_string(),
            action.to_string(),
            object.to_string(),
        );
        // Read the generation before asking, so a change that lands while the
        // source answers leaves the stored entry stale (a miss), never fresh.
        let generation = self.source.generation();
        if freshness == Freshness::Cached
            && let Some((d, at, g)) = self.lock().get(&key)
            && *g == generation
            && now >= *at
            && now - *at < self.ttl
        {
            return d.clone();
        }
        match self.source.query(principal, action, object, now) {
            Ok(a) => {
                let mut c = self.lock();
                if a.sensitive {
                    c.remove(&key);
                } else {
                    c.insert(key, (a.decision.clone(), now, generation));
                }
                a.decision
            }
            Err(SourceUnavailable) => {
                self.lock().remove(&key);
                Decision::Deny {
                    reason: DenyReason::SourceUnreachable,
                }
            }
        }
    }

    /// The cache, recovering from a poisoned lock: the map holds only
    /// decisions that are re-checked against ttl and generation on use, so a
    /// panic elsewhere must not leave `invalidate` a no-op.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, CacheEntry>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<S: Source> Authorizer for CachedAuthorizer<S> {
    fn decide(&self, principal: &str, action: &str, object: &str, f: Freshness) -> Decision {
        self.decide_at(principal, action, object, f, Utc::now())
    }
}
