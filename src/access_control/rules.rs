// SPDX-License-Identifier: MIT OR Apache-2.0
//! Editing rules: who may add or remove a grant, and the audit trail.
//!
//! A rule is a [`Grant`]. Whoever holds the engine's *edit action* over an
//! object can add and remove rules about it. The account holder always can,
//! and so can any strict owner-ancestor of the principal the object names
//! (`agent:<id>@...`), which is how "revocable by any ancestor up to the
//! account holder" is met. Everyone else shares a subset of what they hold
//! with [`InMemoryEngine::delegate`]. Every edit, refused or not, is recorded.

use super::{Effect, Grant, InMemoryEngine, object_matches, object_within};
use chrono::{DateTime, Utc};

/// What happened to a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOp {
    /// A rule was added by an editor.
    Added,
    /// A rule (and what hung from it) was removed.
    Removed,
    /// A subset of a grant was shared.
    Delegated,
    /// An edit was refused.
    Refused,
}

/// One entry of the audit trail: who did what to which rule, and the chain it
/// hung from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// When.
    pub at: DateTime<Utc>,
    /// Who.
    pub actor: String,
    /// What.
    pub op: AuditOp,
    /// The rule concerned.
    pub rule_id: String,
    /// The rule's source chain, nearest first (empty for a root rule).
    pub chain: Vec<String>,
}

/// Why a rule edit was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// The actor may not edit rules about this object.
    NotAuthorized,
    /// A rule with this id exists.
    DuplicateId,
    /// No such rule.
    UnknownRule,
}

/// The principal an object names: `agent:<id>@account` gives `<id>`.
fn principal_of(object: &str) -> Option<&str> {
    let rest = object.strip_prefix("agent:")?;
    let id = rest.split('@').next()?;
    (!id.is_empty() && !id.contains('*')).then_some(id)
}

impl InMemoryEngine {
    /// Name the action that lets its holder edit rules about an object.
    pub fn with_edit_action(mut self, action: impl Into<String>) -> Self {
        self.edit_action = Some(action.into());
        self
    }

    /// The audit trail, oldest first.
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit
    }

    pub(super) fn chain_of(&self, id: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = self.find(id).and_then(|g| g.parent.clone());
        while let Some(p) = cur {
            if out.len() > self.grants.len() {
                break;
            }
            cur = self.find(&p).and_then(|g| g.parent.clone());
            out.push(p);
        }
        out
    }

    pub(super) fn record(
        &mut self,
        at: DateTime<Utc>,
        actor: &str,
        op: AuditOp,
        rule_id: &str,
        chain: Vec<String>,
    ) {
        self.audit.push(AuditEntry {
            at,
            actor: actor.to_string(),
            op,
            rule_id: rule_id.to_string(),
            chain,
        });
    }

    /// May `actor` edit rules about `object` (a literal object or a pattern)?
    pub fn can_edit_rules_about(&self, actor: &str, object: &str, now: DateTime<Utc>) -> bool {
        if let Some(reg) = &self.principals
            && !reg.is_active(actor)
        {
            return false;
        }
        if self.account_holder.as_deref() == Some(actor) {
            return true;
        }
        if let (Some(reg), Some(p)) = (&self.principals, principal_of(object))
            && p != actor
            && reg.is_ancestor_or_self(actor, p)
        {
            return true;
        }
        let Some(edit) = self.edit_action.as_deref() else {
            return false;
        };
        if !self.registry.is_registered(edit) {
            return false;
        }
        // A pattern is covered only if some edit grant of the actor contains
        // it, and the actor has no edit-action deny at all (a deny on one
        // object under the pattern could otherwise be edited around).
        let live: Vec<&Grant> = self
            .grants
            .iter()
            .filter(|g| {
                (g.principal == "*" || g.principal == actor)
                    && (g.action == "*" || g.action == edit)
                    && self.chain_alive(g, now)
            })
            .collect();
        if object.contains('*') && live.iter().any(|g| g.effect == Effect::Deny) {
            return false;
        }
        let denied = live
            .iter()
            .any(|g| g.effect == Effect::Deny && object_matches(&g.object, object));
        let allowed = live
            .iter()
            .any(|g| g.effect == Effect::Allow && object_within(&g.object, object));
        allowed && !denied
    }

    /// Add a rule as `actor`. Refused (and recorded) unless the actor may edit
    /// rules about the rule's object.
    pub fn add_rule(&mut self, actor: &str, rule: Grant) -> Result<(), RuleError> {
        self.add_rule_at(actor, rule, Utc::now())
    }

    /// [`add_rule`](Self::add_rule) at a given instant.
    pub fn add_rule_at(
        &mut self,
        actor: &str,
        mut rule: Grant,
        now: DateTime<Utc>,
    ) -> Result<(), RuleError> {
        if !self.can_edit_rules_about(actor, &rule.object, now) {
            self.record(now, actor, AuditOp::Refused, &rule.id, Vec::new());
            return Err(RuleError::NotAuthorized);
        }
        if self.find(&rule.id).is_some() {
            return Err(RuleError::DuplicateId);
        }
        // An editor's rule is a root rule: it hangs from nothing.
        rule.parent = None;
        rule.depth = 0;
        rule.issuer = Some(actor.to_string());
        let id = rule.id.clone();
        self.grants.push(rule);
        self.record(now, actor, AuditOp::Added, &id, Vec::new());
        Ok(())
    }

    /// Remove a rule (and everything delegated from it) as `actor`: allowed
    /// to whoever may edit rules about its object, and to the rule's issuer.
    pub fn remove_rule(&mut self, actor: &str, id: &str) -> Result<(), RuleError> {
        self.remove_rule_at(actor, id, Utc::now())
    }

    /// [`remove_rule`](Self::remove_rule) at a given instant.
    pub fn remove_rule_at(
        &mut self,
        actor: &str,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), RuleError> {
        let g = self.find(id).cloned().ok_or(RuleError::UnknownRule)?;
        let chain = self.chain_of(id);
        let by_issuer = g.issuer.as_deref() == Some(actor)
            && self.principals.as_ref().is_none_or(|r| r.is_active(actor));
        if !by_issuer && !self.can_edit_rules_about(actor, &g.object, now) {
            self.record(now, actor, AuditOp::Refused, id, chain);
            return Err(RuleError::NotAuthorized);
        }
        self.remove_grant(id);
        self.record(now, actor, AuditOp::Removed, id, chain);
        Ok(())
    }
}
