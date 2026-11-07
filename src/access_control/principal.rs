// SPDX-License-Identifier: MIT OR Apache-2.0
//! Principals: humans, programs and agents, each with a stable id, an owner,
//! bound keys and a lifecycle.
//!
//! A human has no owner; a program or agent is owned by another principal, so
//! every non-human traces up through its owners to the human who is
//! responsible for it ([`PrincipalRegistry::root_human`]). Ids are never
//! reused, a key thumbprint belongs to one principal for ever, and a principal
//! is effectively active only while it and every owner above it are active.

use std::collections::HashMap;

/// What kind of principal this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A person. Has no owner.
    Human,
    /// A service or program acting on its own account.
    Program,
    /// An agent acting for its owner.
    Agent,
}

/// Where a principal is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// In use.
    Active,
    /// Paused; may be resumed.
    Suspended,
    /// Finished for ever; its id stays reserved and its keys are revoked.
    Retired,
}

/// A principal.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Stable, never reused.
    pub id: String,
    /// Human, program or agent.
    pub kind: PrincipalKind,
    /// The principal that owns this one (none for a human).
    pub owner: Option<String>,
    /// Thumbprints of keys that may act as this principal.
    pub keys: Vec<String>,
    /// Thumbprints that were bound and have been revoked; never rebound.
    pub revoked_keys: Vec<String>,
    /// Lifecycle state.
    pub state: Lifecycle,
}

/// Why a principal operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalError {
    /// The id is empty, has whitespace, or contains `*`.
    InvalidId,
    /// The id was used before (including by a retired principal).
    DuplicateId,
    /// No such principal.
    Unknown,
    /// A human cannot have an owner.
    HumanCannotHaveOwner,
    /// A program or agent needs an owner.
    OwnerRequired,
    /// The owner does not exist or is not effectively active.
    OwnerInactive,
    /// The principal is retired.
    Retired,
    /// The lifecycle change is not allowed from the current state.
    InvalidTransition,
    /// The thumbprint is, or once was, bound to a principal.
    KeyAlreadyBound,
    /// The thumbprint is not an active key of this principal.
    KeyNotBound,
}

/// All principals of one account.
#[derive(Debug, Default, Clone)]
pub struct PrincipalRegistry {
    principals: HashMap<String, Principal>,
    /// Every thumbprint ever bound, to the principal that bound it.
    thumbprints: HashMap<String, String>,
}

impl PrincipalRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look a principal up.
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.principals.get(id)
    }

    /// Create a principal. A human takes no owner; anything else needs an
    /// effectively active owner.
    pub fn create(
        &mut self,
        id: &str,
        kind: PrincipalKind,
        owner: Option<&str>,
    ) -> Result<(), PrincipalError> {
        if id.is_empty() || id.contains('*') || id.chars().any(char::is_whitespace) {
            return Err(PrincipalError::InvalidId);
        }
        if self.principals.contains_key(id) {
            return Err(PrincipalError::DuplicateId);
        }
        match (kind, owner) {
            (PrincipalKind::Human, Some(_)) => return Err(PrincipalError::HumanCannotHaveOwner),
            (PrincipalKind::Human, None) => {}
            (_, None) => return Err(PrincipalError::OwnerRequired),
            (_, Some(o)) => {
                if !self.is_active(o) {
                    return Err(PrincipalError::OwnerInactive);
                }
            }
        }
        self.principals.insert(
            id.to_string(),
            Principal {
                id: id.to_string(),
                kind,
                owner: owner.map(str::to_string),
                keys: Vec::new(),
                revoked_keys: Vec::new(),
                state: Lifecycle::Active,
            },
        );
        Ok(())
    }

    /// True while the principal and every owner above it are `Active`.
    pub fn is_active(&self, id: &str) -> bool {
        let mut cur = self.principals.get(id);
        for _ in 0..=self.principals.len() {
            match cur {
                None => return false,
                Some(p) if p.state != Lifecycle::Active => return false,
                Some(p) => match &p.owner {
                    None => return true,
                    Some(o) => cur = self.principals.get(o),
                },
            }
        }
        false
    }

    /// The human at the top of the owner chain, if the chain is intact.
    pub fn root_human(&self, id: &str) -> Option<&str> {
        let mut cur = self.principals.get(id)?;
        for _ in 0..=self.principals.len() {
            match &cur.owner {
                None => {
                    return (cur.kind == PrincipalKind::Human).then_some(cur.id.as_str());
                }
                Some(o) => cur = self.principals.get(o)?,
            }
        }
        None
    }

    /// True when `ancestor` is `id` itself or any owner above it.
    pub fn is_ancestor_or_self(&self, ancestor: &str, id: &str) -> bool {
        let mut cur = self.principals.get(id);
        for _ in 0..=self.principals.len() {
            match cur {
                None => return false,
                Some(p) if p.id == ancestor => return true,
                Some(p) => match &p.owner {
                    None => return false,
                    Some(o) => cur = self.principals.get(o),
                },
            }
        }
        false
    }

    /// Pause a principal (and so everything it owns).
    pub fn suspend(&mut self, id: &str) -> Result<(), PrincipalError> {
        let p = self.principals.get_mut(id).ok_or(PrincipalError::Unknown)?;
        match p.state {
            Lifecycle::Active => {
                p.state = Lifecycle::Suspended;
                Ok(())
            }
            Lifecycle::Retired => Err(PrincipalError::Retired),
            Lifecycle::Suspended => Err(PrincipalError::InvalidTransition),
        }
    }

    /// Resume a suspended principal.
    pub fn resume(&mut self, id: &str) -> Result<(), PrincipalError> {
        let p = self.principals.get_mut(id).ok_or(PrincipalError::Unknown)?;
        match p.state {
            Lifecycle::Suspended => {
                p.state = Lifecycle::Active;
                Ok(())
            }
            Lifecycle::Retired => Err(PrincipalError::Retired),
            Lifecycle::Active => Err(PrincipalError::InvalidTransition),
        }
    }

    /// Retire a principal for ever, and everything it owns, revoking their
    /// keys. Returns the ids retired. The ids stay reserved.
    pub fn retire(&mut self, id: &str) -> Result<Vec<String>, PrincipalError> {
        let start = self.principals.get(id).ok_or(PrincipalError::Unknown)?;
        if start.state == Lifecycle::Retired {
            return Err(PrincipalError::Retired);
        }
        let mut dead = vec![id.to_string()];
        let mut i = 0;
        while i < dead.len() {
            let cur = dead[i].clone();
            for p in self.principals.values() {
                if p.owner.as_deref() == Some(cur.as_str()) && !dead.contains(&p.id) {
                    dead.push(p.id.clone());
                }
            }
            i += 1;
        }
        for d in &dead {
            if let Some(p) = self.principals.get_mut(d) {
                p.state = Lifecycle::Retired;
                let keys = std::mem::take(&mut p.keys);
                p.revoked_keys.extend(keys);
            }
        }
        Ok(dead)
    }

    /// Bind a key thumbprint to a principal. A thumbprint that was ever bound
    /// (to anyone, revoked or not) cannot be bound again.
    pub fn add_key(&mut self, id: &str, thumbprint: &str) -> Result<(), PrincipalError> {
        if thumbprint.is_empty() {
            return Err(PrincipalError::KeyNotBound);
        }
        let p = self.principals.get(id).ok_or(PrincipalError::Unknown)?;
        if p.state == Lifecycle::Retired {
            return Err(PrincipalError::Retired);
        }
        if self.thumbprints.contains_key(thumbprint) {
            return Err(PrincipalError::KeyAlreadyBound);
        }
        self.thumbprints
            .insert(thumbprint.to_string(), id.to_string());
        if let Some(p) = self.principals.get_mut(id) {
            p.keys.push(thumbprint.to_string());
        }
        Ok(())
    }

    /// Revoke one of a principal's keys for ever.
    pub fn revoke_key(&mut self, id: &str, thumbprint: &str) -> Result<(), PrincipalError> {
        let p = self.principals.get_mut(id).ok_or(PrincipalError::Unknown)?;
        match p.keys.iter().position(|k| k == thumbprint) {
            None => Err(PrincipalError::KeyNotBound),
            Some(i) => {
                let k = p.keys.remove(i);
                p.revoked_keys.push(k);
                Ok(())
            }
        }
    }

    /// The principal a key thumbprint acts as: only if the key is active and
    /// the principal is effectively active.
    pub fn principal_for_thumbprint(&self, thumbprint: &str) -> Option<&Principal> {
        let id = self.thumbprints.get(thumbprint)?;
        let p = self.principals.get(id)?;
        (p.keys.iter().any(|k| k == thumbprint) && self.is_active(id)).then_some(p)
    }
}
