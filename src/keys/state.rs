use crate::errors::{AuthError, Result};

/// Lifecycle of a key. Moves only forward:
/// pending -> active -> retiring -> destroyed, and any live state -> revoked
/// -> destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Created, not yet used to sign; may be published ahead of use.
    Pending,
    /// Signs and verifies.
    Active,
    /// Verifies only, during the rotation overlap window.
    Retiring,
    /// Compromised or withdrawn: verifies nothing, never published.
    Revoked,
    /// Private material erased.
    Destroyed,
}

impl KeyState {
    /// Whether `self -> next` is a legal transition.
    pub fn can_become(self, next: KeyState) -> bool {
        use KeyState::*;
        matches!(
            (self, next),
            (Pending, Active)
                | (Active, Retiring)
                | (Retiring, Destroyed)
                | (Pending, Revoked)
                | (Active, Revoked)
                | (Retiring, Revoked)
                | (Revoked, Destroyed)
                | (Pending, Destroyed)
        )
    }

    /// Perform a transition, failing closed on an illegal one.
    pub fn transition(self, next: KeyState) -> Result<KeyState> {
        if self.can_become(next) {
            Ok(next)
        } else {
            Err(AuthError::validation(format!(
                "illegal key state change {self:?} -> {next:?}"
            )))
        }
    }

    /// May sign new material.
    pub fn can_sign(self) -> bool {
        self == KeyState::Active
    }

    /// May verify existing signatures.
    pub fn can_verify(self) -> bool {
        matches!(self, KeyState::Active | KeyState::Retiring)
    }

    /// Appears in a published JWKS (active and retiring; never revoked).
    pub fn is_published(self) -> bool {
        self.can_verify()
    }
}

#[cfg(test)]
mod tests {
    use super::KeyState::{self, *};

    const ALL: [KeyState; 5] = [Pending, Active, Retiring, Revoked, Destroyed];

    #[test]
    fn only_listed_transitions_are_legal() {
        let legal = [
            (Pending, Active),
            (Active, Retiring),
            (Retiring, Destroyed),
            (Pending, Revoked),
            (Active, Revoked),
            (Retiring, Revoked),
            (Revoked, Destroyed),
            (Pending, Destroyed),
        ];
        for a in ALL {
            for b in ALL {
                assert_eq!(a.can_become(b), legal.contains(&(a, b)), "{a:?}->{b:?}");
            }
        }
    }

    #[test]
    fn nothing_leaves_destroyed_and_revoked_never_returns() {
        for b in ALL {
            assert!(!Destroyed.can_become(b));
        }
        assert!(!Revoked.can_become(Active));
        assert!(Revoked.transition(Active).is_err());
    }

    #[test]
    fn capabilities_follow_state() {
        assert!(Active.can_sign() && !Retiring.can_sign() && !Pending.can_sign());
        assert!(Retiring.can_verify() && !Revoked.can_verify());
        assert!(Active.is_published() && Retiring.is_published());
        assert!(!Revoked.is_published() && !Pending.is_published() && !Destroyed.is_published());
    }
}
