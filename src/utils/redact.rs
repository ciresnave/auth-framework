//! Helpers for `Debug` impls that must not print secret values.
//!
//! A field that holds a secret is shown as `<redacted>`; an optional one keeps its shape
//! (`None` stays `None`, `Some(..)` becomes `Some(<redacted>)`), so a log line still says whether
//! the secret is configured.

use std::fmt;

/// What a secret field prints as.
pub(crate) enum Redacted {
    Absent,
    Present,
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Redacted::Absent => f.write_str("None"),
            Redacted::Present => f.write_str("<redacted>"),
        }
    }
}

/// Anything a secret can be stored in.
pub(crate) trait Secret {
    fn redacted(&self) -> Redacted;
}

impl Secret for String {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl Secret for Vec<u8> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T> Secret for Option<T> {
    fn redacted(&self) -> Redacted {
        if self.is_some() {
            Redacted::Present
        } else {
            Redacted::Absent
        }
    }
}

/// The value to hand to `DebugStruct::field` in place of a secret.
pub(crate) fn redacted<T: Secret>(value: &T) -> Redacted {
    value.redacted()
}
