// SPDX-License-Identifier: MIT OR Apache-2.0
//! G9: what an agent's GNAP token needs from the principal registry: the
//! acting principal, its account holder and software class, and key rotation.
use auth_framework::access_control::*;

use PrincipalKind::*;

fn reg() -> PrincipalRegistry {
    let mut r = PrincipalRegistry::new();
    r.create("alice", Human, None).unwrap();
    r.create("bot", Agent, Some("alice")).unwrap();
    r.create("sub", Agent, Some("bot")).unwrap();
    r.add_key("alice", "tp-alice").unwrap();
    r.add_key("bot", "tp-bot").unwrap();
    r.add_key("sub", "tp-sub").unwrap();
    r
}

#[test]
fn acting_context_names_the_principal_and_the_account_holder() {
    let mut r = reg();
    r.set_class_id("sub", Some("helper-v1")).unwrap();
    assert_eq!(
        r.acting_context("tp-sub"),
        Some(ActingContext {
            principal: "sub".into(),
            account_holder: "alice".into(),
            class_id: Some("helper-v1".into()),
        })
    );
    // A human acts for itself.
    let c = r.acting_context("tp-alice").unwrap();
    assert_eq!(
        (c.principal.as_str(), c.account_holder.as_str()),
        ("alice", "alice")
    );
    assert_eq!(c.class_id, None);
}

#[test]
fn acting_context_fails_closed() {
    let mut r = reg();
    assert_eq!(r.acting_context("unknown"), None);
    assert_eq!(r.acting_context(""), None);
    // Suspending the owner silences everything it owns.
    r.suspend("bot").unwrap();
    assert_eq!(r.acting_context("tp-bot"), None);
    assert_eq!(r.acting_context("tp-sub"), None);
    r.resume("bot").unwrap();
    assert!(r.acting_context("tp-sub").is_some());
    // A revoked key acts as nobody.
    r.revoke_key("sub", "tp-sub").unwrap();
    assert_eq!(r.acting_context("tp-sub"), None);
}

#[test]
fn class_id_is_for_programs_and_agents_and_must_be_one_token() {
    let mut r = reg();
    assert_eq!(
        r.set_class_id("alice", Some("x")),
        Err(PrincipalError::InvalidClassId)
    );
    assert_eq!(
        r.set_class_id("bot", Some("")),
        Err(PrincipalError::InvalidClassId)
    );
    assert_eq!(
        r.set_class_id("bot", Some("a b")),
        Err(PrincipalError::InvalidClassId)
    );
    assert_eq!(
        r.set_class_id("nobody", Some("x")),
        Err(PrincipalError::Unknown)
    );
    r.set_class_id("bot", Some("c1")).unwrap();
    assert_eq!(r.get("bot").unwrap().class_id.as_deref(), Some("c1"));
    r.set_class_id("bot", None).unwrap();
    assert_eq!(r.get("bot").unwrap().class_id, None);
    r.retire("bot").unwrap();
    assert_eq!(
        r.set_class_id("bot", Some("c2")),
        Err(PrincipalError::Retired)
    );
}

#[test]
fn rotate_key_swaps_atomically() {
    let mut r = reg();
    r.rotate_key("bot", "tp-bot", "tp-bot2").unwrap();
    assert_eq!(r.acting_context("tp-bot"), None, "old key is dead");
    assert_eq!(r.acting_context("tp-bot2").unwrap().principal, "bot");
    assert_eq!(r.get("bot").unwrap().keys, vec!["tp-bot2".to_string()]);
    assert!(
        r.get("bot")
            .unwrap()
            .revoked_keys
            .contains(&"tp-bot".to_string())
    );
}

#[test]
fn a_refused_rotation_changes_nothing() {
    let mut r = reg();
    let before = r.get("bot").unwrap().clone();
    // New key already bound to someone else.
    assert_eq!(
        r.rotate_key("bot", "tp-bot", "tp-sub"),
        Err(PrincipalError::KeyAlreadyBound)
    );
    // New key is the old key (bound, so refused).
    assert_eq!(
        r.rotate_key("bot", "tp-bot", "tp-bot"),
        Err(PrincipalError::KeyAlreadyBound)
    );
    // Old key is not this principal's.
    assert_eq!(
        r.rotate_key("bot", "tp-sub", "fresh"),
        Err(PrincipalError::KeyNotBound)
    );
    assert_eq!(
        r.rotate_key("bot", "nope", "fresh"),
        Err(PrincipalError::KeyNotBound)
    );
    assert_eq!(
        r.rotate_key("bot", "tp-bot", ""),
        Err(PrincipalError::InvalidThumbprint)
    );
    assert_eq!(
        r.rotate_key("ghost", "tp-bot", "fresh"),
        Err(PrincipalError::Unknown)
    );
    let after = r.get("bot").unwrap();
    assert_eq!(
        (&before.keys, &before.revoked_keys),
        (&after.keys, &after.revoked_keys)
    );
    assert!(r.acting_context("tp-bot").is_some());
    assert_eq!(
        r.acting_context("fresh"),
        None,
        "never bound by a refused rotation"
    );
    // A once-revoked key can never come back through rotation.
    r.rotate_key("bot", "tp-bot", "tp-bot2").unwrap();
    assert_eq!(
        r.rotate_key("bot", "tp-bot2", "tp-bot"),
        Err(PrincipalError::KeyAlreadyBound)
    );
    assert!(r.acting_context("tp-bot2").is_some());
}

#[test]
fn rotation_on_a_retired_principal_is_refused() {
    let mut r = reg();
    r.retire("sub").unwrap();
    assert_eq!(
        r.rotate_key("sub", "tp-sub", "fresh"),
        Err(PrincipalError::Retired)
    );
}
