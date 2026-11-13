// SPDX-License-Identifier: MIT OR Apache-2.0
//! A creator can be issued only the actions it already holds.
use auth_framework::access_control::*;
use chrono::Utc;

const OBJ: &str = "agent:new@acct";

fn engine() -> InMemoryEngine {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    a.register("synapse:send", false);
    let mut e = InMemoryEngine::new(a).with_account_holder("owner@acct");
    e.add_grant(Grant::new(
        "g",
        "b@acct",
        "synapse:see",
        "agent:*@acct",
        Effect::Allow,
    ))
    .unwrap();
    e
}

fn can(e: &InMemoryEngine, who: &str, action: &str) -> bool {
    e.decide_at(who, action, OBJ, Utc::now()).is_allow()
}

#[test]
fn a_creator_cannot_be_issued_an_action_it_does_not_hold() {
    let mut e = engine();
    assert_eq!(
        e.register_new_principal("b@acct", OBJ, &["synapse:see", "synapse:send"]),
        Err(DelegationError::CreatorLacksAction)
    );
    // all or nothing: the held action was not granted either
    assert!(!can(&e, "b@acct", "synapse:send"));
    assert!(e.grant("creator:agent:new@acct:synapse:see").is_none());
}

#[test]
fn a_creator_with_no_grants_at_all_gets_nothing() {
    let mut e = engine();
    assert_eq!(
        e.register_new_principal("stranger@acct", OBJ, &["synapse:see"]),
        Err(DelegationError::CreatorLacksAction)
    );
    assert!(!can(&e, "stranger@acct", "synapse:see"));
}

#[test]
fn a_creator_gets_what_it_holds_and_the_account_holder_may_create_anything() {
    let mut e = engine();
    assert!(
        e.register_new_principal("b@acct", OBJ, &["synapse:see"])
            .is_ok()
    );
    assert!(can(&e, "b@acct", "synapse:see"));
    assert!(
        e.register_new_principal(
            "owner@acct",
            "agent:o@acct",
            &["synapse:see", "synapse:send"]
        )
        .is_ok()
    );
}

#[test]
fn a_denied_creator_cannot_be_issued_the_action() {
    let mut e = engine();
    e.add_grant(Grant::new("d", "b@acct", "synapse:see", OBJ, Effect::Deny))
        .unwrap();
    assert_eq!(
        e.register_new_principal("b@acct", OBJ, &["synapse:see"]),
        Err(DelegationError::CreatorLacksAction)
    );
}

#[test]
fn an_inactive_creator_is_refused_when_a_registry_is_attached() {
    let mut p = PrincipalRegistry::new();
    p.create("alice", PrincipalKind::Human, None).unwrap();
    p.create("bot", PrincipalKind::Agent, Some("alice"))
        .unwrap();
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    let mut e = InMemoryEngine::new(a).with_principals(p);
    e.add_grant(Grant::new("g", "bot", "synapse:see", "*", Effect::Allow))
        .unwrap();
    e.principals_mut().unwrap().suspend("bot").unwrap();
    assert_eq!(
        e.register_new_principal("bot", OBJ, &["synapse:see"]),
        Err(DelegationError::CreatorLacksAction)
    );
}
