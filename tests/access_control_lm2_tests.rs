// SPDX-License-Identifier: MIT OR Apache-2.0
//! Delegation follows the state of the principals who issued it.
use auth_framework::access_control::*;
use chrono::Utc;

fn engine() -> InMemoryEngine {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    let mut p = PrincipalRegistry::new();
    p.create("alice", PrincipalKind::Human, None).unwrap();
    p.create("bot", PrincipalKind::Agent, Some("alice"))
        .unwrap();
    p.create("helper", PrincipalKind::Agent, Some("alice"))
        .unwrap();
    p.create("leaf", PrincipalKind::Agent, Some("alice"))
        .unwrap();
    let mut e = InMemoryEngine::new(a).with_principals(p);
    e.add_grant(Grant::new(
        "root",
        "bot",
        "synapse:see",
        "doc:1",
        Effect::Allow,
    ))
    .unwrap();
    e
}

fn request(id: &str, from: &str, by: &str, to: &str) -> DelegationRequest {
    DelegationRequest {
        id: id.into(),
        from: from.into(),
        delegator: by.into(),
        delegatee: to.into(),
        action: "synapse:see".into(),
        object: "doc:1".into(),
        expires: None,
        sensitive: false,
    }
}

fn sees(e: &InMemoryEngine, who: &str) -> bool {
    e.decide_at(who, "synapse:see", "doc:1", Utc::now())
        .is_allow()
}

#[test]
fn a_suspended_principal_cannot_delegate() {
    let mut e = engine();
    e.principals_mut().unwrap().suspend("bot").unwrap();
    assert_eq!(
        e.delegate(request("d1", "root", "bot", "helper")),
        Err(DelegationError::DelegatorInactive)
    );
    assert!(e.grant("d1").is_none());
}

#[test]
fn delegation_stops_working_while_the_delegator_is_suspended_and_returns_on_resume() {
    let mut e = engine();
    e.delegate(request("d1", "root", "bot", "helper")).unwrap();
    assert!(sees(&e, "helper"));
    e.principals_mut().unwrap().suspend("bot").unwrap();
    assert!(!sees(&e, "helper"));
    e.principals_mut().unwrap().resume("bot").unwrap();
    assert!(sees(&e, "helper"));
}

#[test]
fn retiring_the_delegator_ends_what_it_delegated_for_good() {
    let mut e = engine();
    e.delegate(request("d1", "root", "bot", "helper")).unwrap();
    e.delegate(request("d2", "d1", "helper", "leaf")).unwrap();
    assert!(sees(&e, "leaf"));
    e.principals_mut().unwrap().retire("bot").unwrap();
    assert!(!sees(&e, "helper"));
    assert!(!sees(&e, "leaf"));
}

#[test]
fn a_suspension_in_the_middle_of_a_chain_cuts_everything_below() {
    let mut e = engine();
    e.delegate(request("d1", "root", "bot", "helper")).unwrap();
    e.delegate(request("d2", "d1", "helper", "leaf")).unwrap();
    e.principals_mut().unwrap().suspend("helper").unwrap();
    assert!(!sees(&e, "leaf"));
    e.principals_mut().unwrap().resume("helper").unwrap();
    assert!(sees(&e, "leaf"));
}

#[test]
fn an_unknown_delegator_is_refused_when_a_registry_is_attached() {
    let mut e = engine();
    e.add_grant(Grant::new(
        "g2",
        "ghost",
        "synapse:see",
        "doc:1",
        Effect::Allow,
    ))
    .unwrap();
    assert_eq!(
        e.delegate(request("d1", "g2", "ghost", "helper")),
        Err(DelegationError::DelegatorInactive)
    );
}

#[test]
fn without_a_registry_delegation_is_unchanged() {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    let mut e = InMemoryEngine::new(a);
    e.add_grant(Grant::new(
        "root",
        "bot",
        "synapse:see",
        "doc:1",
        Effect::Allow,
    ))
    .unwrap();
    e.delegate(request("d1", "root", "bot", "helper")).unwrap();
    assert!(sees(&e, "helper"));
}
