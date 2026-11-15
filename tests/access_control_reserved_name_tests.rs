// SPDX-License-Identifier: MIT OR Apache-2.0
//! The audit trail's name for direct engine calls, `(direct)`, cannot be taken
//! by a principal or used as the actor of a rule edit, delegation or creation.
use auth_framework::access_control::*;
use chrono::Utc;

use PrincipalKind::*;

const OBJ: &str = "agent:new@acct";

fn engine() -> InMemoryEngine {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    // No registry attached, so any actor name is accepted by the engine: only
    // the reservation can refuse it. The account holder is allowed everything.
    InMemoryEngine::new(a).with_account_holder(DIRECT_ACTOR)
}

/// Every entry under the reserved name came from a direct add or remove.
fn only_direct_calls_are_under_the_name(e: &InMemoryEngine) {
    for x in e.audit_log().iter().filter(|x| x.actor == DIRECT_ACTOR) {
        assert!(
            matches!(
                x.op,
                AuditOp::GrantAdded | AuditOp::GrantRemoved | AuditOp::Refused
            ),
            "{x:?}"
        );
    }
}

#[test]
fn no_principal_can_be_named_the_reserved_name() {
    let mut r = PrincipalRegistry::new();
    assert_eq!(
        r.create(DIRECT_ACTOR, Human, None),
        Err(PrincipalError::InvalidId)
    );
    r.create("alice", Human, None).unwrap();
    assert_eq!(
        r.create(DIRECT_ACTOR, Agent, Some("alice")),
        Err(PrincipalError::InvalidId)
    );
    assert!(r.get(DIRECT_ACTOR).is_none());
}

#[test]
fn the_reserved_name_cannot_create_a_principal_s_grants() {
    let mut e = engine();
    assert_eq!(
        e.register_new_principal(DIRECT_ACTOR, OBJ, &["synapse:see"]),
        Err(DelegationError::DelegatorInactive)
    );
    assert!(e.grant(&format!("creator:{OBJ}:synapse:see")).is_none());
    only_direct_calls_are_under_the_name(&e);
    assert!(e.audit_log().iter().all(|x| x.op != AuditOp::GrantAdded));
}

#[test]
fn the_reserved_name_cannot_delegate() {
    let mut e = engine();
    e.add_grant(Grant::new(
        "g",
        DIRECT_ACTOR,
        "synapse:see",
        "agent:*@acct",
        Effect::Allow,
    ))
    .unwrap();
    let r = e.delegate(DelegationRequest {
        id: "d".into(),
        from: "g".into(),
        delegator: DIRECT_ACTOR.into(),
        delegatee: "bob".into(),
        action: "synapse:see".into(),
        object: OBJ.into(),
        expires: None,
        sensitive: false,
    });
    assert_eq!(r, Err(DelegationError::DelegatorInactive));
    assert!(e.grant("d").is_none());
    assert!(e.audit_log().iter().all(|x| x.op != AuditOp::Delegated));
    only_direct_calls_are_under_the_name(&e);
}

#[test]
fn the_reserved_name_cannot_add_or_remove_a_rule() {
    let mut e = engine();
    e.add_grant(Grant::new("g", "carol", "synapse:see", OBJ, Effect::Allow))
        .unwrap();
    // Even as the issuer of a rule, the reserved name cannot remove it.
    let mut rule = Grant::new("r", "carol", "synapse:see", OBJ, Effect::Allow);
    rule.issuer = Some(DIRECT_ACTOR.into());
    e.add_grant(rule).unwrap();
    assert_eq!(
        e.remove_rule_at(DIRECT_ACTOR, "r", Utc::now()),
        Err(RuleError::NotAuthorized)
    );
    assert!(e.grant("r").is_some());
    assert_eq!(
        e.add_rule(
            DIRECT_ACTOR,
            Grant::new("n", "carol", "synapse:see", OBJ, Effect::Allow)
        ),
        Err(RuleError::NotAuthorized)
    );
    assert!(
        e.audit_log()
            .iter()
            .all(|x| !matches!(x.op, AuditOp::Added | AuditOp::Removed))
    );
}
