// SPDX-License-Identifier: MIT OR Apache-2.0
use auth_framework::access_control::*;
use chrono::{DateTime, Duration, Utc};

const HOLDER: &str = "holder@acct";
const B: &str = "b@acct";
const C: &str = "c@acct";
const D: &str = "d@acct";
const E: &str = "e@acct";
const PM: &str = "agent:pm@acct";

fn engine() -> InMemoryEngine {
    let mut r = ActionRegistry::new();
    r.register("synapse:see", false);
    r.register("synapse:send", false);
    r.register("synapse:edit-rule", true);
    let mut e = InMemoryEngine::new(r);
    e.add_grant(Grant::new(
        "root",
        HOLDER,
        "synapse:see",
        "agent:*@acct",
        Effect::Allow,
    ));
    e
}

fn req(id: &str, from: &str, who: &str, to: &str, action: &str, object: &str) -> DelegationRequest {
    DelegationRequest {
        id: id.into(),
        from: from.into(),
        delegator: who.into(),
        delegatee: to.into(),
        action: action.into(),
        object: object.into(),
        expires: None,
        sensitive: false,
    }
}

fn allowed(e: &InMemoryEngine, who: &str, action: &str, obj: &str) -> bool {
    e.decide(who, action, obj, Freshness::Cached).is_allow()
}

#[test]
fn a_delegation_gives_the_delegatee_the_subset() {
    let mut e = engine();
    assert!(!allowed(&e, B, "synapse:see", PM));
    e.delegate(req("d1", "root", HOLDER, B, "synapse:see", PM))
        .unwrap();
    assert!(allowed(&e, B, "synapse:see", PM));
    assert!(!allowed(&e, B, "synapse:see", "agent:other@acct"));
}

#[test]
fn a_delegation_cannot_widen_the_action() {
    let mut e = engine();
    assert_eq!(
        e.delegate(req("d1", "root", HOLDER, B, "synapse:send", PM)),
        Err(DelegationError::ActionWidens)
    );
    assert_eq!(
        e.delegate(req("d2", "root", HOLDER, B, "*", PM)),
        Err(DelegationError::ActionWidens)
    );
    assert!(!allowed(&e, B, "synapse:send", PM));
}

#[test]
fn a_delegation_cannot_widen_the_object() {
    let mut e = engine();
    for obj in ["agent:*@other", "room:x@acct", "*", "agent:pm@other"] {
        assert_eq!(
            e.delegate(req("d", "root", HOLDER, B, "synapse:see", obj)),
            Err(DelegationError::ObjectWidens),
            "{obj}"
        );
    }
    assert!(object_within("agent:*@acct", "agent:p*@acct"));
    assert!(!object_within("agent:pm@acct", "agent:*@acct"));
}

#[test]
fn only_the_holder_can_delegate() {
    let mut e = engine();
    assert_eq!(
        e.delegate(req("d1", "root", B, C, "synapse:see", PM)),
        Err(DelegationError::NotHolder)
    );
}

#[test]
fn unknown_source_and_duplicate_id_are_refused() {
    let mut e = engine();
    assert_eq!(
        e.delegate(req("d1", "nope", HOLDER, B, "synapse:see", PM)),
        Err(DelegationError::UnknownGrant)
    );
    assert_eq!(
        e.delegate(req("root", "root", HOLDER, B, "synapse:see", PM)),
        Err(DelegationError::DuplicateId)
    );
}

#[test]
fn a_deny_grant_cannot_be_delegated() {
    let mut e = engine();
    e.add_grant(Grant::new("deny", HOLDER, "synapse:send", PM, Effect::Deny));
    assert_eq!(
        e.delegate(req("d1", "deny", HOLDER, B, "synapse:send", PM)),
        Err(DelegationError::NotAnAllowGrant)
    );
}

#[test]
fn a_delegatee_cannot_redelegate_more_than_it_got() {
    let mut e = engine();
    e.delegate(req("d1", "root", HOLDER, B, "synapse:see", PM))
        .unwrap();
    assert_eq!(
        e.delegate(req("d2", "d1", B, C, "synapse:see", "agent:*@acct")),
        Err(DelegationError::ObjectWidens)
    );
    e.delegate(req("d3", "d1", B, C, "synapse:see", PM))
        .unwrap();
    assert!(allowed(&e, C, "synapse:see", PM));
}

#[test]
fn a_delegation_cannot_outlive_its_source() {
    let mut e = engine();
    let now = Utc::now();
    let mut r1 = req("d1", "root", HOLDER, B, "synapse:see", PM);
    r1.expires = Some(now + Duration::hours(1));
    e.delegate_at(r1, now).unwrap();
    let mut r2 = req("d2", "d1", B, C, "synapse:see", PM);
    r2.expires = Some(now + Duration::hours(2));
    assert_eq!(e.delegate_at(r2, now), Err(DelegationError::ExpiryWidens));
    let r3 = req("d3", "d1", B, C, "synapse:see", PM);
    assert_eq!(e.delegate_at(r3, now), Err(DelegationError::ExpiryWidens));
    let mut r4 = req("d4", "d1", B, C, "synapse:see", PM);
    r4.expires = Some(now + Duration::minutes(30));
    assert_eq!(e.delegate_at(r4, now), Ok(()));
}

#[test]
fn a_delegation_dies_with_its_source_grants_expiry() {
    let mut e = engine();
    let now = Utc::now();
    let mut r1 = req("d1", "root", HOLDER, B, "synapse:see", PM);
    r1.expires = Some(now + Duration::hours(1));
    e.delegate_at(r1, now).unwrap();
    let mut r2 = req("d2", "d1", B, C, "synapse:see", PM);
    r2.expires = Some(now + Duration::hours(1));
    e.delegate_at(r2, now).unwrap();
    let at = |t: DateTime<Utc>| e.decide_at(C, "synapse:see", PM, t).is_allow();
    assert!(at(now));
    assert!(!at(now + Duration::hours(2)));
}

#[test]
fn a_delegation_dies_when_a_source_ancestor_expires_even_if_its_own_expiry_is_later() {
    // Build the chain, then expire the root only: the child has no expiry of
    // its own beyond the chain.
    let mut e = InMemoryEngine::new({
        let mut r = ActionRegistry::new();
        r.register("synapse:see", false);
        r
    });
    let now = Utc::now();
    let mut root = Grant::new("root", HOLDER, "synapse:see", PM, Effect::Allow);
    root.expires = Some(now + Duration::hours(1));
    e.add_grant(root);
    let mut child = Grant::new("d1", B, "synapse:see", PM, Effect::Allow);
    child.parent = Some("root".into());
    child.depth = 1;
    e.add_grant(child);
    assert!(e.decide_at(B, "synapse:see", PM, now).is_allow());
    assert!(
        !e.decide_at(B, "synapse:see", PM, now + Duration::hours(1))
            .is_allow()
    );
}

#[test]
fn revoking_a_source_removes_everything_delegated_from_it() {
    let mut e = engine();
    e.delegate(req("d1", "root", HOLDER, B, "synapse:see", PM))
        .unwrap();
    e.delegate(req("d2", "d1", B, C, "synapse:see", PM))
        .unwrap();
    e.delegate(req("d3", "d2", C, D, "synapse:see", PM))
        .unwrap();
    e.delegate(req("side", "root", HOLDER, E, "synapse:see", PM))
        .unwrap();
    assert!(allowed(&e, D, "synapse:see", PM));
    e.remove_grant("d1");
    assert!(!allowed(&e, B, "synapse:see", PM));
    assert!(!allowed(&e, C, "synapse:see", PM));
    assert!(!allowed(&e, D, "synapse:see", PM));
    // a sibling branch and the root are untouched
    assert!(allowed(&e, E, "synapse:see", PM));
    assert!(allowed(&e, HOLDER, "synapse:see", PM));
    // removed means removed: a new delegation from d2 finds no source
    assert_eq!(
        e.delegate(req("again", "d2", C, D, "synapse:see", PM)),
        Err(DelegationError::UnknownGrant)
    );
}

#[test]
fn a_chain_is_limited_to_depth_three_by_default_and_the_limit_is_configurable() {
    let mut e = engine();
    e.delegate(req("d1", "root", HOLDER, B, "synapse:see", PM))
        .unwrap();
    e.delegate(req("d2", "d1", B, C, "synapse:see", PM))
        .unwrap();
    e.delegate(req("d3", "d2", C, D, "synapse:see", PM))
        .unwrap();
    assert_eq!(
        e.delegate(req("d4", "d3", D, E, "synapse:see", PM)),
        Err(DelegationError::TooDeep { max: 3 })
    );
    let mut e = engine().with_max_delegation_depth(1);
    e.delegate(req("d1", "root", HOLDER, B, "synapse:see", PM))
        .unwrap();
    assert_eq!(
        e.delegate(req("d2", "d1", B, C, "synapse:see", PM)),
        Err(DelegationError::TooDeep { max: 1 })
    );
}

#[test]
fn a_delegation_inherits_sensitivity_and_cannot_lower_it() {
    let mut e = engine();
    let mut root = Grant::new("sroot", HOLDER, "synapse:see", PM, Effect::Allow);
    root.sensitive = true;
    e.add_grant(root);
    e.delegate(req("d1", "sroot", HOLDER, B, "synapse:see", PM))
        .unwrap();
    // read back through a second hop: still sensitive via the engine's view
    assert!(e.grant("d1").unwrap().sensitive);
    e.delegate(req("d2", "root", HOLDER, C, "synapse:see", PM))
        .unwrap();
    assert!(!e.grant("d2").unwrap().sensitive);
}

#[test]
fn a_deny_on_the_delegatee_still_wins() {
    let mut e = engine();
    e.delegate(req("d1", "root", HOLDER, B, "synapse:see", PM))
        .unwrap();
    e.add_grant(Grant::new("deny", B, "synapse:see", PM, Effect::Deny));
    assert!(!allowed(&e, B, "synapse:see", PM));
}

#[test]
fn a_new_principal_is_visible_only_to_its_creator_and_the_account_holder() {
    let mut e = engine().with_account_holder("owner@acct");
    let obj = "agent:sub1@acct";
    let ids = e
        .register_new_principal(B, obj, &["synapse:see", "synapse:send"])
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert!(allowed(&e, B, "synapse:see", obj));
    assert!(allowed(&e, B, "synapse:send", obj));
    assert!(!allowed(&e, C, "synapse:see", obj));
    assert!(!allowed(&e, C, "synapse:send", obj));
    assert!(allowed(&e, "owner@acct", "synapse:see", obj));
    // the creator got only what was listed
    assert!(!allowed(&e, B, "synapse:edit-rule", obj));
}

#[test]
fn the_creator_can_hide_a_sub_agent_but_the_account_holder_always_overrides() {
    let mut e = engine().with_account_holder("owner@acct");
    let obj = "agent:sub1@acct";
    e.register_new_principal(B, obj, &["synapse:see"]).unwrap();
    e.delegate(req(
        "share",
        "creator:agent:sub1@acct:synapse:see",
        B,
        C,
        "synapse:see",
        obj,
    ))
    .unwrap();
    assert!(allowed(&e, C, "synapse:see", obj));
    // the creator hides it from everyone, itself included, and from the owner
    e.add_grant(Grant::new("hide", "*", "synapse:see", obj, Effect::Deny));
    assert!(!allowed(&e, C, "synapse:see", obj));
    assert!(!allowed(&e, B, "synapse:see", obj));
    assert!(allowed(&e, "owner@acct", "synapse:see", obj));
}

#[test]
fn registering_a_principal_with_an_unknown_action_or_twice_is_refused() {
    let mut e = engine();
    assert_eq!(
        e.register_new_principal(B, "agent:s@acct", &["synapse:nope"]),
        Err(DelegationError::ActionWidens)
    );
    assert!(!allowed(&e, B, "synapse:nope", "agent:s@acct"));
    e.register_new_principal(B, "agent:s@acct", &["synapse:see"])
        .unwrap();
    assert_eq!(
        e.register_new_principal(C, "agent:s@acct", &["synapse:see"]),
        Err(DelegationError::DuplicateId)
    );
    assert!(!allowed(&e, C, "synapse:see", "agent:s@acct"));
}

#[test]
fn an_unregistered_action_cannot_be_delegated_under_a_wildcard_source() {
    let mut e = engine();
    e.add_grant(Grant::new("wild", HOLDER, "*", "*", Effect::Allow));
    assert_eq!(
        e.delegate(req("d1", "wild", HOLDER, B, "synapse:nope", PM)),
        Err(DelegationError::ActionWidens)
    );
}
