// SPDX-License-Identifier: MIT OR Apache-2.0
use auth_framework::access_control::*;
use chrono::Utc;

use PrincipalKind::*;

const EDIT: &str = "synapse:edit-rule";
const SUB: &str = "agent:sub@acct";
const SVC: &str = "agent:svc@acct";
const ALL: &str = "agent:*@acct";

fn engine() -> InMemoryEngine {
    let mut p = PrincipalRegistry::new();
    p.create("alice", Human, None).unwrap();
    p.create("carol", Human, None).unwrap();
    p.create("dave", Human, None).unwrap();
    p.create("bot", Agent, Some("alice")).unwrap();
    p.create("sub", Agent, Some("bot")).unwrap();
    p.create("sub2", Agent, Some("sub")).unwrap();
    p.create("svc", Program, Some("alice")).unwrap();
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    a.register("synapse:send", false);
    a.register(EDIT, true);
    InMemoryEngine::new(a)
        .with_principals(p)
        .with_account_holder("alice")
        .with_edit_action(EDIT)
}

fn rule(id: &str, who: &str, action: &str, object: &str, effect: Effect) -> Grant {
    Grant::new(id, who, action, object, effect)
}

fn sees(e: &InMemoryEngine, who: &str, object: &str) -> bool {
    e.decide_at(who, "synapse:see", object, Utc::now())
        .is_allow()
}

#[test]
fn the_account_holder_can_add_and_remove_any_rule_about_its_own_agents() {
    let mut e = engine();
    e.add_rule(
        "alice",
        rule("r1", "carol", "synapse:see", SUB, Effect::Allow),
    )
    .unwrap();
    assert!(sees(&e, "carol", SUB));
    e.remove_rule("alice", "r1").unwrap();
    assert!(!sees(&e, "carol", SUB));
}

#[test]
fn a_stranger_cannot_add_a_rule_and_the_refusal_is_recorded() {
    let mut e = engine();
    assert_eq!(
        e.add_rule(
            "dave",
            rule("r1", "dave", "synapse:see", SUB, Effect::Allow)
        ),
        Err(RuleError::NotAuthorized)
    );
    assert!(!sees(&e, "dave", SUB));
    let last = e.audit_log().last().unwrap();
    assert_eq!((last.actor.as_str(), last.op), ("dave", AuditOp::Refused));
    assert_eq!(last.rule_id, "r1");
}

#[test]
fn an_edit_rule_holder_can_edit_within_its_scope_only() {
    let mut e = engine();
    e.add_rule("alice", rule("scope", "carol", EDIT, SVC, Effect::Allow))
        .unwrap();
    e.add_rule(
        "carol",
        rule("r1", "dave", "synapse:see", SVC, Effect::Allow),
    )
    .unwrap();
    assert!(sees(&e, "dave", SVC));
    assert_eq!(
        e.add_rule(
            "carol",
            rule("r2", "dave", "synapse:see", SUB, Effect::Allow)
        ),
        Err(RuleError::NotAuthorized)
    );
    assert!(!sees(&e, "dave", SUB));
}

#[test]
fn an_edit_scope_covers_narrower_objects_never_wider_ones() {
    let mut e = engine();
    e.add_rule("alice", rule("wide", "carol", EDIT, ALL, Effect::Allow))
        .unwrap();
    e.add_rule("alice", rule("narrow", "dave", EDIT, SUB, Effect::Allow))
        .unwrap();
    assert!(e.can_edit_rules_about("carol", SUB, Utc::now()));
    assert!(e.can_edit_rules_about("carol", "agent:s*@acct", Utc::now()));
    assert!(e.can_edit_rules_about("dave", SUB, Utc::now()));
    assert!(!e.can_edit_rules_about("dave", ALL, Utc::now()));
    assert!(!e.can_edit_rules_about("dave", SVC, Utc::now()));
    assert!(!e.can_edit_rules_about("carol", "agent:x@other", Utc::now()));
}

#[test]
fn a_deny_on_editing_blocks_that_object_and_every_pattern_over_it() {
    let mut e = engine();
    e.add_rule("alice", rule("wide", "carol", EDIT, ALL, Effect::Allow))
        .unwrap();
    e.add_rule("alice", rule("no", "carol", EDIT, SUB, Effect::Deny))
        .unwrap();
    assert!(!e.can_edit_rules_about("carol", SUB, Utc::now()));
    assert!(!e.can_edit_rules_about("carol", ALL, Utc::now()));
    assert!(!e.can_edit_rules_about("carol", "agent:s*@acct", Utc::now()));
    assert!(e.can_edit_rules_about("carol", SVC, Utc::now()));
}

#[test]
fn an_owner_ancestor_can_edit_rules_about_what_it_owns_but_not_itself_or_others() {
    let e = engine();
    let now = Utc::now();
    assert!(e.can_edit_rules_about("bot", SUB, now));
    assert!(e.can_edit_rules_about("bot", "agent:sub2@acct", now));
    assert!(!e.can_edit_rules_about("bot", SVC, now));
    assert!(!e.can_edit_rules_about("sub", SUB, now), "not itself");
    assert!(
        !e.can_edit_rules_about("sub", "agent:bot@acct", now),
        "not upwards"
    );
    assert!(!e.can_edit_rules_about("carol", SUB, now));
}

#[test]
fn a_creator_grant_is_revocable_by_any_ancestor_and_by_nobody_unrelated() {
    let mut e = engine();
    let ids = e
        .register_new_principal("sub", "agent:sub2@acct", &["synapse:see"])
        .unwrap();
    let g = ids[0].as_str();
    assert!(sees(&e, "sub", "agent:sub2@acct"));
    assert_eq!(e.remove_rule("svc", g), Err(RuleError::NotAuthorized));
    assert_eq!(e.remove_rule("carol", g), Err(RuleError::NotAuthorized));
    assert!(sees(&e, "sub", "agent:sub2@acct"));
    e.remove_rule("bot", g).unwrap(); // an ancestor
    assert!(!sees(&e, "sub", "agent:sub2@acct"));
    let ids = e
        .register_new_principal("sub", "agent:sub2@acct", &["synapse:send"])
        .unwrap();
    e.remove_rule("alice", &ids[0]).unwrap(); // the account holder
}

#[test]
fn an_issuer_can_remove_what_it_issued_but_not_what_others_issued() {
    let mut e = engine();
    e.add_grant(rule("src", "bot", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    let req = |id: &str, to: &str| DelegationRequest {
        id: id.into(),
        from: "src".into(),
        delegator: "bot".into(),
        delegatee: to.into(),
        action: "synapse:see".into(),
        object: SUB.into(),
        expires: None,
        sensitive: false,
    };
    e.delegate(req("d1", "carol")).unwrap();
    assert_eq!(e.remove_rule("carol", "d1"), Err(RuleError::NotAuthorized));
    assert_eq!(e.remove_rule("dave", "d1"), Err(RuleError::NotAuthorized));
    assert!(sees(&e, "carol", SUB));
    e.remove_rule("bot", "d1").unwrap();
    assert!(!sees(&e, "carol", SUB));
    assert_eq!(e.remove_rule("bot", "ghost"), Err(RuleError::UnknownRule));
}

#[test]
fn removing_a_rule_cascades_and_the_audit_records_the_chain() {
    let mut e = engine();
    e.add_rule("alice", rule("r", "bot", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    let d = |id: &str, from: &str, by: &str, to: &str| DelegationRequest {
        id: id.into(),
        from: from.into(),
        delegator: by.into(),
        delegatee: to.into(),
        action: "synapse:see".into(),
        object: SUB.into(),
        expires: None,
        sensitive: false,
    };
    e.delegate(d("d1", "r", "bot", "carol")).unwrap();
    e.delegate(d("d2", "d1", "carol", "dave")).unwrap();
    assert!(sees(&e, "dave", SUB));
    e.remove_rule("alice", "d2").unwrap();
    let last = e.audit_log().last().unwrap();
    assert_eq!(last.op, AuditOp::Removed);
    assert_eq!(last.chain, ["d1", "r"]);
    e.remove_rule("alice", "r").unwrap();
    assert!(!sees(&e, "bot", SUB) && !sees(&e, "carol", SUB));
    assert!(e.grant("d1").is_none());
}

#[test]
fn the_audit_trail_records_adds_delegations_and_refusals_in_order() {
    let mut e = engine();
    e.add_rule("alice", rule("r", "bot", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    e.delegate(DelegationRequest {
        id: "d1".into(),
        from: "r".into(),
        delegator: "bot".into(),
        delegatee: "carol".into(),
        action: "synapse:see".into(),
        object: SUB.into(),
        expires: None,
        sensitive: false,
    })
    .unwrap();
    let _ = e.remove_rule("dave", "d1");
    let ops: Vec<_> = e
        .audit_log()
        .iter()
        .map(|a| (a.actor.as_str(), a.op, a.rule_id.as_str()))
        .collect();
    assert_eq!(
        ops,
        [
            ("alice", AuditOp::Added, "r"),
            ("bot", AuditOp::Delegated, "d1"),
            ("dave", AuditOp::Refused, "d1"),
        ]
    );
    assert_eq!(e.audit_log()[1].chain, ["r"]);
}

#[test]
fn an_added_rule_is_a_root_rule_issued_by_its_editor() {
    let mut e = engine();
    let mut g = rule("r", "carol", "synapse:see", SUB, Effect::Allow);
    g.parent = Some("nonexistent".into());
    g.depth = 3;
    g.issuer = Some("someone-else".into());
    e.add_rule("alice", g).unwrap();
    let g = e.grant("r").unwrap();
    assert_eq!(
        (g.parent.clone(), g.depth, g.issuer.clone()),
        (None, 0, Some("alice".into()))
    );
    assert!(sees(&e, "carol", SUB));
    assert_eq!(
        e.add_rule(
            "alice",
            rule("r", "carol", "synapse:see", SUB, Effect::Allow)
        ),
        Err(RuleError::DuplicateId)
    );
}

#[test]
fn an_inactive_editor_cannot_edit() {
    let mut e = engine();
    e.add_rule("alice", rule("wide", "carol", EDIT, ALL, Effect::Allow))
        .unwrap();
    assert!(e.can_edit_rules_about("carol", SUB, Utc::now()));
    e.principals_mut().unwrap().suspend("carol").unwrap();
    assert!(!e.can_edit_rules_about("carol", SUB, Utc::now()));
    e.principals_mut().unwrap().suspend("bot").unwrap();
    assert!(!e.can_edit_rules_about("bot", "agent:sub2@acct", Utc::now()));
    e.principals_mut().unwrap().suspend("alice").unwrap();
    assert!(!e.can_edit_rules_about("alice", SUB, Utc::now()));
}

#[test]
fn without_a_configured_or_registered_edit_action_only_the_holder_and_ancestors_edit() {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    a.register(EDIT, true);
    let mut e = InMemoryEngine::new(a.clone()).with_account_holder("alice");
    e.add_grant(rule("g", "carol", EDIT, ALL, Effect::Allow))
        .unwrap();
    assert!(!e.can_edit_rules_about("carol", SUB, Utc::now()));
    assert!(e.can_edit_rules_about("alice", SUB, Utc::now()));
    // configured but never registered
    let mut e = InMemoryEngine::new(ActionRegistry::new())
        .with_account_holder("alice")
        .with_edit_action(EDIT);
    e.add_grant(rule("g", "carol", EDIT, ALL, Effect::Allow))
        .unwrap();
    assert!(!e.can_edit_rules_about("carol", SUB, Utc::now()));
}

#[test]
fn an_expired_edit_grant_no_longer_edits() {
    let mut e = engine();
    let mut g = rule("wide", "carol", EDIT, ALL, Effect::Allow);
    g.expires = Some(Utc::now() + chrono::Duration::minutes(5));
    e.add_rule("alice", g).unwrap();
    let now = Utc::now();
    assert!(e.can_edit_rules_about("carol", SUB, now));
    assert!(!e.can_edit_rules_about("carol", SUB, now + chrono::Duration::minutes(6)));
}

#[test]
fn an_unrelated_issuer_can_still_remove_what_it_shared_and_only_that() {
    // carol is neither the account holder, an ancestor of svc, nor an editor:
    // the only thing that lets her remove her own share is that she issued it.
    let mut e = engine();
    e.add_grant(rule("src", "carol", "synapse:see", SVC, Effect::Allow))
        .unwrap();
    let req = |id: &str, to: &str| DelegationRequest {
        id: id.into(),
        from: "src".into(),
        delegator: "carol".into(),
        delegatee: to.into(),
        action: "synapse:see".into(),
        object: SVC.into(),
        expires: None,
        sensitive: false,
    };
    e.delegate(req("mine", "dave")).unwrap();
    assert!(!e.can_edit_rules_about("carol", SVC, Utc::now()));
    assert_eq!(e.remove_rule("dave", "mine"), Err(RuleError::NotAuthorized));
    assert!(sees(&e, "dave", SVC));
    e.remove_rule("carol", "mine").unwrap();
    assert!(!sees(&e, "dave", SVC));
    // she did not issue the root grant "src" (add_grant has no issuer)
    assert_eq!(e.remove_rule("carol", "src"), Err(RuleError::NotAuthorized));
    assert!(sees(&e, "carol", SVC));
}

fn dreq(id: &str, from: &str, who: &str) -> DelegationRequest {
    DelegationRequest {
        id: id.into(),
        from: from.into(),
        delegator: who.into(),
        delegatee: "carol".into(),
        action: "synapse:see".into(),
        object: SUB.into(),
        expires: None,
        sensitive: false,
    }
}

#[test]
fn a_refused_delegation_and_a_duplicate_or_empty_rule_id_are_recorded() {
    let mut e = engine();
    e.add_rule("alice", rule("r", "bot", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    // Wrong delegator.
    assert_eq!(
        e.delegate(dreq("d1", "r", "dave")),
        Err(DelegationError::NotHolder)
    );
    // Unknown source.
    assert_eq!(
        e.delegate(dreq("d2", "ghost", "bot")),
        Err(DelegationError::UnknownGrant)
    );
    // Duplicate rule id and empty rule id.
    assert_eq!(
        e.add_rule(
            "alice",
            rule("r", "carol", "synapse:see", SUB, Effect::Allow)
        ),
        Err(RuleError::DuplicateId)
    );
    assert_eq!(
        e.add_rule(
            "alice",
            rule("", "carol", "synapse:see", SUB, Effect::Allow)
        ),
        Err(RuleError::InvalidId)
    );
    let ops: Vec<_> = e
        .audit_log()
        .iter()
        .map(|a| (a.actor.as_str(), a.op, a.rule_id.as_str()))
        .collect();
    assert_eq!(
        ops,
        [
            ("alice", AuditOp::Added, "r"),
            ("dave", AuditOp::Refused, "d1"),
            ("bot", AuditOp::Refused, "d2"),
            ("alice", AuditOp::Refused, "r"),
            ("alice", AuditOp::Refused, ""),
        ]
    );
    assert!(e.audit_log()[1].chain.is_empty());
}

#[test]
fn a_deny_on_an_unrelated_object_does_not_block_a_pattern_edit() {
    let mut e = engine();
    e.add_rule("alice", rule("wide", "carol", EDIT, ALL, Effect::Allow))
        .unwrap();
    e.add_rule(
        "alice",
        rule("room", "carol", EDIT, "room:x@acct", Effect::Deny),
    )
    .unwrap();
    assert!(e.can_edit_rules_about("carol", ALL, Utc::now()));
    // Control: a deny that does overlap the pattern still blocks it.
    e.add_rule("alice", rule("no", "carol", EDIT, SUB, Effect::Deny))
        .unwrap();
    assert!(!e.can_edit_rules_about("carol", ALL, Utc::now()));
    assert!(!e.can_edit_rules_about("carol", "agent:s*@acct", Utc::now()));
}

#[test]
fn a_rule_added_through_the_cache_is_seen_at_once() {
    let mut c = CachedAuthorizer::new(engine());
    let t = Utc::now();
    assert!(
        !c.decide_at("carol", "synapse:see", SUB, Freshness::Cached, t)
            .is_allow()
    );
    c.source_mut()
        .add_rule(
            "alice",
            rule("r1", "carol", "synapse:see", SUB, Effect::Allow),
        )
        .unwrap();
    assert!(
        c.decide_at("carol", "synapse:see", SUB, Freshness::Cached, t)
            .is_allow()
    );
}

#[test]
fn a_direct_add_and_remove_are_in_the_audit_trail() {
    let mut e = engine();
    e.add_grant(rule("g", "carol", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    e.remove_grant("g");
    let log = e.audit_log();
    assert_eq!(log.len(), 2);
    assert_eq!(
        (log[0].op, log[0].actor.as_str(), log[0].rule_id.as_str()),
        (AuditOp::GrantAdded, DIRECT_ACTOR, "g")
    );
    assert_eq!(
        (log[1].op, log[1].actor.as_str(), log[1].rule_id.as_str()),
        (AuditOp::GrantRemoved, DIRECT_ACTOR, "g")
    );
}

#[test]
fn a_refused_direct_add_is_recorded_and_changes_nothing() {
    let mut e = engine();
    e.add_grant(rule("g", "carol", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    // A duplicate id is refused.
    assert!(
        e.add_grant(rule("g", "dave", "synapse:see", SUB, Effect::Allow))
            .is_err()
    );
    // It was not inserted: dave gets nothing, carol keeps her grant.
    assert!(!sees(&e, "dave", SUB));
    assert!(sees(&e, "carol", SUB));
    // A grant claiming a parent is refused too.
    let mut forged = rule("f", "dave", "synapse:see", SUB, Effect::Allow);
    forged.parent = Some("g".into());
    assert!(e.add_grant(forged).is_err());
    assert!(!sees(&e, "dave", SUB));
    let ops: Vec<(AuditOp, &str)> = e
        .audit_log()
        .iter()
        .map(|a| (a.op, a.rule_id.as_str()))
        .collect();
    assert_eq!(
        ops,
        vec![
            (AuditOp::GrantAdded, "g"),
            (AuditOp::Refused, "g"),
            (AuditOp::Refused, "f")
        ]
    );
}

#[test]
fn removing_a_missing_grant_records_nothing_and_leaves_the_generation() {
    let mut e = engine();
    e.add_grant(rule("g", "carol", "synapse:see", SUB, Effect::Allow))
        .unwrap();
    let (generation, entries) = (e.generation(), e.audit_log().len());
    e.remove_grant("nope");
    assert_eq!(e.audit_log().len(), entries);
    assert_eq!(e.generation(), generation);
    // Control: removing a real grant does move both.
    e.remove_grant("g");
    assert_eq!(e.audit_log().len(), entries + 1);
    assert_ne!(e.generation(), generation);
}

#[test]
fn an_editor_cannot_take_the_name_the_trail_uses_for_direct_calls() {
    // A real, active principal that is also the account holder: only the
    // reserved name can be what refuses it.
    let mut p = PrincipalRegistry::new();
    p.create(DIRECT_ACTOR, Human, None).unwrap();
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    let mut e = InMemoryEngine::new(a)
        .with_principals(p)
        .with_account_holder(DIRECT_ACTOR);
    assert_eq!(
        e.add_rule(
            DIRECT_ACTOR,
            rule("r", "carol", "synapse:see", SUB, Effect::Allow)
        ),
        Err(RuleError::NotAuthorized)
    );
    assert!(
        e.audit_log()
            .iter()
            .all(|a| a.op == AuditOp::Refused && a.rule_id == "r")
    );
}

#[test]
fn a_rule_removal_by_an_editor_is_recorded_once() {
    let mut e = engine();
    e.add_rule(
        "alice",
        rule("r", "carol", "synapse:see", SUB, Effect::Allow),
    )
    .unwrap();
    e.remove_rule("alice", "r").unwrap();
    let ops: Vec<AuditOp> = e.audit_log().iter().map(|a| a.op).collect();
    assert_eq!(ops, vec![AuditOp::Added, AuditOp::Removed]);
}
