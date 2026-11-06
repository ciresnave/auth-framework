use auth_framework::access_control::*;
use chrono::Utc;

use Lifecycle::*;
use PrincipalKind::*;

fn reg() -> PrincipalRegistry {
    let mut r = PrincipalRegistry::new();
    r.create("alice", Human, None).unwrap();
    r.create("svc", Program, Some("alice")).unwrap();
    r.create("bot", Agent, Some("alice")).unwrap();
    r.create("sub", Agent, Some("bot")).unwrap();
    r
}

#[test]
fn a_human_has_no_owner_and_others_need_one() {
    let mut r = PrincipalRegistry::new();
    assert_eq!(
        r.create("h", Human, Some("x")),
        Err(PrincipalError::HumanCannotHaveOwner)
    );
    assert_eq!(
        r.create("a", Agent, None),
        Err(PrincipalError::OwnerRequired)
    );
    assert_eq!(
        r.create("p", Program, None),
        Err(PrincipalError::OwnerRequired)
    );
    assert_eq!(
        r.create("a", Agent, Some("ghost")),
        Err(PrincipalError::OwnerInactive)
    );
    assert!(r.get("a").is_none() && r.get("h").is_none());
}

#[test]
fn ids_are_validated_and_never_reused() {
    let mut r = reg();
    for bad in ["", "a b", "x*", "*"] {
        assert_eq!(
            r.create(bad, Human, None),
            Err(PrincipalError::InvalidId),
            "{bad:?}"
        );
    }
    assert_eq!(
        r.create("bot", Agent, Some("alice")),
        Err(PrincipalError::DuplicateId)
    );
    r.retire("bot").unwrap();
    assert_eq!(
        r.create("bot", Agent, Some("alice")),
        Err(PrincipalError::DuplicateId)
    );
}

#[test]
fn every_non_human_traces_to_a_human() {
    let r = reg();
    for id in ["alice", "svc", "bot", "sub"] {
        assert_eq!(r.root_human(id), Some("alice"), "{id}");
    }
    assert_eq!(r.root_human("ghost"), None);
    assert!(r.is_ancestor_or_self("alice", "sub"));
    assert!(r.is_ancestor_or_self("bot", "sub"));
    assert!(r.is_ancestor_or_self("sub", "sub"));
    assert!(!r.is_ancestor_or_self("svc", "sub"));
    assert!(!r.is_ancestor_or_self("sub", "bot"));
}

#[test]
fn suspending_an_owner_deactivates_what_it_owns_and_resuming_restores_it() {
    let mut r = reg();
    r.suspend("bot").unwrap();
    assert!(!r.is_active("bot"));
    assert!(!r.is_active("sub"));
    assert!(r.is_active("svc"));
    assert_eq!(
        r.create("sub2", Agent, Some("bot")),
        Err(PrincipalError::OwnerInactive)
    );
    r.resume("bot").unwrap();
    assert!(r.is_active("sub"));
}

#[test]
fn lifecycle_transitions_are_checked() {
    let mut r = reg();
    assert_eq!(r.resume("bot"), Err(PrincipalError::InvalidTransition));
    r.suspend("bot").unwrap();
    assert_eq!(r.suspend("bot"), Err(PrincipalError::InvalidTransition));
    assert_eq!(r.suspend("ghost"), Err(PrincipalError::Unknown));
    r.retire("bot").unwrap();
    assert_eq!(r.resume("bot"), Err(PrincipalError::Retired));
    assert_eq!(r.suspend("bot"), Err(PrincipalError::Retired));
    assert_eq!(r.retire("bot"), Err(PrincipalError::Retired));
}

#[test]
fn retiring_an_owner_retires_everything_it_owns_and_revokes_their_keys() {
    let mut r = reg();
    r.add_key("sub", "tp-sub").unwrap();
    r.add_key("svc", "tp-svc").unwrap();
    let mut dead = r.retire("bot").unwrap();
    dead.sort();
    assert_eq!(dead, ["bot", "sub"]);
    assert_eq!(r.get("sub").unwrap().state, Retired);
    assert!(r.principal_for_thumbprint("tp-sub").is_none());
    assert!(r.get("sub").unwrap().keys.is_empty());
    assert_eq!(r.get("sub").unwrap().revoked_keys, ["tp-sub"]);
    // siblings are untouched
    assert!(r.principal_for_thumbprint("tp-svc").is_some());
    assert_eq!(r.get("svc").unwrap().state, Active);
}

#[test]
fn a_key_resolves_to_its_principal_only_while_both_are_live() {
    let mut r = reg();
    r.add_key("bot", "tp").unwrap();
    assert_eq!(r.principal_for_thumbprint("tp").unwrap().id, "bot");
    assert!(r.principal_for_thumbprint("other").is_none());
    r.suspend("alice").unwrap();
    assert!(r.principal_for_thumbprint("tp").is_none());
    r.resume("alice").unwrap();
    r.revoke_key("bot", "tp").unwrap();
    assert!(r.principal_for_thumbprint("tp").is_none());
}

#[test]
fn a_thumbprint_is_bound_once_for_ever() {
    let mut r = reg();
    r.add_key("bot", "tp").unwrap();
    assert_eq!(r.add_key("svc", "tp"), Err(PrincipalError::KeyAlreadyBound));
    assert_eq!(r.add_key("bot", "tp"), Err(PrincipalError::KeyAlreadyBound));
    r.revoke_key("bot", "tp").unwrap();
    assert_eq!(r.add_key("svc", "tp"), Err(PrincipalError::KeyAlreadyBound));
    assert_eq!(r.add_key("bot", "tp"), Err(PrincipalError::KeyAlreadyBound));
    assert_eq!(r.revoke_key("bot", "tp"), Err(PrincipalError::KeyNotBound));
    assert_eq!(r.add_key("bot", ""), Err(PrincipalError::KeyNotBound));
    r.retire("svc").unwrap();
    assert_eq!(r.add_key("svc", "fresh"), Err(PrincipalError::Retired));
    assert_eq!(r.add_key("ghost", "fresh"), Err(PrincipalError::Unknown));
}

// ---- the engine with a registry attached ----

fn engine() -> InMemoryEngine {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    let mut e = InMemoryEngine::new(a).with_principals(reg());
    for who in ["alice", "svc", "bot", "sub", "ghost"] {
        e.add_grant(Grant::new(
            format!("g-{who}"),
            who,
            "synapse:see",
            "agent:pm@acct",
            Effect::Allow,
        ));
    }
    e
}

fn allowed(e: &InMemoryEngine, who: &str) -> Decision {
    e.decide_at(who, "synapse:see", "agent:pm@acct", Utc::now())
}

#[test]
fn an_unknown_principal_is_denied_even_with_a_grant() {
    let e = engine();
    assert!(allowed(&e, "bot").is_allow());
    assert_eq!(
        allowed(&e, "ghost"),
        Decision::Deny {
            reason: DenyReason::PrincipalInactive
        }
    );
}

#[test]
fn a_suspended_or_retired_principal_or_owner_is_denied() {
    let mut e = engine();
    e.principals_mut().unwrap().suspend("bot").unwrap();
    for who in ["bot", "sub"] {
        assert_eq!(
            allowed(&e, who),
            Decision::Deny {
                reason: DenyReason::PrincipalInactive
            },
            "{who}"
        );
    }
    assert!(allowed(&e, "svc").is_allow());
    e.principals_mut().unwrap().resume("bot").unwrap();
    assert!(allowed(&e, "sub").is_allow());
    e.principals_mut().unwrap().retire("alice").unwrap();
    for who in ["alice", "svc", "bot", "sub"] {
        assert!(!allowed(&e, who).is_allow(), "{who}");
    }
}

#[test]
fn without_a_registry_any_id_is_accepted() {
    let mut a = ActionRegistry::new();
    a.register("synapse:see", false);
    let mut e = InMemoryEngine::new(a);
    e.add_grant(Grant::new("g", "anyone", "synapse:see", "x", Effect::Allow));
    assert!(
        e.decide_at("anyone", "synapse:see", "x", Utc::now())
            .is_allow()
    );
}

#[test]
fn an_inactive_principal_answer_is_sensitive_so_it_is_never_cached() {
    let mut e = engine();
    e.principals_mut().unwrap().suspend("bot").unwrap();
    assert!(
        e.answer_at("bot", "synapse:see", "agent:pm@acct", Utc::now())
            .sensitive
    );
}

#[test]
fn invalidate_applies_a_suspension_at_once() {
    let mut c = CachedAuthorizer::new(engine());
    let t = Utc::now();
    assert!(
        c.decide_at("bot", "synapse:see", "agent:pm@acct", Freshness::Cached, t)
            .is_allow()
    );
    c.source_mut()
        .principals_mut()
        .unwrap()
        .suspend("bot")
        .unwrap();
    c.invalidate();
    assert!(
        !c.decide_at("bot", "synapse:see", "agent:pm@acct", Freshness::Cached, t)
            .is_allow()
    );
}

#[test]
fn a_program_nobody_owns_cannot_exist_so_no_agent_can_hang_off_one() {
    // A tool principal with no human behind it is refused outright, so the
    // owner chain of every principal ends in a human.
    let mut r = PrincipalRegistry::new();
    assert_eq!(
        r.create("tool", Program, None),
        Err(PrincipalError::OwnerRequired)
    );
    assert_eq!(
        r.create("agent", Agent, Some("tool")),
        Err(PrincipalError::OwnerInactive)
    );
    assert!(r.get("tool").is_none() && r.get("agent").is_none());
    // An agent made by a program resolves through the program to its human.
    r.create("alice", Human, None).unwrap();
    r.create("tool", Program, Some("alice")).unwrap();
    r.create("agent", Agent, Some("tool")).unwrap();
    assert_eq!(r.root_human("agent"), Some("alice"));
}
