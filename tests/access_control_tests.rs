// SPDX-License-Identifier: MIT OR Apache-2.0
use auth_framework::access_control::*;
use chrono::{Duration, Utc};

const A: &str = "lane-a@acct";
const PM: &str = "agent:pm@acct";

fn engine() -> InMemoryEngine {
    let mut r = ActionRegistry::new();
    r.register("synapse:see", false);
    r.register("synapse:send", false);
    r.register("synapse:edit-rule", true);
    InMemoryEngine::new(r)
}
fn d(e: &InMemoryEngine, action: &str, obj: &str) -> Decision {
    e.decide(A, action, obj, Freshness::Cached)
}

#[test]
fn default_deny() {
    assert_eq!(
        d(&engine(), "synapse:see", PM),
        Decision::Deny {
            reason: DenyReason::NoMatchingGrant
        }
    );
}

#[test]
fn allow_grant_allows() {
    let mut e = engine();
    e.add_grant(Grant::new("g1", A, "synapse:see", PM, Effect::Allow));
    assert_eq!(
        d(&e, "synapse:see", PM),
        Decision::Allow {
            grant_ref: "g1".into()
        }
    );
}

#[test]
fn deny_beats_allow_in_either_order() {
    for deny_first in [true, false] {
        let mut e = engine();
        let allow = Grant::new("a", A, "synapse:send", "agent:*@acct", Effect::Allow);
        let deny = Grant::new("d", A, "synapse:send", PM, Effect::Deny);
        if deny_first {
            e.add_grant(deny);
            e.add_grant(allow);
        } else {
            e.add_grant(allow);
            e.add_grant(deny);
        }
        assert_eq!(
            d(&e, "synapse:send", PM),
            Decision::Deny {
                reason: DenyReason::ExplicitDeny {
                    grant_ref: "d".into()
                }
            }
        );
        assert!(d(&e, "synapse:send", "agent:other@acct").is_allow());
    }
}

#[test]
fn see_does_not_imply_send_and_send_does_not_imply_see() {
    let mut e = engine();
    e.add_grant(Grant::new("s", A, "synapse:see", PM, Effect::Allow));
    assert!(d(&e, "synapse:see", PM).is_allow());
    assert!(!d(&e, "synapse:send", PM).is_allow());
    let mut e = engine();
    e.add_grant(Grant::new("s", A, "synapse:send", PM, Effect::Allow));
    assert!(!d(&e, "synapse:see", PM).is_allow());
}

#[test]
fn unregistered_action_is_denied_even_with_wildcard_grant() {
    let mut e = engine();
    e.add_grant(Grant::new("w", "*", "*", "*", Effect::Allow));
    assert_eq!(
        d(&e, "synapse:nope", PM),
        Decision::Deny {
            reason: DenyReason::UnregisteredAction
        }
    );
}

#[test]
fn expired_grant_is_ignored() {
    let mut e = engine();
    let mut g = Grant::new("x", A, "synapse:see", PM, Effect::Allow);
    g.expires = Some(Utc::now() - Duration::seconds(1));
    e.add_grant(g);
    assert!(!d(&e, "synapse:see", PM).is_allow());
}

#[test]
fn expired_deny_no_longer_blocks() {
    let mut e = engine();
    e.add_grant(Grant::new("a", A, "synapse:see", PM, Effect::Allow));
    let mut g = Grant::new("d", A, "synapse:see", PM, Effect::Deny);
    g.expires = Some(Utc::now() - Duration::seconds(1));
    e.add_grant(g);
    assert!(d(&e, "synapse:see", PM).is_allow());
}

#[test]
fn grant_is_for_its_principal_only() {
    let mut e = engine();
    e.add_grant(Grant::new(
        "g",
        "lane-b@acct",
        "synapse:see",
        PM,
        Effect::Allow,
    ));
    assert!(!d(&e, "synapse:see", PM).is_allow());
}

#[test]
fn wildcard_object_stays_inside_its_account() {
    assert!(object_matches("agent:*@acct", "agent:pm@acct"));
    assert!(!object_matches("agent:*@acct", "agent:pm@other"));
    assert!(!object_matches("agent:*@acct", "agent:pm@evil@acct"));
    assert!(!object_matches("agent:*@acct", "room:pm@acct"));
    assert!(object_matches("*", "anything@anywhere"));
}

#[test]
fn removing_a_grant_removes_access() {
    let mut e = engine();
    e.add_grant(Grant::new("g", A, "synapse:see", PM, Effect::Allow));
    e.remove_grant("g");
    assert!(!d(&e, "synapse:see", PM).is_allow());
}

#[test]
fn reregistering_never_lowers_sensitivity() {
    let mut r = ActionRegistry::new();
    r.register("x", true);
    r.register("x", false);
    assert!(r.is_sensitive("x"));
    assert!(!r.is_sensitive("unknown"));
}
