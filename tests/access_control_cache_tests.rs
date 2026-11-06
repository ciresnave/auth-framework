use auth_framework::access_control::*;
use chrono::{DateTime, Duration, Utc};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const A: &str = "a@acct";
const B: &str = "b@acct";
const PM: &str = "agent:pm@acct";

/// A source that counts queries and can be switched off.
struct Flaky {
    inner: InMemoryEngine,
    up: AtomicBool,
    calls: AtomicUsize,
}

impl Source for Flaky {
    fn query(
        &self,
        p: &str,
        a: &str,
        o: &str,
        now: DateTime<Utc>,
    ) -> Result<Answer, SourceUnavailable> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.up.load(Ordering::SeqCst) {
            return Err(SourceUnavailable);
        }
        self.inner.query(p, a, o, now)
    }
}

fn cached() -> CachedAuthorizer<Flaky> {
    let mut r = ActionRegistry::new();
    r.register("synapse:see", false);
    r.register("synapse:send", false);
    r.register("synapse:edit-rule", true);
    let mut e = InMemoryEngine::new(r);
    e.add_grant(Grant::new("g", A, "synapse:see", PM, Effect::Allow));
    e.add_grant(Grant::new("r", A, "synapse:edit-rule", PM, Effect::Allow));
    CachedAuthorizer::new(Flaky {
        inner: e,
        up: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    })
}

fn calls(c: &CachedAuthorizer<Flaky>) -> usize {
    c.source().calls.load(Ordering::SeqCst)
}
fn set_up(c: &CachedAuthorizer<Flaky>, up: bool) {
    c.source().up.store(up, Ordering::SeqCst);
}
fn see(c: &CachedAuthorizer<Flaky>, who: &str, f: Freshness, t: DateTime<Utc>) -> Decision {
    c.decide_at(who, "synapse:see", PM, f, t)
}

#[test]
fn a_decision_is_reused_within_the_ttl() {
    let c = cached();
    let t = Utc::now();
    assert!(see(&c, A, Freshness::Cached, t).is_allow());
    assert!(see(&c, A, Freshness::Cached, t + Duration::seconds(59)).is_allow());
    assert_eq!(calls(&c), 1);
}

#[test]
fn a_revoke_applies_within_60_seconds() {
    let mut c = cached();
    let t = Utc::now();
    assert!(see(&c, A, Freshness::Cached, t).is_allow());
    c.source_mut().inner.remove_grant("g");
    // inside the window a stale allow is the permitted staleness
    assert!(see(&c, A, Freshness::Cached, t + Duration::seconds(59)).is_allow());
    // at 60 s the cache entry is dead and the source says no
    assert!(!see(&c, A, Freshness::Cached, t + Duration::seconds(60)).is_allow());
    assert_eq!(calls(&c), 2);
}

#[test]
fn the_ttl_cannot_be_raised_above_60_seconds() {
    let c = cached().with_ttl(Duration::hours(1));
    let t = Utc::now();
    see(&c, A, Freshness::Cached, t);
    see(&c, A, Freshness::Cached, t + Duration::seconds(61));
    assert_eq!(calls(&c), 2);
}

#[test]
fn a_shorter_ttl_is_honoured() {
    let c = cached().with_ttl(Duration::seconds(5));
    let t = Utc::now();
    see(&c, A, Freshness::Cached, t);
    see(&c, A, Freshness::Cached, t + Duration::seconds(4));
    assert_eq!(calls(&c), 1);
    see(&c, A, Freshness::Cached, t + Duration::seconds(5));
    assert_eq!(calls(&c), 2);
}

#[test]
fn the_cache_is_per_principal_action_and_object() {
    let c = cached();
    let t = Utc::now();
    assert!(see(&c, A, Freshness::Cached, t).is_allow());
    assert!(!see(&c, B, Freshness::Cached, t).is_allow());
    assert!(
        !c.decide_at(A, "synapse:send", PM, Freshness::Cached, t)
            .is_allow()
    );
    assert!(
        !c.decide_at(A, "synapse:see", "agent:x@acct", Freshness::Cached, t)
            .is_allow()
    );
    assert_eq!(calls(&c), 4);
}

#[test]
fn live_always_asks_the_source() {
    let mut c = cached();
    let t = Utc::now();
    assert!(see(&c, A, Freshness::Cached, t).is_allow());
    c.source_mut().inner.remove_grant("g");
    assert!(!see(&c, A, Freshness::Live, t).is_allow());
}

#[test]
fn a_sensitive_action_is_checked_live_on_every_call() {
    let mut c = cached();
    let t = Utc::now();
    let edit =
        |c: &CachedAuthorizer<Flaky>| c.decide_at(A, "synapse:edit-rule", PM, Freshness::Cached, t);
    assert!(edit(&c).is_allow());
    assert!(edit(&c).is_allow());
    assert_eq!(calls(&c), 2);
    c.source_mut().inner.remove_grant("r");
    assert!(!edit(&c).is_allow());
}

#[test]
fn a_sensitive_grant_is_checked_live_on_every_call() {
    let mut c = cached();
    let mut g = Grant::new("sg", B, "synapse:see", PM, Effect::Allow);
    g.sensitive = true;
    c.source_mut().inner.add_grant(g);
    let t = Utc::now();
    assert!(see(&c, B, Freshness::Cached, t).is_allow());
    assert!(see(&c, B, Freshness::Cached, t).is_allow());
    assert_eq!(calls(&c), 2);
    c.source_mut().inner.remove_grant("sg");
    assert!(!see(&c, B, Freshness::Cached, t).is_allow());
}

#[test]
fn a_sensitive_object_is_checked_live_on_every_call() {
    let mut c = cached();
    c.source_mut().inner.mark_object_sensitive("agent:pm@acct");
    let t = Utc::now();
    see(&c, A, Freshness::Cached, t);
    see(&c, A, Freshness::Cached, t);
    assert_eq!(calls(&c), 2);
    // other objects still cache
    c.decide_at(A, "synapse:see", "agent:x@acct", Freshness::Cached, t);
    c.decide_at(A, "synapse:see", "agent:x@acct", Freshness::Cached, t);
    assert_eq!(calls(&c), 3);
}

#[test]
fn an_unreachable_source_denies_a_live_decision() {
    let c = cached();
    set_up(&c, false);
    assert_eq!(
        see(&c, A, Freshness::Live, Utc::now()),
        Decision::Deny {
            reason: DenyReason::SourceUnreachable
        }
    );
}

#[test]
fn an_unreachable_source_denies_a_sensitive_decision_even_if_it_was_allowed_before() {
    let c = cached();
    let t = Utc::now();
    assert!(
        c.decide_at(A, "synapse:edit-rule", PM, Freshness::Cached, t)
            .is_allow()
    );
    set_up(&c, false);
    assert_eq!(
        c.decide_at(A, "synapse:edit-rule", PM, Freshness::Cached, t),
        Decision::Deny {
            reason: DenyReason::SourceUnreachable
        }
    );
}

#[test]
fn a_cached_decision_is_served_until_its_60_seconds_end_then_denied_when_the_source_is_down() {
    let c = cached();
    let t = Utc::now();
    assert!(see(&c, A, Freshness::Cached, t).is_allow());
    set_up(&c, false);
    assert!(see(&c, A, Freshness::Cached, t + Duration::seconds(59)).is_allow());
    assert_eq!(
        see(&c, A, Freshness::Cached, t + Duration::seconds(60)),
        Decision::Deny {
            reason: DenyReason::SourceUnreachable
        }
    );
    // and a stale allow is not resurrected when the clock is read again
    assert!(!see(&c, A, Freshness::Cached, t + Duration::seconds(61)).is_allow());
}

#[test]
fn an_unreachable_source_never_turns_a_deny_into_an_allow() {
    let c = cached();
    let t = Utc::now();
    assert!(!see(&c, B, Freshness::Cached, t).is_allow());
    set_up(&c, false);
    for s in [0, 30, 59, 60, 600] {
        assert!(!see(&c, B, Freshness::Cached, t + Duration::seconds(s)).is_allow());
        assert!(!see(&c, B, Freshness::Live, t + Duration::seconds(s)).is_allow());
    }
}

#[test]
fn invalidate_drops_cached_decisions() {
    let mut c = cached();
    let t = Utc::now();
    assert!(see(&c, A, Freshness::Cached, t).is_allow());
    c.source_mut().inner.remove_grant("g");
    c.invalidate();
    assert!(!see(&c, A, Freshness::Cached, t).is_allow());
}

#[test]
fn the_engine_reports_sensitivity_from_action_object_and_grant() {
    let mut r = ActionRegistry::new();
    r.register("plain", false);
    r.register("touchy", true);
    let mut e = InMemoryEngine::new(r);
    let now = Utc::now();
    e.add_grant(Grant::new("g", A, "plain", PM, Effect::Allow));
    assert!(!e.answer_at(A, "plain", PM, now).sensitive);
    assert!(e.answer_at(A, "touchy", PM, now).sensitive);
    e.mark_object_sensitive("agent:*@acct");
    assert!(e.answer_at(A, "plain", PM, now).sensitive);
}
