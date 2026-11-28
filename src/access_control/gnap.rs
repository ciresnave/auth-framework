// SPDX-License-Identifier: MIT OR Apache-2.0
//! Access-control engine behind GNAP: [`EngineGnapPolicy`] implements
//! [`GnapAccessPolicy`] by mapping the client key thumbprint to a principal and
//! asking the engine about every requested (action, location) pair.
//!
//! Fail closed throughout: an unknown, revoked or inactive key gets nothing; a
//! request with a `*` in an action or location is dropped (the engine treats `*`
//! in a *rule* as a wildcard, a client must never be able to ask for one); a
//! poisoned engine lock denies everything. The return is the allowed subset,
//! empty meaning deny.

use super::{ActingContext, Authorizer, Freshness, InMemoryEngine};
use crate::protocols::gnap::{GnapAccessPolicy, GnapAccessRequest};
use async_trait::async_trait;
use std::sync::{Arc, RwLock};

/// The object a request with no locations is checked against: only a rule whose
/// object is `*` covers it.
const WHOLE_SCOPE: &str = "*";

/// A [`GnapAccessPolicy`] backed by an [`InMemoryEngine`] that has a principal
/// registry attached.
#[derive(Clone)]
pub struct EngineGnapPolicy {
    engine: Arc<RwLock<InMemoryEngine>>,
}

impl std::fmt::Debug for EngineGnapPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineGnapPolicy").finish_non_exhaustive()
    }
}

impl EngineGnapPolicy {
    /// Use `engine` (shared, so rules can still be edited through the handle).
    pub fn new(engine: Arc<RwLock<InMemoryEngine>>) -> Self {
        Self { engine }
    }

    /// Who this client key acts as and for whom: what a GNAP token for an agent
    /// names (the principal acting and the account holder on whose behalf). `None`
    /// (fail closed) for an unknown or revoked key, an inactive principal, a
    /// principal whose owner chain does not end at a human, or a poisoned lock.
    pub fn acting_context(&self, client_key_thumbprint: &str) -> Option<ActingContext> {
        let engine = self.engine.read().ok()?;
        engine.principals()?.acting_context(client_key_thumbprint)
    }

    fn grant_sync(
        &self,
        client_key_thumbprint: &str,
        requested: &[GnapAccessRequest],
    ) -> Vec<GnapAccessRequest> {
        let Ok(engine) = self.engine.read() else {
            return Vec::new();
        };
        let Some(principal) = engine
            .principals()
            .and_then(|r| r.principal_for_thumbprint(client_key_thumbprint))
            .map(|p| p.id.clone())
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for req in requested {
            let actions: Vec<&str> = if req.actions.is_empty() {
                vec![req.access_type.as_str()]
            } else {
                req.actions.iter().map(String::as_str).collect()
            };
            if actions.iter().any(|a| a.contains('*'))
                || req.locations.iter().any(|l| l.contains('*'))
            {
                continue;
            }
            let locations: Vec<&str> = if req.locations.is_empty() {
                vec![WHOLE_SCOPE]
            } else {
                req.locations.iter().map(String::as_str).collect()
            };
            // Group locations by the set of actions allowed there, so the answer
            // never claims an action at a location where it was refused.
            let mut groups: Vec<(Vec<String>, Vec<String>)> = Vec::new();
            for loc in locations {
                let allowed: Vec<String> = actions
                    .iter()
                    .filter(|a| {
                        engine
                            .decide(&principal, a, loc, Freshness::Live)
                            .is_allow()
                    })
                    .map(|a| a.to_string())
                    .collect();
                if allowed.is_empty() {
                    continue;
                }
                match groups.iter_mut().find(|(acts, _)| *acts == allowed) {
                    Some((_, locs)) => locs.push(loc.to_string()),
                    None => groups.push((allowed, vec![loc.to_string()])),
                }
            }
            for (acts, locs) in groups {
                out.push(GnapAccessRequest {
                    access_type: req.access_type.clone(),
                    // An empty request list stays empty: the type was the action.
                    actions: if req.actions.is_empty() {
                        Vec::new()
                    } else {
                        acts
                    },
                    locations: if req.locations.is_empty() {
                        Vec::new()
                    } else {
                        locs
                    },
                    // The engine decides (action, location) pairs only. The datatypes, identifier and privileges the
                    // client asked for (RFC 9635 8.2) are not decided by it, so the granted right carries none of
                    // them: copying a client's word into a token would grant what nothing decided.
                    ..Default::default()
                });
            }
        }
        out
    }
}

#[async_trait]
impl GnapAccessPolicy for EngineGnapPolicy {
    async fn grant(
        &self,
        client_key_thumbprint: &str,
        requested: &[GnapAccessRequest],
    ) -> Vec<GnapAccessRequest> {
        self.grant_sync(client_key_thumbprint, requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_control::{ActionRegistry, Effect, Grant, PrincipalKind};

    fn req(t: &str, a: &[&str], l: &[&str]) -> GnapAccessRequest {
        GnapAccessRequest {
            access_type: t.into(),
            actions: a.iter().map(|s| s.to_string()).collect(),
            locations: l.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// The engine decides (action, location) pairs and nothing else. A datatype, identifier or privilege the
    /// client asked for is not something it granted, so a granted right never carries one: the right is what
    /// the engine decided, and no more.
    #[test]
    fn granted_rights_carry_only_what_the_engine_decided() {
        let asked = GnapAccessRequest {
            datatypes: vec!["d1".into()],
            identifier: Some("i1".into()),
            privileges: vec!["p1".into()],
            ..req("doc", &["read"], &["doc:1"])
        };
        let (policy, _) = setup();
        let granted = policy.grant_sync("tp-alice", std::slice::from_ref(&asked));
        // the decided part is granted ...
        assert_eq!(granted.len(), 1);
        assert!(has(&granted, &req("doc", &["read"], &["doc:1"])));
        // ... and none of the three undecided fields is copied from the request
        assert!(granted[0].datatypes.is_empty(), "{:?}", granted[0]);
        assert_eq!(granted[0].identifier, None);
        assert!(granted[0].privileges.is_empty(), "{:?}", granted[0]);
        // control: the same request without the three fields is granted the same right
        let plain = policy.grant_sync("tp-alice", &[req("doc", &["read"], &["doc:1"])]);
        assert_eq!(plain.len(), 1);
        assert!(has(&plain, &req("doc", &["read"], &["doc:1"])));
        // and an (action, location) the engine did not grant stays refused, fields or not
        let denied = GnapAccessRequest {
            privileges: vec!["p1".into()],
            ..req("doc", &["write"], &["doc:1"])
        };
        assert!(policy.grant_sync("tp-alice", &[denied]).is_empty());
    }

    fn key(r: &GnapAccessRequest) -> (String, Vec<String>, Vec<String>) {
        (
            r.access_type.clone(),
            r.actions.clone(),
            r.locations.clone(),
        )
    }

    fn has(out: &[GnapAccessRequest], want: &GnapAccessRequest) -> bool {
        out.iter().any(|r| key(r) == key(want))
    }

    fn setup() -> (EngineGnapPolicy, Arc<RwLock<InMemoryEngine>>) {
        let mut actions = ActionRegistry::new();
        actions.register("read", false);
        actions.register("write", false);
        let mut reg = crate::access_control::PrincipalRegistry::new();
        reg.create("alice", PrincipalKind::Human, None).unwrap();
        reg.add_key("alice", "tp-alice").unwrap();
        let mut e = InMemoryEngine::new(actions).with_principals(reg);
        e.add_grant(Grant::new("g1", "alice", "read", "doc:1", Effect::Allow))
            .unwrap();
        e.add_grant(Grant::new("g2", "alice", "read", "doc:2", Effect::Allow))
            .unwrap();
        e.add_grant(Grant::new("g3", "alice", "write", "doc:2", Effect::Allow))
            .unwrap();
        let e = Arc::new(RwLock::new(e));
        (EngineGnapPolicy::new(e.clone()), e)
    }

    #[test]
    fn acting_context_names_the_agent_and_its_account_holder() {
        let (p, e) = setup();
        {
            let mut g = e.write().unwrap();
            let reg = g.principals_mut().unwrap();
            reg.create("bot", PrincipalKind::Agent, Some("alice"))
                .unwrap();
            reg.add_key("bot", "tp-bot").unwrap();
        }
        let c = p.acting_context("tp-bot").unwrap();
        assert_eq!(c.principal, "bot");
        assert_eq!(c.account_holder, "alice");
        assert_eq!(
            p.acting_context("tp-alice").unwrap().account_holder,
            "alice"
        );
        // fail closed: unknown key, suspended agent
        assert_eq!(p.acting_context("nope"), None);
        e.write()
            .unwrap()
            .principals_mut()
            .unwrap()
            .suspend("bot")
            .unwrap();
        assert_eq!(p.acting_context("tp-bot"), None);
    }

    #[tokio::test]
    async fn returns_only_the_allowed_subset() {
        let (p, _) = setup();
        let out = p
            .grant(
                "tp-alice",
                &[req("doc", &["read", "write"], &["doc:1", "doc:2", "doc:3"])],
            )
            .await;
        assert_eq!(out.len(), 2);
        assert!(has(&out, &req("doc", &["read"], &["doc:1"])));
        assert!(has(&out, &req("doc", &["read", "write"], &["doc:2"])));
    }

    #[tokio::test]
    async fn unknown_key_and_wildcards_get_nothing() {
        let (p, _) = setup();
        assert!(
            p.grant("nobody", &[req("doc", &["read"], &["doc:1"])])
                .await
                .is_empty()
        );
        assert!(
            p.grant("tp-alice", &[req("doc", &["*"], &["doc:1"])])
                .await
                .is_empty()
        );
        assert!(
            p.grant("tp-alice", &[req("doc", &["read"], &["doc:*"])])
                .await
                .is_empty()
        );
        assert!(
            p.grant("tp-alice", &[req("doc", &["read"], &[])])
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn revoked_key_and_suspended_principal_get_nothing() {
        let (p, e) = setup();
        let r = [req("doc", &["read"], &["doc:1"])];
        assert_eq!(p.grant("tp-alice", &r).await.len(), 1);
        e.write()
            .unwrap()
            .principals_mut()
            .unwrap()
            .suspend("alice")
            .unwrap();
        assert!(p.grant("tp-alice", &r).await.is_empty());
        e.write()
            .unwrap()
            .principals_mut()
            .unwrap()
            .resume("alice")
            .unwrap();
        e.write()
            .unwrap()
            .principals_mut()
            .unwrap()
            .revoke_key("alice", "tp-alice")
            .unwrap();
        assert!(p.grant("tp-alice", &r).await.is_empty());
    }

    #[tokio::test]
    async fn deny_grant_removes_a_location() {
        let (p, e) = setup();
        e.write()
            .unwrap()
            .add_grant(Grant::new("d1", "alice", "read", "doc:1", Effect::Deny))
            .unwrap();
        let out = p
            .grant("tp-alice", &[req("doc", &["read"], &["doc:1"])])
            .await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn client_cannot_request_a_wildcard_location_even_under_a_wildcard_rule() {
        let (p, e) = setup();
        e.write()
            .unwrap()
            .add_grant(Grant::new("w", "alice", "read", "pub:*", Effect::Allow))
            .unwrap();
        let ok = p
            .grant("tp-alice", &[req("doc", &["read"], &["pub:a"])])
            .await;
        assert_eq!(ok.len(), 1);
        let wild = p
            .grant("tp-alice", &[req("doc", &["read"], &["pub:*"])])
            .await;
        assert!(wild.is_empty());
    }
}
