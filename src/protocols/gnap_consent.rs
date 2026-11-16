// SPDX-License-Identifier: MIT OR Apache-2.0
//! Consent records for GNAP (RFC 9635 section 4, "Determining authorization and consent").
//!
//! When a resource owner approves an interactive transaction and the authorization server issues
//! an access token for it, the approval is written down as a [`GnapConsent`]: who approved, which
//! client key was granted what, when, and whether it has since been withdrawn. The record is kept
//! through the [`GnapConsentStore`] trait, so a deployer chooses where it lives;
//! [`InMemoryConsentStore`] is the default and loses its records on restart.
//!
//! A consent record is evidence, not a second policy: it never widens what the
//! [`GnapAccessPolicy`](super::gnap::GnapAccessPolicy) decides, and withdrawing one revokes the
//! tokens it produced (see `GnapService::revoke_consent`).

use super::gnap::GnapAccessRequest;
use crate::errors::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// One approval by a resource owner, as the authorization server recorded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapConsent {
    /// Unique id of this record.
    pub id: String,
    /// The transaction whose approval this is; the tokens it produced carry the same id.
    pub transaction_id: String,
    /// The resource owner who approved, when the integrator named one at approval.
    pub resource_owner: Option<String>,
    /// RFC 7638 thumbprint of the client key the access was granted to.
    pub client_key_thumbprint: String,
    /// What was granted: what the access policy returned, which may be less than was requested.
    pub access: Vec<GnapAccessRequest>,
    /// When the access token was issued (epoch seconds).
    pub granted_at: u64,
    /// When the consent was withdrawn (epoch seconds), `None` while it stands.
    pub revoked_at: Option<u64>,
}

impl GnapConsent {
    /// Whether the consent still stands.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Where consent records are kept.
///
/// An implementation must make `record` durable before it returns `Ok`: the authorization server
/// does not hand out a token whose consent it could not record.
#[async_trait]
pub trait GnapConsentStore: Send + Sync {
    /// Keep a new record. A record with an id already stored is an error, never an overwrite.
    async fn record(&self, consent: GnapConsent) -> Result<()>;

    /// The record with this id, if any.
    async fn get(&self, id: &str) -> Result<Option<GnapConsent>>;

    /// Every record (withdrawn ones included) approved by this resource owner, oldest first.
    async fn list_for_owner(&self, resource_owner: &str) -> Result<Vec<GnapConsent>>;

    /// Mark a record withdrawn at `at`. Returns the record as it now stands, or `None` when no
    /// such record exists. Withdrawing a record twice keeps the first withdrawal time.
    async fn revoke(&self, id: &str, at: u64) -> Result<Option<GnapConsent>>;

    /// Mark every record granted to the client key with this RFC 7638 `thumbprint` withdrawn at
    /// `at` (keeping any earlier withdrawal time) and return those records as they now stand.
    async fn revoke_for_key(&self, thumbprint: &str, at: u64) -> Result<Vec<GnapConsent>>;
}

/// A [`GnapConsentStore`] held in memory.
#[derive(Default)]
pub struct InMemoryConsentStore {
    records: RwLock<HashMap<String, GnapConsent>>,
}

impl std::fmt::Debug for InMemoryConsentStore {
    /// The records hold resource-owner identifiers, so they are not printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryConsentStore")
            .finish_non_exhaustive()
    }
}

impl InMemoryConsentStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GnapConsentStore for InMemoryConsentStore {
    async fn record(&self, consent: GnapConsent) -> Result<()> {
        let mut records = self.records.write().await;
        if records.contains_key(&consent.id) {
            return Err(crate::errors::AuthError::validation(
                "GNAP consent record already exists",
            ));
        }
        records.insert(consent.id.clone(), consent);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<GnapConsent>> {
        Ok(self.records.read().await.get(id).cloned())
    }

    async fn list_for_owner(&self, resource_owner: &str) -> Result<Vec<GnapConsent>> {
        let mut found: Vec<GnapConsent> = self
            .records
            .read()
            .await
            .values()
            .filter(|c| c.resource_owner.as_deref() == Some(resource_owner))
            .cloned()
            .collect();
        found.sort_by(|a, b| (a.granted_at, &a.id).cmp(&(b.granted_at, &b.id)));
        Ok(found)
    }

    async fn revoke(&self, id: &str, at: u64) -> Result<Option<GnapConsent>> {
        let mut records = self.records.write().await;
        Ok(records.get_mut(id).map(|c| {
            c.revoked_at.get_or_insert(at);
            c.clone()
        }))
    }

    async fn revoke_for_key(&self, thumbprint: &str, at: u64) -> Result<Vec<GnapConsent>> {
        let mut records = self.records.write().await;
        let mut found: Vec<GnapConsent> = records
            .values_mut()
            .filter(|c| c.client_key_thumbprint == thumbprint)
            .map(|c| {
                c.revoked_at.get_or_insert(at);
                c.clone()
            })
            .collect();
        found.sort_by(|a, b| (a.granted_at, &a.id).cmp(&(b.granted_at, &b.id)));
        Ok(found)
    }
}
