//! Google Zanzibar–inspired Relationship-Based Access Control (ReBAC).
//!
//! Implements a tuple-based authorization model where access decisions are derived
//! from relationships between subjects and objects, enabling questions like
//! "does User X own Folder Y that contains Document Z?"
//!
//! # Core Concepts
//!
//! - **Tuple** — `(object, relation, subject)` e.g. `("doc:readme", "viewer", "user:alice")`
//! - **Namespace** — a type of object (e.g. `document`, `folder`, `group`)
//! - **Relation** — named edge between an object and a subject (e.g. `owner`, `viewer`)
//! - **Userset rewrite** — indirect relationships via union, intersection, or computed paths
//!
//! # References
//!
//! - [Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/pub48190/)
//! - [OpenFGA / Zanzibar model](https://openfga.dev/docs/concepts)

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

// ── Relation tuple ──────────────────────────────────────────────────

/// A single relationship tuple: (object, relation, subject).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelationTuple {
    /// Object identifier (e.g. "document:readme").
    pub object: String,
    /// Relation name (e.g. "viewer", "owner", "parent").
    pub relation: String,
    /// Subject — either a direct user ID or a userset reference
    /// (e.g. "user:alice" or "group:engineering#member").
    pub subject: String,
}

impl RelationTuple {
    /// Create a new relation tuple.
    pub fn new(
        object: impl Into<String>,
        relation: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        Self {
            object: object.into(),
            relation: relation.into(),
            subject: subject.into(),
        }
    }

    /// Parse the subject's namespace and optional userset relation.
    ///
    /// `"user:alice"` → `("user", "alice", None)`
    /// `"group:eng#member"` → `("group", "eng", Some("member"))`
    pub fn parse_subject(&self) -> Option<(&str, &str, Option<&str>)> {
        let (ns_id, userset) = if let Some(hash_pos) = self.subject.find('#') {
            (
                &self.subject[..hash_pos],
                Some(&self.subject[hash_pos + 1..]),
            )
        } else {
            (self.subject.as_str(), None)
        };
        let colon_pos = ns_id.find(':')?;
        Some((&ns_id[..colon_pos], &ns_id[colon_pos + 1..], userset))
    }

    /// Parse the object's namespace and ID.
    ///
    /// `"document:readme"` → `("document", "readme")`
    pub fn parse_object(&self) -> Option<(&str, &str)> {
        let pos = self.object.find(':')?;
        Some((&self.object[..pos], &self.object[pos + 1..]))
    }
}

// ── Namespace configuration ─────────────────────────────────────────

/// Defines the valid relations for a namespace and how they compute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceConfig {
    /// Namespace name (e.g. "document").
    pub name: String,
    /// Direct relation definitions.
    pub relations: HashMap<String, RelationDef>,
}

/// Definition of a relation within a namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationDef {
    /// Direct assignment allowed.
    #[serde(default = "default_true")]
    pub direct: bool,
    /// Compute via union of other relation's subjects.
    /// e.g. `viewer` includes all `editor` subjects.
    #[serde(default)]
    pub union: Vec<String>,
    /// Compute via a tuple-to-userset rewrite.
    /// e.g. `viewer` includes `parent#viewer` — traverse the `parent` relation
    /// on the object, then check `viewer` on those parent objects.
    #[serde(default)]
    pub tuple_to_userset: Vec<TupleToUserset>,
}

fn default_true() -> bool {
    true
}

/// A tuple-to-userset rewrite rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TupleToUserset {
    /// The relation to traverse on the current object (e.g. "parent").
    pub tupleset_relation: String,
    /// The relation to check on the resolved object (e.g. "viewer").
    pub computed_userset_relation: String,
}

// ── Zanzibar Store ──────────────────────────────────────────────────

/// In-memory Zanzibar-style relationship store with namespace configuration.
pub struct ZanzibarStore {
    /// Namespace configurations.
    namespaces: Arc<RwLock<HashMap<String, NamespaceConfig>>>,
    /// All stored relation tuples, indexed by object.
    tuples: Arc<RwLock<HashMap<String, Vec<RelationTuple>>>>,
    /// Maximum graph traversal depth to prevent cycles.
    max_depth: usize,
}

impl ZanzibarStore {
    /// Create a new Zanzibar store with the given max traversal depth.
    pub fn new(max_depth: usize) -> Self {
        Self {
            namespaces: Arc::new(RwLock::new(HashMap::new())),
            tuples: Arc::new(RwLock::new(HashMap::new())),
            max_depth,
        }
    }

    /// Register a namespace configuration.
    pub async fn add_namespace(&self, config: NamespaceConfig) {
        self.namespaces
            .write()
            .await
            .insert(config.name.clone(), config);
    }

    /// Write a relation tuple.
    pub async fn write_tuple(&self, tuple: RelationTuple) -> Result<()> {
        // Validate namespace/relation
        if let Some((ns, _)) = tuple.parse_object() {
            let namespaces = self.namespaces.read().await;
            if let Some(ns_config) = namespaces.get(ns) {
                if !ns_config.relations.contains_key(&tuple.relation) {
                    return Err(AuthError::validation(&format!(
                        "Relation '{}' not defined in namespace '{}'",
                        tuple.relation, ns
                    )));
                }
            }
        }

        self.tuples
            .write()
            .await
            .entry(tuple.object.clone())
            .or_default()
            .push(tuple);
        Ok(())
    }

    /// Delete a specific relation tuple.
    pub async fn delete_tuple(&self, tuple: &RelationTuple) -> bool {
        let mut tuples = self.tuples.write().await;
        if let Some(list) = tuples.get_mut(&tuple.object) {
            let before = list.len();
            list.retain(|t| t != tuple);
            list.len() < before
        } else {
            false
        }
    }

    /// Read all tuples for an object, optionally filtered by relation.
    pub async fn read_tuples(&self, object: &str, relation: Option<&str>) -> Vec<RelationTuple> {
        let tuples = self.tuples.read().await;
        match tuples.get(object) {
            Some(list) => {
                if let Some(rel) = relation {
                    list.iter().filter(|t| t.relation == rel).cloned().collect()
                } else {
                    list.clone()
                }
            }
            None => Vec::new(),
        }
    }

    /// **Check** — the core Zanzibar operation.
    ///
    /// Determines whether `subject` has the `relation` on `object` by
    /// traversing direct tuples, union rewrites, and tuple-to-userset paths.
    pub async fn check(&self, object: &str, relation: &str, subject: &str) -> Result<bool> {
        let mut visited = HashSet::new();
        self.check_internal(object, relation, subject, 0, &mut visited)
            .await
    }

    #[allow(clippy::only_used_in_recursion)]
    fn check_internal<'a>(
        &'a self,
        object: &'a str,
        relation: &'a str,
        subject: &'a str,
        depth: usize,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            if depth > self.max_depth {
                return Err(AuthError::internal(
                    "Zanzibar check exceeded maximum traversal depth",
                ));
            }

            let visit_key = format!("{object}#{relation}@{subject}");
            if !visited.insert(visit_key) {
                return Ok(false); // Cycle detected
            }

            // 1. Direct check
            let direct_tuples = self.read_tuples(object, Some(relation)).await;
            for t in &direct_tuples {
                if t.subject == subject {
                    return Ok(true);
                }

                // Userset reference: e.g. subject = "group:eng#member"
                if let Some((_, sub_id, Some(sub_rel))) = t.parse_subject() {
                    let (sub_ns, _) = t.subject.split_once('#').unwrap_or((&t.subject, ""));
                    // Check if `subject` has `sub_rel` on the referenced object
                    if self
                        .check_internal(sub_ns, sub_rel, subject, depth + 1, visited)
                        .await?
                    {
                        let _ = sub_id; // used for the userset resolution
                        return Ok(true);
                    }
                }
            }

            // 2. Union rewrites
            if let Some((ns, _)) = object.split_once(':') {
                let namespaces = self.namespaces.read().await;
                if let Some(ns_config) = namespaces.get(ns) {
                    if let Some(rel_def) = ns_config.relations.get(relation) {
                        // Check union relations
                        for union_rel in &rel_def.union {
                            if self
                                .check_internal(object, union_rel, subject, depth + 1, visited)
                                .await?
                            {
                                return Ok(true);
                            }
                        }

                        // 3. Tuple-to-userset rewrites
                        for ttu in &rel_def.tuple_to_userset {
                            let parent_tuples =
                                self.read_tuples(object, Some(&ttu.tupleset_relation)).await;
                            for pt in &parent_tuples {
                                if self
                                    .check_internal(
                                        &pt.subject,
                                        &ttu.computed_userset_relation,
                                        subject,
                                        depth + 1,
                                        visited,
                                    )
                                    .await?
                                {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
            }

            Ok(false)
        })
    }

    /// **Expand** — list all subjects that have a given relation on an object.
    pub async fn expand(&self, object: &str, relation: &str) -> Result<Vec<String>> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        self.expand_internal(object, relation, 0, &mut result, &mut visited)
            .await?;
        Ok(result)
    }

    fn expand_internal<'a>(
        &'a self,
        object: &'a str,
        relation: &'a str,
        depth: usize,
        result: &'a mut Vec<String>,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if depth > self.max_depth {
                return Ok(());
            }

            let visit_key = format!("{object}#{relation}");
            if !visited.insert(visit_key) {
                return Ok(());
            }

            // Direct subjects
            let tuples = self.read_tuples(object, Some(relation)).await;
            for t in &tuples {
                if t.subject.contains('#') {
                    // Userset: expand the referenced object's relation
                    let (ref_obj, ref_rel) = t.subject.split_once('#').unwrap();
                    self.expand_internal(ref_obj, ref_rel, depth + 1, result, visited)
                        .await?;
                } else if !result.contains(&t.subject) {
                    result.push(t.subject.clone());
                }
            }

            // Union rewrites
            if let Some((ns, _)) = object.split_once(':') {
                let namespaces = self.namespaces.read().await;
                if let Some(ns_config) = namespaces.get(ns) {
                    if let Some(rel_def) = ns_config.relations.get(relation) {
                        for union_rel in &rel_def.union {
                            self.expand_internal(object, union_rel, depth + 1, result, visited)
                                .await?;
                        }
                        for ttu in &rel_def.tuple_to_userset {
                            let parent_tuples =
                                self.read_tuples(object, Some(&ttu.tupleset_relation)).await;
                            for pt in &parent_tuples {
                                self.expand_internal(
                                    &pt.subject,
                                    &ttu.computed_userset_relation,
                                    depth + 1,
                                    result,
                                    visited,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }

            Ok(())
        })
    }

    /// **List objects** — find all objects of a given type where the subject
    /// has the specified relation (reverse lookup, uses BFS).
    pub async fn list_objects(
        &self,
        object_type: &str,
        relation: &str,
        subject: &str,
    ) -> Result<Vec<String>> {
        let prefix = format!("{object_type}:");
        let tuples = self.tuples.read().await;

        let mut found = Vec::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut seen = HashSet::new();

        // Seed: all objects of this type
        for key in tuples.keys() {
            if key.starts_with(&prefix) {
                queue.push_back(key.clone());
            }
        }

        while let Some(obj) = queue.pop_front() {
            if !seen.insert(obj.clone()) {
                continue;
            }
            // We need to release the lock for the async check
            drop(tuples);
            if self.check(&obj, relation, subject).await? {
                found.push(obj);
            }
            // Re-acquire for next iteration is not needed since we already collected keys
            break; // We can't hold tuples across await, so do it differently
        }

        // Simpler approach: collect candidate objects first, then check each
        let candidates: Vec<String> = {
            let tuples = self.tuples.read().await;
            tuples
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect()
        };

        let mut result = Vec::new();
        for obj in candidates {
            if self.check(&obj, relation, subject).await? {
                result.push(obj);
            }
        }
        Ok(result)
    }

    /// Get the count of stored tuples.
    pub async fn tuple_count(&self) -> usize {
        self.tuples.read().await.values().map(|v| v.len()).sum()
    }
}

impl Default for ZanzibarStore {
    fn default() -> Self {
        Self::new(15)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tuple parsing ───────────────────────────────────────────

    #[test]
    fn test_tuple_parse_object() {
        let t = RelationTuple::new("document:readme", "viewer", "user:alice");
        let (ns, id) = t.parse_object().unwrap();
        assert_eq!(ns, "document");
        assert_eq!(id, "readme");
    }

    #[test]
    fn test_tuple_parse_subject_direct() {
        let t = RelationTuple::new("document:readme", "viewer", "user:alice");
        let (ns, id, userset) = t.parse_subject().unwrap();
        assert_eq!(ns, "user");
        assert_eq!(id, "alice");
        assert_eq!(userset, None);
    }

    #[test]
    fn test_tuple_parse_subject_userset() {
        let t = RelationTuple::new("document:readme", "viewer", "group:eng#member");
        let (ns, id, userset) = t.parse_subject().unwrap();
        assert_eq!(ns, "group");
        assert_eq!(id, "eng");
        assert_eq!(userset, Some("member"));
    }

    #[test]
    fn test_tuple_serialization() {
        let t = RelationTuple::new("doc:1", "viewer", "user:alice");
        let json = serde_json::to_string(&t).unwrap();
        let parsed: RelationTuple = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, t);
    }

    // ── Direct check ────────────────────────────────────────────

    #[tokio::test]
    async fn test_direct_relation_check() {
        let store = ZanzibarStore::default();
        store
            .write_tuple(RelationTuple::new(
                "document:readme",
                "viewer",
                "user:alice",
            ))
            .await
            .unwrap();

        assert!(
            store
                .check("document:readme", "viewer", "user:alice")
                .await
                .unwrap()
        );
        assert!(
            !store
                .check("document:readme", "viewer", "user:bob")
                .await
                .unwrap()
        );
        assert!(
            !store
                .check("document:readme", "editor", "user:alice")
                .await
                .unwrap()
        );
    }

    // ── Union relation ──────────────────────────────────────────

    #[tokio::test]
    async fn test_union_relation() {
        let store = ZanzibarStore::default();

        // Configure: viewer includes editor (editors can also view)
        store
            .add_namespace(NamespaceConfig {
                name: "document".to_string(),
                relations: HashMap::from([
                    (
                        "editor".to_string(),
                        RelationDef {
                            direct: true,
                            union: vec![],
                            tuple_to_userset: vec![],
                        },
                    ),
                    (
                        "viewer".to_string(),
                        RelationDef {
                            direct: true,
                            union: vec!["editor".to_string()],
                            tuple_to_userset: vec![],
                        },
                    ),
                ]),
            })
            .await;

        store
            .write_tuple(RelationTuple::new(
                "document:readme",
                "editor",
                "user:alice",
            ))
            .await
            .unwrap();

        // Alice is an editor, viewer includes editor via union
        assert!(
            store
                .check("document:readme", "viewer", "user:alice")
                .await
                .unwrap()
        );
        // Alice is also directly an editor
        assert!(
            store
                .check("document:readme", "editor", "user:alice")
                .await
                .unwrap()
        );
        // Bob has no relation
        assert!(
            !store
                .check("document:readme", "viewer", "user:bob")
                .await
                .unwrap()
        );
    }

    // ── Tuple-to-userset (parent folder) ────────────────────────

    #[tokio::test]
    async fn test_tuple_to_userset() {
        let store = ZanzibarStore::default();

        // Configure: document.viewer includes folder(parent).viewer
        store
            .add_namespace(NamespaceConfig {
                name: "document".to_string(),
                relations: HashMap::from([
                    (
                        "parent".to_string(),
                        RelationDef {
                            direct: true,
                            union: vec![],
                            tuple_to_userset: vec![],
                        },
                    ),
                    (
                        "viewer".to_string(),
                        RelationDef {
                            direct: true,
                            union: vec![],
                            tuple_to_userset: vec![TupleToUserset {
                                tupleset_relation: "parent".to_string(),
                                computed_userset_relation: "viewer".to_string(),
                            }],
                        },
                    ),
                ]),
            })
            .await;

        store
            .add_namespace(NamespaceConfig {
                name: "folder".to_string(),
                relations: HashMap::from([(
                    "viewer".to_string(),
                    RelationDef {
                        direct: true,
                        union: vec![],
                        tuple_to_userset: vec![],
                    },
                )]),
            })
            .await;

        // folder:docs has viewer alice
        store
            .write_tuple(RelationTuple::new("folder:docs", "viewer", "user:alice"))
            .await
            .unwrap();

        // document:readme has parent folder:docs
        store
            .write_tuple(RelationTuple::new(
                "document:readme",
                "parent",
                "folder:docs",
            ))
            .await
            .unwrap();

        // Alice should be able to view document:readme via folder:docs
        assert!(
            store
                .check("document:readme", "viewer", "user:alice")
                .await
                .unwrap()
        );
        // Bob cannot
        assert!(
            !store
                .check("document:readme", "viewer", "user:bob")
                .await
                .unwrap()
        );
    }

    // ── Group membership (userset reference) ────────────────────

    #[tokio::test]
    async fn test_group_membership_userset() {
        let store = ZanzibarStore::default();

        store
            .add_namespace(NamespaceConfig {
                name: "group".to_string(),
                relations: HashMap::from([(
                    "member".to_string(),
                    RelationDef {
                        direct: true,
                        union: vec![],
                        tuple_to_userset: vec![],
                    },
                )]),
            })
            .await;

        store
            .add_namespace(NamespaceConfig {
                name: "document".to_string(),
                relations: HashMap::from([(
                    "viewer".to_string(),
                    RelationDef {
                        direct: true,
                        union: vec![],
                        tuple_to_userset: vec![],
                    },
                )]),
            })
            .await;

        // Alice is a member of group:eng
        store
            .write_tuple(RelationTuple::new("group:eng", "member", "user:alice"))
            .await
            .unwrap();

        // group:eng#member can view document:readme
        store
            .write_tuple(RelationTuple::new(
                "document:readme",
                "viewer",
                "group:eng#member",
            ))
            .await
            .unwrap();

        // Alice can view via group membership
        assert!(
            store
                .check("document:readme", "viewer", "user:alice")
                .await
                .unwrap()
        );
        // Bob cannot
        assert!(
            !store
                .check("document:readme", "viewer", "user:bob")
                .await
                .unwrap()
        );
    }

    // ── Expand ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_expand() {
        let store = ZanzibarStore::default();

        store
            .write_tuple(RelationTuple::new(
                "document:readme",
                "viewer",
                "user:alice",
            ))
            .await
            .unwrap();
        store
            .write_tuple(RelationTuple::new("document:readme", "viewer", "user:bob"))
            .await
            .unwrap();
        store
            .write_tuple(RelationTuple::new(
                "document:readme",
                "editor",
                "user:carol",
            ))
            .await
            .unwrap();

        let viewers = store.expand("document:readme", "viewer").await.unwrap();
        assert_eq!(viewers.len(), 2);
        assert!(viewers.contains(&"user:alice".to_string()));
        assert!(viewers.contains(&"user:bob".to_string()));
    }

    // ── Delete tuple ────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_tuple() {
        let store = ZanzibarStore::default();
        let tuple = RelationTuple::new("document:readme", "viewer", "user:alice");

        store.write_tuple(tuple.clone()).await.unwrap();
        assert!(
            store
                .check("document:readme", "viewer", "user:alice")
                .await
                .unwrap()
        );

        assert!(store.delete_tuple(&tuple).await);
        assert!(
            !store
                .check("document:readme", "viewer", "user:alice")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_delete_nonexistent_tuple() {
        let store = ZanzibarStore::default();
        let tuple = RelationTuple::new("document:readme", "viewer", "user:alice");
        assert!(!store.delete_tuple(&tuple).await);
    }

    // ── Tuple count ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_tuple_count() {
        let store = ZanzibarStore::default();
        assert_eq!(store.tuple_count().await, 0);

        store
            .write_tuple(RelationTuple::new("doc:1", "viewer", "user:a"))
            .await
            .unwrap();
        store
            .write_tuple(RelationTuple::new("doc:2", "viewer", "user:b"))
            .await
            .unwrap();
        assert_eq!(store.tuple_count().await, 2);
    }

    // ── Namespace validation ────────────────────────────────────

    #[tokio::test]
    async fn test_invalid_relation_rejected() {
        let store = ZanzibarStore::default();
        store
            .add_namespace(NamespaceConfig {
                name: "document".to_string(),
                relations: HashMap::from([(
                    "viewer".to_string(),
                    RelationDef {
                        direct: true,
                        union: vec![],
                        tuple_to_userset: vec![],
                    },
                )]),
            })
            .await;

        let result = store
            .write_tuple(RelationTuple::new("document:readme", "admin", "user:alice"))
            .await;
        assert!(result.is_err());
    }

    // ── Cycle protection ────────────────────────────────────────

    #[tokio::test]
    async fn test_cycle_protection() {
        let store = ZanzibarStore::new(5);

        // Create a cycle: group:a member -> group:b#member, group:b member -> group:a#member
        store
            .write_tuple(RelationTuple::new("group:a", "member", "group:b#member"))
            .await
            .unwrap();
        store
            .write_tuple(RelationTuple::new("group:b", "member", "group:a#member"))
            .await
            .unwrap();

        // Should not infinite-loop; returns false (or an error if depth exceeded)
        let result = store.check("group:a", "member", "user:alice").await;
        // Either false or depth error — both are acceptable
        match result {
            Ok(v) => assert!(!v),
            Err(_) => {} // Depth exceeded is fine
        }
    }

    // ── Read tuples ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_read_tuples_with_filter() {
        let store = ZanzibarStore::default();
        store
            .write_tuple(RelationTuple::new("doc:1", "viewer", "user:a"))
            .await
            .unwrap();
        store
            .write_tuple(RelationTuple::new("doc:1", "editor", "user:b"))
            .await
            .unwrap();

        let viewers = store.read_tuples("doc:1", Some("viewer")).await;
        assert_eq!(viewers.len(), 1);
        assert_eq!(viewers[0].subject, "user:a");

        let all = store.read_tuples("doc:1", None).await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_read_tuples_empty() {
        let store = ZanzibarStore::default();
        let result = store.read_tuples("doc:nonexistent", None).await;
        assert!(result.is_empty());
    }
}
