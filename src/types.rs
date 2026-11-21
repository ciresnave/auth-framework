// SPDX-License-Identifier: MIT OR Apache-2.0
//! Common domain types used throughout the AuthFramework.
//!
//! This module provides type-safe wrappers around raw collections and primitives
//! to improve API clarity and prevent common mistakes.

use std::collections::HashMap;
use std::ops::Deref;

/// A collection of user roles.
///
/// Provides type safety when working with role assignments and prevents
/// accidentally passing the wrong collection type.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::Roles;
///
/// let roles = Roles(vec!["admin".to_string(), "user".to_string()]);
/// assert_eq!(roles.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Roles(pub Vec<String>);

impl Roles {
    /// Create a new Roles collection
    pub fn new(roles: Vec<String>) -> Self {
        Self(roles)
    }

    /// Create an empty Roles collection
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of roles
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific role is present
    pub fn contains(&self, role: &str) -> bool {
        self.0.contains(&role.to_string())
    }

    /// Add a role to the collection
    pub fn push(&mut self, role: String) {
        self.0.push(role);
    }

    /// Iterate over the roles
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for Roles {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for Roles {
    fn from(roles: Vec<String>) -> Self {
        Self(roles)
    }
}

impl From<Roles> for Vec<String> {
    fn from(roles: Roles) -> Vec<String> {
        roles.0
    }
}

impl<S: AsRef<str>> From<&[S]> for Roles {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for Roles {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Roles {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for Roles {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for Roles {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Roles {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(feature = "postgres-storage")]
impl sqlx::Type<sqlx::Postgres> for Roles {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "postgres-storage")]
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Roles {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let inner = <Vec<String> as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        Ok(Self(inner))
    }
}

#[cfg(feature = "postgres-storage")]
impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Roles {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <Vec<String> as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
    }
}

/// A collection of OAuth scopes.
///
/// Provides type safety for scope management and prevents confusion
/// with other string collections.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::Scopes;
///
/// let scopes = Scopes(vec!["read".to_string(), "write".to_string()]);
/// assert!(scopes.contains("read"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Scopes(pub Vec<String>);

impl Scopes {
    /// Create a new Scopes collection
    pub fn new(scopes: Vec<String>) -> Self {
        Self(scopes)
    }

    /// Create an empty Scopes collection
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of scopes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific scope is present
    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(&scope.to_string())
    }

    /// Add a scope to the collection
    pub fn push(&mut self, scope: String) {
        self.0.push(scope);
    }

    /// Iterate over the scopes
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for Scopes {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for Scopes {
    fn from(scopes: Vec<String>) -> Self {
        Self(scopes)
    }
}

impl From<Scopes> for Vec<String> {
    fn from(scopes: Scopes) -> Vec<String> {
        scopes.0
    }
}

impl<S: AsRef<str>> From<&[S]> for Scopes {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for Scopes {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Scopes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for Scopes {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for Scopes {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Scopes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(feature = "postgres-storage")]
impl sqlx::Type<sqlx::Postgres> for Scopes {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "postgres-storage")]
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Scopes {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let inner = <Vec<String> as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        Ok(Self(inner))
    }
}

#[cfg(feature = "postgres-storage")]
impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Scopes {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <Vec<String> as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
    }
}

/// A collection of redirect URIs for OAuth clients.
///
/// Provides type safety for redirect URI management.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::RedirectUris;
///
/// let uris = RedirectUris(vec!["https://example.com/callback".to_string()]);
/// assert!(uris.contains("https://example.com/callback"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RedirectUris(pub Vec<String>);

impl RedirectUris {
    /// Create a new RedirectUris collection
    pub fn new(uris: Vec<String>) -> Self {
        Self(uris)
    }

    /// Create an empty RedirectUris collection
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of URIs
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific URI is present
    pub fn contains(&self, uri: &str) -> bool {
        self.0.contains(&uri.to_string())
    }

    /// Add a URI to the collection
    pub fn push(&mut self, uri: String) {
        self.0.push(uri);
    }

    /// Iterate over the URIs
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for RedirectUris {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for RedirectUris {
    fn from(uris: Vec<String>) -> Self {
        Self(uris)
    }
}

impl From<RedirectUris> for Vec<String> {
    fn from(uris: RedirectUris) -> Vec<String> {
        uris.0
    }
}

impl<S: AsRef<str>> From<&[S]> for RedirectUris {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for RedirectUris {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RedirectUris {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for RedirectUris {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for RedirectUris {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a RedirectUris {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A collection of OAuth grant types.
///
/// Provides type safety for grant type management.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::GrantTypes;
///
/// let types = GrantTypes(vec!["authorization_code".to_string()]);
/// assert!(types.contains("authorization_code"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantTypes(pub Vec<String>);

impl GrantTypes {
    /// Create a new GrantTypes collection
    pub fn new(types: Vec<String>) -> Self {
        Self(types)
    }

    /// Create an empty GrantTypes collection
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of types
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific type is present
    pub fn contains(&self, grant_type: &str) -> bool {
        self.0.contains(&grant_type.to_string())
    }

    /// Add a type to the collection
    pub fn push(&mut self, grant_type: String) {
        self.0.push(grant_type);
    }

    /// Iterate over the types
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for GrantTypes {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for GrantTypes {
    fn from(types: Vec<String>) -> Self {
        Self(types)
    }
}

impl From<GrantTypes> for Vec<String> {
    fn from(types: GrantTypes) -> Vec<String> {
        types.0
    }
}

impl<S: AsRef<str>> From<&[S]> for GrantTypes {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for GrantTypes {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for GrantTypes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for GrantTypes {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for GrantTypes {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a GrantTypes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A collection of OAuth response types.
///
/// Provides type safety for response type management.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::ResponseTypes;
///
/// let types = ResponseTypes(vec!["code".to_string()]);
/// assert!(types.contains("code"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseTypes(pub Vec<String>);

impl ResponseTypes {
    /// Create a new ResponseTypes collection
    pub fn new(types: Vec<String>) -> Self {
        Self(types)
    }

    /// Create an empty ResponseTypes collection
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of types
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific type is present
    pub fn contains(&self, response_type: &str) -> bool {
        self.0.contains(&response_type.to_string())
    }

    /// Add a type to the collection
    pub fn push(&mut self, response_type: String) {
        self.0.push(response_type);
    }

    /// Iterate over the types
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for ResponseTypes {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for ResponseTypes {
    fn from(types: Vec<String>) -> Self {
        Self(types)
    }
}

impl From<ResponseTypes> for Vec<String> {
    fn from(types: ResponseTypes) -> Vec<String> {
        types.0
    }
}

impl<S: AsRef<str>> From<&[S]> for ResponseTypes {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for ResponseTypes {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ResponseTypes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for ResponseTypes {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for ResponseTypes {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ResponseTypes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A collection of permissions.
///
/// Provides type safety for permission management and prevents confusion
/// with other string collections.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::Permissions;
///
/// let perms = Permissions(vec!["user:read".to_string(), "user:write".to_string()]);
/// assert!(perms.contains("user:read"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Permissions(pub Vec<String>);

impl Permissions {
    /// Create a new Permissions collection
    pub fn new(permissions: Vec<String>) -> Self {
        Self(permissions)
    }

    /// Create an empty Permissions collection
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of permissions
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific permission is present
    pub fn contains(&self, permission: &str) -> bool {
        self.0.contains(&permission.to_string())
    }

    /// Add a permission to the collection
    pub fn push(&mut self, permission: String) {
        self.0.push(permission);
    }

    /// Iterate over the permissions
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for Permissions {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for Permissions {
    fn from(permissions: Vec<String>) -> Self {
        Self(permissions)
    }
}

impl From<Permissions> for Vec<String> {
    fn from(permissions: Permissions) -> Vec<String> {
        permissions.0
    }
}

impl<S: AsRef<str>> From<&[S]> for Permissions {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for Permissions {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Permissions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for Permissions {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for Permissions {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Permissions {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(feature = "postgres-storage")]
impl sqlx::Type<sqlx::Postgres> for Permissions {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <Vec<String> as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "postgres-storage")]
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Permissions {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let inner = <Vec<String> as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        Ok(Self(inner))
    }
}

#[cfg(feature = "postgres-storage")]
impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Permissions {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <Vec<String> as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
    }
}

/// User attributes as key-value pairs.
///
/// Provides type safety for user attribute management and prevents confusion
/// with other `HashMap` types.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::UserAttributes;
/// use std::collections::HashMap;
///
/// let mut attrs = HashMap::new();
/// attrs.insert("department".to_string(), "engineering".to_string());
/// let user_attrs = UserAttributes::new(attrs);
/// assert_eq!(user_attrs.get("department"), Some(&"engineering".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserAttributes(pub HashMap<String, String>);

impl UserAttributes {
    /// Creates a new `UserAttributes` from the given map.
    pub fn new(attributes: HashMap<String, String>) -> Self {
        Self(attributes)
    }

    /// Create an empty UserAttributes collection
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    /// Get the number of attributes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get a specific attribute value
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Set an attribute value
    pub fn insert(&mut self, key: String, value: String) -> Option<String> {
        self.0.insert(key, value)
    }

    /// Remove an attribute
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    /// Iterate over the attributes
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, String, String> {
        self.0.iter()
    }
}

impl Default for UserAttributes {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<HashMap<String, String>> for UserAttributes {
    fn from(attributes: HashMap<String, String>) -> Self {
        Self(attributes)
    }
}

impl From<UserAttributes> for HashMap<String, String> {
    fn from(attributes: UserAttributes) -> HashMap<String, String> {
        attributes.0
    }
}

impl Deref for UserAttributes {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for UserAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> IntoIterator for &'a UserAttributes {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::hash_map::Iter<'a, String, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// User attributes as key-value pairs (string values).
///
/// Provides type safety for user attribute management in contexts where
/// string values are expected (e.g., UserContext).
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::UserAttributesString;
/// use std::collections::HashMap;
///
/// let mut attrs = HashMap::new();
/// attrs.insert("department".to_string(), "engineering".to_string());
/// let user_attrs = UserAttributesString(attrs);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserAttributesString(pub HashMap<String, String>);

impl UserAttributesString {
    /// Create a new UserAttributesString collection
    pub fn new(attributes: HashMap<String, String>) -> Self {
        Self(attributes)
    }

    /// Create an empty UserAttributesString collection
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    /// Get the number of attributes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the collection is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get a specific attribute value
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Set an attribute value
    pub fn insert(&mut self, key: String, value: String) -> Option<String> {
        self.0.insert(key, value)
    }

    /// Remove an attribute
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    /// Iterate over the attributes
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, String, String> {
        self.0.iter()
    }
}

impl Default for UserAttributesString {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<HashMap<String, String>> for UserAttributesString {
    fn from(attributes: HashMap<String, String>) -> Self {
        Self(attributes)
    }
}

impl From<UserAttributesString> for HashMap<String, String> {
    fn from(attributes: UserAttributesString) -> HashMap<String, String> {
        attributes.0
    }
}

impl Deref for UserAttributesString {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for UserAttributesString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> IntoIterator for &'a UserAttributesString {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::hash_map::Iter<'a, String, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// IP address whitelist for access control.
///
/// Provides type safety for IP address management with validation.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::IpList;
///
/// let ips = IpList(vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()]);
/// assert!(ips.contains("192.168.1.1"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IpList(pub Vec<String>);

impl IpList {
    /// Create a new IpList
    pub fn new(ips: Vec<String>) -> Self {
        Self(ips)
    }

    /// Create an empty IpList
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the number of IP addresses
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if a specific IP is in the list
    pub fn contains(&self, ip: &str) -> bool {
        self.0.contains(&ip.to_string())
    }

    /// Add an IP to the list
    pub fn push(&mut self, ip: String) {
        self.0.push(ip);
    }

    /// Iterate over the IPs
    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.0.iter()
    }
}

impl Default for IpList {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<String>> for IpList {
    fn from(ips: Vec<String>) -> Self {
        Self(ips)
    }
}

impl From<IpList> for Vec<String> {
    fn from(ips: IpList) -> Vec<String> {
        ips.0
    }
}

impl<S: AsRef<str>> From<&[S]> for IpList {
    fn from(slice: &[S]) -> Self {
        Self(slice.iter().map(|s| s.as_ref().to_owned()).collect())
    }
}

impl Deref for IpList {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for IpList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<String> for IpList {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for IpList {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a IpList {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Custom parameters to include in OAuth authorization requests.
///
/// Wraps a `HashMap<String, String>` for type safety. Commonly used with
/// [`OAuthProviderConfig`](crate::providers::OAuthProviderConfig) to pass
/// provider-specific query parameters.
///
/// # Examples
///
/// ```rust
/// use auth_framework::types::AdditionalParams;
///
/// let mut params = AdditionalParams::new();
/// params.insert("prompt", "consent");
/// params.insert("access_type", "offline");
/// assert_eq!(params.len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct AdditionalParams(pub HashMap<String, String>);

impl AdditionalParams {
    /// Creates an empty parameter set.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Inserts a key-value pair, overwriting any previous value for `key`.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }
}

impl Deref for AdditionalParams {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for AdditionalParams {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> IntoIterator for &'a AdditionalParams {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::hash_map::Iter<'a, String, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<HashMap<String, String>> for AdditionalParams {
    fn from(map: HashMap<String, String>) -> Self {
        Self(map)
    }
}

impl From<AdditionalParams> for HashMap<String, String> {
    fn from(params: AdditionalParams) -> HashMap<String, String> {
        params.0
    }
}
