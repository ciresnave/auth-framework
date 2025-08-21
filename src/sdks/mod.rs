//! SDK Generation Module
//!
//! This module provides SDK generators for multiple programming languages,
//! enabling easy integration of AuthFramework's enhanced RBAC capabilities.

#[cfg(feature = "enhanced-rbac")]
pub mod javascript;

#[cfg(feature = "enhanced-rbac")]
pub mod python;

#[cfg(feature = "enhanced-rbac")]
pub use javascript::{EnhancedSdkConfig as JsConfig, JsSdkGenerator};

#[cfg(feature = "enhanced-rbac")]
pub use python::{PythonSdkConfig, PythonSdkGenerator};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SDK generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkGenerationConfig {
    /// Base API URL
    pub base_url: String,
    /// API version
    pub version: String,
    /// Languages to generate SDKs for
    pub languages: Vec<SdkLanguage>,
    /// Include RBAC functionality
    pub include_rbac: bool,
    /// Include conditional permissions
    pub include_conditional_permissions: bool,
    /// Include audit logging
    pub include_audit: bool,
    /// Custom client names per language
    pub client_names: HashMap<SdkLanguage, String>,
}

/// Supported SDK languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SdkLanguage {
    JavaScript,
    TypeScript,
    Python,
    Rust,
    Go,
    Java,
    CSharp,
}

impl Default for SdkGenerationConfig {
    fn default() -> Self {
        let mut client_names = HashMap::new();
        client_names.insert(SdkLanguage::JavaScript, "AuthFrameworkClient".to_string());
        client_names.insert(SdkLanguage::TypeScript, "AuthFrameworkClient".to_string());
        client_names.insert(SdkLanguage::Python, "AuthFrameworkClient".to_string());

        Self {
            base_url: "https://api.example.com".to_string(),
            version: "v1".to_string(),
            languages: vec![SdkLanguage::TypeScript, SdkLanguage::Python],
            include_rbac: true,
            include_conditional_permissions: true,
            include_audit: true,
            client_names,
        }
    }
}

/// SDK generation result
#[derive(Debug)]
pub struct SdkGenerationResult {
    /// Generated files by language
    pub files: HashMap<SdkLanguage, HashMap<String, String>>,
    /// Generation errors
    pub errors: Vec<SdkGenerationError>,
}

/// SDK generation error
#[derive(Debug, thiserror::Error)]
pub enum SdkGenerationError {
    #[error("Language {0:?} not supported")]
    UnsupportedLanguage(SdkLanguage),
    #[error("Generation failed for {language:?}: {error}")]
    GenerationFailed {
        language: SdkLanguage,
        error: String,
    },
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Multi-language SDK generator
pub struct SdkGenerator {
    config: SdkGenerationConfig,
}

impl SdkGenerator {
    /// Create new SDK generator
    pub fn new(config: SdkGenerationConfig) -> Self {
        Self { config }
    }

    /// Generate SDKs for all configured languages
    pub fn generate_all(&self) -> Result<SdkGenerationResult, Box<dyn std::error::Error>> {
        let mut result = SdkGenerationResult {
            files: HashMap::new(),
            errors: Vec::new(),
        };

        for &language in &self.config.languages {
            match self.generate_for_language(language) {
                Ok(files) => {
                    result.files.insert(language, files);
                }
                Err(error) => {
                    result.errors.push(SdkGenerationError::GenerationFailed {
                        language,
                        error: error.to_string(),
                    });
                }
            }
        }

        Ok(result)
    }

    /// Generate SDK for specific language
    pub fn generate_for_language(
        &self,
        language: SdkLanguage,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        match language {
            #[cfg(feature = "enhanced-rbac")]
            SdkLanguage::JavaScript | SdkLanguage::TypeScript => {
                let js_config = javascript::EnhancedSdkConfig {
                    base_url: self.config.base_url.clone(),
                    version: self.config.version.clone(),
                    typescript: language == SdkLanguage::TypeScript,
                    include_rbac: self.config.include_rbac,
                    include_conditional_permissions: self.config.include_conditional_permissions,
                    include_audit: self.config.include_audit,
                    client_name: self
                        .config
                        .client_names
                        .get(&language)
                        .cloned()
                        .unwrap_or_else(|| "AuthFrameworkClient".to_string()),
                };

                let generator = javascript::JsSdkGenerator::new(js_config);
                generator.generate_sdk()
            }

            #[cfg(feature = "enhanced-rbac")]
            SdkLanguage::Python => {
                let python_config = python::PythonSdkConfig {
                    base_url: self.config.base_url.clone(),
                    version: self.config.version.clone(),
                    include_rbac: self.config.include_rbac,
                    include_conditional_permissions: self.config.include_conditional_permissions,
                    include_audit: self.config.include_audit,
                    client_name: self
                        .config
                        .client_names
                        .get(&language)
                        .cloned()
                        .unwrap_or_else(|| "AuthFrameworkClient".to_string()),
                    async_support: true,
                    type_hints: true,
                };

                let generator = python::PythonSdkGenerator::new(python_config);
                generator.generate_sdk()
            }

            _ => Err(Box::new(SdkGenerationError::UnsupportedLanguage(language))),
        }
    }

    /// Get supported languages
    pub fn supported_languages() -> Vec<SdkLanguage> {
        vec![
            #[cfg(feature = "enhanced-rbac")]
            SdkLanguage::JavaScript,
            #[cfg(feature = "enhanced-rbac")]
            SdkLanguage::TypeScript,
            #[cfg(feature = "enhanced-rbac")]
            SdkLanguage::Python,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_generation_config() {
        let config = SdkGenerationConfig::default();
        assert_eq!(config.version, "v1");
        assert!(config.include_rbac);
        assert!(config.include_conditional_permissions);
        assert!(config.include_audit);
    }

    #[test]
    fn test_supported_languages() {
        let languages = SdkGenerator::supported_languages();
        assert!(!languages.is_empty());
    }

    #[cfg(feature = "enhanced-rbac")]
    #[test]
    fn test_multi_language_generation() {
        let config = SdkGenerationConfig {
            languages: vec![SdkLanguage::TypeScript, SdkLanguage::Python],
            ..Default::default()
        };

        let generator = SdkGenerator::new(config);
        let result = generator.generate_all();

        assert!(result.is_ok());
        let sdk_result = result.unwrap();

        // Should have generated files for both languages
        assert!(sdk_result.files.contains_key(&SdkLanguage::TypeScript));
        assert!(sdk_result.files.contains_key(&SdkLanguage::Python));
    }
}


