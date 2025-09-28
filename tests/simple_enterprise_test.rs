//! Simple test for WS-Security, SAML, and WS-Trust functionality
//!
//! This test validates that our enterprise authentication components work
//! independently of the OAuth modules that have compilation issues.

// Standard library imports for Rust 2024 edition
use std::{
    assert, assert_eq,
    default::Default,
    option::Option::{None, Some},
    println,
    result::Result::{Err, Ok},
    vec,
};

use auth_framework::{
    saml_assertions::{SamlAssertionBuilder, SamlAssertionValidator, SamlNameId, SamlSubject},
    ws_security::{PasswordType, WsSecurityClient, WsSecurityConfig},
    ws_trust::{
        AuthenticationContext, RequestSecurityToken, SecurityTokenService, StsConfig, TokenLifetime,
    },
};
use chrono::{Duration, Utc};
use std::collections::HashMap;

#[test]
fn test_saml_assertion_creation() {
    let issuer = "https://test.idp.com";
    let subject = "test_user@example.com";
    let audience = "https://test.app.com";
    let now = Utc::now();

    let subject_obj = SamlSubject {
        name_id: Some(SamlNameId {
            value: subject.to_string(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress".to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
        }),
        subject_confirmations: vec![],
    };

    let assertion = SamlAssertionBuilder::new(issuer)
        .with_subject(subject_obj)
        .with_audience(audience)
        .with_validity_period(now, now + Duration::hours(1))
        .with_attribute("role", "admin")
        .with_attribute("department", "engineering")
        .build();

    let xml = assertion.to_xml().unwrap();

    // Verify essential elements
    assert!(xml.contains("<saml:Assertion"));
    assert!(xml.contains("test_user@example.com"));
    assert!(xml.contains("https://test.app.com"));
    assert!(xml.contains("admin"));
    assert!(xml.contains("engineering"));

    println!("✅ SAML 2.0 Assertion creation test passed");
}

#[test]
fn test_saml_assertion_validation() {
    let subject_obj = SamlSubject {
        name_id: Some(SamlNameId {
            value: "valid_user".to_string(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
        }),
        subject_confirmations: vec![],
    };

    let assertion = SamlAssertionBuilder::new("https://trusted.idp.com")
        .with_subject(subject_obj)
        .with_audience("https://valid.app.com")
        .with_validity_period(Utc::now(), Utc::now() + Duration::hours(1))
        .build();

    let validator = SamlAssertionValidator::new();
    let result = validator.validate(&assertion);

    assert!(result.is_ok());
    println!("✅ SAML 2.0 Assertion validation test passed");
}

#[test]
fn test_ws_security_username_token() {
    let config = WsSecurityConfig::default();
    let client = WsSecurityClient::new(config);

    // Test PasswordText
    let header_text = client
        .create_username_token_header("testuser", Some("testpass"), PasswordType::PasswordText)
        .unwrap();

    let xml_text = client.header_to_xml(&header_text).unwrap();
    assert!(xml_text.contains("<wsse:Security"));
    assert!(xml_text.contains("testuser"));
    assert!(xml_text.contains("testpass"));
    assert!(xml_text.contains("#PasswordText\">"));

    // Test PasswordDigest
    let header_digest = client
        .create_username_token_header("testuser", Some("testpass"), PasswordType::PasswordDigest)
        .unwrap();

    let xml_digest = client.header_to_xml(&header_digest).unwrap();
    assert!(xml_digest.contains("<wsse:Security"));
    assert!(xml_digest.contains("testuser"));
    assert!(!xml_digest.contains("testpass")); // Should be hashed
    assert!(xml_digest.contains("#PasswordDigest\">"));
    assert!(xml_digest.contains("<wsse:Nonce"));

    println!("✅ WS-Security 1.1 UsernameToken test passed");
}

#[test]
fn test_ws_security_timestamp() {
    let config = WsSecurityConfig::default();
    let client = WsSecurityClient::new(config);

    let header = client
        .create_username_token_header("user", Some("pass"), PasswordType::PasswordText)
        .unwrap();

    let xml = client.header_to_xml(&header).unwrap();

    assert!(xml.contains("<wsu:Timestamp"));
    assert!(xml.contains("<wsu:Created>"));
    assert!(xml.contains("<wsu:Expires>"));

    println!("✅ WS-Security 1.1 Timestamp test passed");
}

#[test]
fn test_ws_trust_saml_token_issuance() {
    let config = StsConfig::default();
    let mut sts = SecurityTokenService::new(config);

    let auth_context = AuthenticationContext {
        username: "enterprise_user".to_string(),
        auth_method: "certificate".to_string(),
        claims: {
            let mut claims = HashMap::new();
            claims.insert("role".to_string(), "manager".to_string());
            claims.insert("clearance".to_string(), "secret".to_string());
            claims
        },
    };

    let request = RequestSecurityToken {
        request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
        token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        applies_to: Some("https://enterprise.app.com".to_string()),
        lifetime: None,
        key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
        key_size: None,
        existing_token: None,
        auth_context: Some(auth_context),
    };

    let response = sts.process_request(request).unwrap();

    assert_eq!(response.token_type, "urn:oasis:names:tc:SAML:2.0:assertion");
    assert!(
        response
            .requested_security_token
            .contains("<saml:Assertion")
    );
    assert!(
        response
            .requested_security_token
            .contains("enterprise_user")
    );
    assert!(response.requested_security_token.contains("manager"));
    assert!(response.requested_security_token.contains("secret"));

    println!("✅ WS-Trust 1.3 SAML token issuance test passed");
}

#[test]
fn test_ws_trust_jwt_token_issuance() {
    let config = StsConfig::default();
    let mut sts = SecurityTokenService::new(config);

    let auth_context = AuthenticationContext {
        username: "api_client".to_string(),
        auth_method: "client_credentials".to_string(),
        claims: {
            let mut claims = HashMap::new();
            claims.insert("scope".to_string(), "read write".to_string());
            claims
        },
    };

    let request = RequestSecurityToken {
        request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
        token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        applies_to: Some("https://api.example.com".to_string()),
        lifetime: None,
        key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
        key_size: None,
        existing_token: None,
        auth_context: Some(auth_context),
    };

    let response = sts.process_request(request).unwrap();

    assert_eq!(response.token_type, "urn:ietf:params:oauth:token-type:jwt");

    // Verify JWT structure
    let jwt_parts: Vec<&str> = response.requested_security_token.split('.').collect();
    assert_eq!(jwt_parts.len(), 3);

    println!("✅ WS-Trust 1.3 JWT token issuance test passed");
}

#[test]
fn test_ws_trust_soap_request_generation() {
    let config = StsConfig::default();
    let sts = SecurityTokenService::new(config);

    let request = RequestSecurityToken {
        request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
        token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        applies_to: Some("https://service.example.com".to_string()),
        lifetime: Some(TokenLifetime {
            created: Utc::now(),
            expires: Utc::now() + Duration::hours(1),
        }),
        key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
        key_size: None,
        existing_token: None,
        auth_context: None,
    };

    let soap_request = sts.create_rst_soap_request(&request).unwrap();

    assert!(soap_request.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(soap_request.contains("<soap:Envelope"));
    assert!(soap_request.contains("<wsse:Security"));
    assert!(soap_request.contains("<wst:RequestSecurityToken"));
    assert!(soap_request.contains("https://service.example.com"));
    assert!(soap_request.contains("</soap:Envelope>"));

    println!("✅ WS-Trust 1.3 SOAP request generation test passed");
}

#[test]
fn test_complete_enterprise_workflow() {
    println!("\n🚀 Testing Complete Enterprise Authentication Workflow");

    // 1. Create SAML assertion for user authentication
    let employee_subject = SamlSubject {
        name_id: Some(SamlNameId {
            value: "employee@corp.com".to_string(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress".to_string()),
            name_qualifier: None,
            sp_name_qualifier: None,
        }),
        subject_confirmations: vec![],
    };

    let assertion = SamlAssertionBuilder::new("https://corp.idp.com")
        .with_subject(employee_subject)
        .with_audience("https://enterprise.app.com")
        .with_validity_period(Utc::now(), Utc::now() + Duration::hours(2))
        .with_attribute("employee_id", "12345")
        .with_attribute("department", "finance")
        .with_attribute("clearance", "confidential")
        .build();

    assert!(assertion.to_xml().unwrap().contains("employee@corp.com"));
    println!("   ✅ Step 1: SAML assertion created");

    // 2. Create WS-Security header for SOAP service call
    let ws_config = WsSecurityConfig::default();
    let ws_client = WsSecurityClient::new(ws_config);

    let header = ws_client
        .create_username_token_header(
            "service_account",
            Some("secure_password"),
            PasswordType::PasswordDigest,
        )
        .unwrap();

    let header_xml = ws_client.header_to_xml(&header).unwrap();
    assert!(header_xml.contains("<wsse:Security"));
    println!("   ✅ Step 2: WS-Security header created");

    // 3. Use WS-Trust STS to exchange SAML for service-specific token
    let config = StsConfig::default();
    let mut sts = SecurityTokenService::new(config);

    let auth_context = AuthenticationContext {
        username: "employee@corp.com".to_string(),
        auth_method: "saml_assertion".to_string(),
        claims: {
            let mut claims = HashMap::new();
            claims.insert("employee_id".to_string(), "12345".to_string());
            claims.insert("department".to_string(), "finance".to_string());
            claims.insert("clearance".to_string(), "confidential".to_string());
            claims
        },
    };

    let token_request = RequestSecurityToken {
        request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
        token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        applies_to: Some("https://finance.service.com".to_string()),
        lifetime: None,
        key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
        key_size: None,
        existing_token: None,
        auth_context: Some(auth_context),
    };

    let token_response = sts.process_request(token_request).unwrap();
    assert!(
        token_response
            .requested_security_token
            .contains("employee@corp.com")
    );
    println!("   ✅ Step 3: Service-specific token issued via WS-Trust");

    // 4. Generate complete SOAP message for service call
    let soap_message = sts
        .create_rst_soap_request(&RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: Some("https://backend.service.com".to_string()),
            lifetime: None,
            key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
            key_size: None,
            existing_token: None,
            auth_context: None,
        })
        .unwrap();

    assert!(soap_message.contains("<soap:Envelope"));
    assert!(soap_message.contains("<wsse:Security"));
    assert!(soap_message.contains("backend.service.com"));
    println!("   ✅ Step 4: Complete SOAP message with security headers");

    println!("\n🎉 Complete Enterprise Authentication Workflow SUCCESSFUL!");
    println!("   📋 SAML 2.0 assertions for identity federation");
    println!("   🔒 WS-Security 1.1 for SOAP message security");
    println!("   🎫 WS-Trust 1.3 for token transformation and issuance");
    println!("   🌐 Full SOAP message generation with security context");
}
