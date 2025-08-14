//! Integration tests for WS-Security, SAML, and WS-Trust
//!
//! This test suite validates the complete enterprise authentication stack
//! including WS-Security 1.1, SAML 2.0 assertions, and WS-Trust 1.3 STS.

#[cfg(test)]
mod tests {
    use auth_framework::{
        saml_assertions::{SamlAssertionBuilder, SamlAssertionValidator, SamlNameId, SamlSubject},
        ws_security::{PasswordType, WsSecurityClient, WsSecurityConfig},
        ws_trust::{
            AuthenticationContext, RequestSecurityToken, SecurityTokenService, StsConfig,
            TokenLifetime,
        },
    };
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    #[test]
    fn test_complete_enterprise_auth_flow() {
        // 1. Create SAML Assertion
        let issuer = "https://idp.enterprise.com";
        let subject = "enterprise_user@company.com";
        let audience = "https://app.enterprise.com";
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
            .with_attribute("role", "manager")
            .with_attribute("department", "finance")
            .with_attribute("clearance_level", "confidential")
            .build();

        let assertion_xml = assertion.to_xml().unwrap();

        // Verify SAML assertion contains expected elements
        assert!(assertion_xml.contains("<saml:Assertion"));
        assert!(assertion_xml.contains("enterprise_user@company.com"));
        assert!(assertion_xml.contains("https://app.enterprise.com"));
        assert!(assertion_xml.contains("manager"));
        assert!(assertion_xml.contains("finance"));
        assert!(assertion_xml.contains("confidential"));

        println!("✅ SAML 2.0 Assertion created successfully");

        // 2. Validate SAML Assertion
        let validator = SamlAssertionValidator::new();
        let validation_result = validator.validate(&assertion);
        assert!(validation_result.is_ok());

        println!("✅ SAML 2.0 Assertion validation passed");

        // 3. Create WS-Security Header with SAML
        let ws_config = WsSecurityConfig::default();
        let ws_client = WsSecurityClient::new(ws_config);

        // Create username token header
        let header = ws_client
            .create_username_token_header(
                "ws_user",
                Some("ws_password"),
                PasswordType::PasswordDigest,
            )
            .unwrap();

        let header_xml = ws_client.header_to_xml(&header).unwrap();

        // Verify WS-Security header
        assert!(header_xml.contains("<wsse:Security"));
        assert!(header_xml.contains("<wsse:UsernameToken"));
        assert!(header_xml.contains("ws_user"));
        assert!(header_xml.contains("#PasswordDigest\">"));
        assert!(header_xml.contains("<wsu:Timestamp"));

        println!("✅ WS-Security 1.1 header created successfully");

        // 4. Create WS-Trust STS and issue token
        let sts_config = StsConfig::default();
        let mut sts = SecurityTokenService::new(sts_config);

        let auth_context = AuthenticationContext {
            username: subject.to_string(),
            auth_method: "saml_assertion".to_string(),
            claims: {
                let mut claims = HashMap::new();
                claims.insert("role".to_string(), "manager".to_string());
                claims.insert("department".to_string(), "finance".to_string());
                claims.insert("clearance_level".to_string(), "confidential".to_string());
                claims
            },
        };

        let token_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: Some(audience.to_string()),
            lifetime: Some(TokenLifetime {
                created: now,
                expires: now + Duration::hours(2),
            }),
            key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
            key_size: None,
            existing_token: None,
            auth_context: Some(auth_context),
        };

        let token_response = sts.process_request(token_request).unwrap();

        // Verify token response
        assert_eq!(
            token_response.token_type,
            "urn:oasis:names:tc:SAML:2.0:assertion"
        );
        assert!(
            token_response
                .requested_security_token
                .contains("<saml:Assertion")
        );
        assert!(
            token_response
                .requested_security_token
                .contains("enterprise_user@company.com")
        );
        assert!(
            token_response
                .applies_to
                .as_ref()
                .unwrap()
                .contains("app.enterprise.com")
        );

        println!("✅ WS-Trust 1.3 token issuance successful");

        // 5. Create complete SOAP request with WS-Security and WS-Trust
        let soap_request = sts
            .create_rst_soap_request(&RequestSecurityToken {
                request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
                token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
                applies_to: Some("https://service.enterprise.com".to_string()),
                lifetime: None,
                key_type: Some(
                    "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string(),
                ),
                key_size: None,
                existing_token: None,
                auth_context: None,
            })
            .unwrap();

        // Verify complete SOAP request
        assert!(soap_request.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(soap_request.contains("<soap:Envelope"));
        assert!(soap_request.contains("<wsse:Security"));
        assert!(soap_request.contains("<wst:RequestSecurityToken"));
        assert!(soap_request.contains("https://service.enterprise.com"));
        assert!(soap_request.contains("</soap:Envelope>"));

        println!("✅ Complete SOAP request with WS-Security and WS-Trust created");

        // 6. Test token renewal
        let renewal_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: Some(audience.to_string()),
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some(token_response.requested_unattached_reference.unwrap()),
            auth_context: None,
        };

        let renewal_response = sts.process_request(renewal_request).unwrap();
        assert_eq!(
            renewal_response.token_type,
            "urn:oasis:names:tc:SAML:2.0:assertion"
        );

        println!("✅ WS-Trust token renewal successful");

        println!("\n🎉 Complete Enterprise Authentication Stack Test PASSED!");
        println!("   ✅ SAML 2.0 Assertions");
        println!("   ✅ WS-Security 1.1 Headers");
        println!("   ✅ WS-Trust 1.3 Security Token Service");
        println!("   ✅ SOAP Message Integration");
        println!("   ✅ Token Lifecycle Management");
    }

    #[test]
    fn test_ws_security_password_types() {
        let ws_config = WsSecurityConfig::default();
        let ws_client = WsSecurityClient::new(ws_config);

        // Test PasswordText
        let header_text = ws_client
            .create_username_token_header("user1", Some("password123"), PasswordType::PasswordText)
            .unwrap();

        let xml_text = ws_client.header_to_xml(&header_text).unwrap();
        assert!(xml_text.contains("#PasswordText\">"));
        assert!(xml_text.contains("password123"));

        // Test PasswordDigest
        let header_digest = ws_client
            .create_username_token_header(
                "user1",
                Some("password123"),
                PasswordType::PasswordDigest,
            )
            .unwrap();

        let xml_digest = ws_client.header_to_xml(&header_digest).unwrap();
        assert!(xml_digest.contains("#PasswordDigest\">"));
        assert!(!xml_digest.contains("password123")); // Should be hashed
        assert!(xml_digest.contains("<wsse:Nonce"));

        println!("✅ WS-Security password types test passed");
    }

    #[test]
    fn test_saml_assertion_attributes() {
        let test_subject = SamlSubject {
            name_id: Some(SamlNameId {
                value: "test_user".to_string(),
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
                name_qualifier: None,
                sp_name_qualifier: None,
            }),
            subject_confirmations: vec![],
        };

        let assertion = SamlAssertionBuilder::new("https://test.idp.com")
            .with_subject(test_subject)
            .with_audience("https://test.app.com")
            .with_attribute("email", "test@example.com")
            .with_attribute("role", "admin")
            .with_attribute("groups", "administrators,users")
            .with_attribute("security_clearance", "top_secret")
            .build();

        let xml = assertion.to_xml().unwrap();

        // Verify all attributes are present
        assert!(xml.contains("test@example.com"));
        assert!(xml.contains("admin"));
        assert!(xml.contains("administrators,users"));
        assert!(xml.contains("top_secret"));

        // Verify structure
        assert!(xml.contains("<saml:AttributeStatement>"));
        assert!(xml.contains("<saml:Attribute Name=\"email\""));
        assert!(xml.contains("<saml:Attribute Name=\"role\""));
        assert!(xml.contains("<saml:Attribute Name=\"groups\""));
        assert!(xml.contains("<saml:Attribute Name=\"security_clearance\""));

        println!("✅ SAML assertion attributes test passed");
    }

    #[test]
    fn test_ws_trust_jwt_tokens() {
        let sts_config = StsConfig::default();
        let mut sts = SecurityTokenService::new(sts_config);

        let auth_context = AuthenticationContext {
            username: "jwt_user".to_string(),
            auth_method: "client_certificate".to_string(),
            claims: {
                let mut claims = HashMap::new();
                claims.insert("scope".to_string(), "read write admin".to_string());
                claims.insert("client_id".to_string(), "enterprise_app_123".to_string());
                claims
            },
        };

        let jwt_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            applies_to: Some("https://api.enterprise.com".to_string()),
            lifetime: None,
            key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
            key_size: None,
            existing_token: None,
            auth_context: Some(auth_context),
        };

        let jwt_response = sts.process_request(jwt_request).unwrap();

        assert_eq!(
            jwt_response.token_type,
            "urn:ietf:params:oauth:token-type:jwt"
        );

        // Verify JWT structure (header.payload.signature)
        let jwt_parts: Vec<&str> = jwt_response.requested_security_token.split('.').collect();
        assert_eq!(jwt_parts.len(), 3);

        // Decode and verify payload contains expected claims
        use base64::{Engine, engine::general_purpose};
        let payload_json = general_purpose::URL_SAFE
            .decode(jwt_parts[1])
            .unwrap_or_else(|_| {
                // Fallback to no-pad if padding fails
                general_purpose::URL_SAFE_NO_PAD
                    .decode(jwt_parts[1])
                    .unwrap()
            });
        let payload_str = String::from_utf8(payload_json).unwrap();
        assert!(payload_str.contains("jwt_user"));
        assert!(payload_str.contains("client_certificate"));
        assert!(payload_str.contains("api.enterprise.com"));

        println!("✅ WS-Trust JWT token issuance test passed");
    }

    #[test]
    fn test_token_validation_and_cancellation() {
        let sts_config = StsConfig::default();
        let mut sts = SecurityTokenService::new(sts_config);

        // Issue a token first
        let auth_context = AuthenticationContext {
            username: "validation_user".to_string(),
            auth_method: "password".to_string(),
            claims: HashMap::new(),
        };

        let issue_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: Some("https://validation.test.com".to_string()),
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(auth_context),
        };

        let issue_response = sts.process_request(issue_request).unwrap();
        let token_id = issue_response.requested_unattached_reference.unwrap();

        // Validate the token
        let validate_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some(token_id.clone()),
            auth_context: None,
        };

        let validate_response = sts.process_request(validate_request).unwrap();
        assert!(validate_response.requested_security_token.contains("Valid"));

        // Cancel the token
        let cancel_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some(token_id.clone()),
            auth_context: None,
        };

        let cancel_response = sts.process_request(cancel_request).unwrap();
        assert!(
            cancel_response
                .requested_security_token
                .contains("cancelled")
        );

        println!("✅ Token validation and cancellation test passed");
    }
}
