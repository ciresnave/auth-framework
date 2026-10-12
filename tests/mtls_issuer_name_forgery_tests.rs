//! A client certificate must be signed by a trusted CA. It used to be accepted when its ISSUER
//! NAME matched the subject name of a trusted CA, with the signature never verified, so a
//! certificate "issued" by an attacker's own look-alike CA authenticated.

use auth_framework::server::security::mtls::{
    MutualTlsClientConfig, MutualTlsManager, MutualTlsMethod,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = dn(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

fn leaf_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(vec![format!("{cn}.example.test")]).unwrap();
    p.distinguished_name = dn(cn);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    p
}

async fn manager_trusting(root_der: Vec<u8>) -> MutualTlsManager {
    let mut m = MutualTlsManager::new();
    m.add_ca_certificate(root_der).unwrap();
    m.register_client(MutualTlsClientConfig {
        client_id: "client-a".to_string(),
        auth_method: MutualTlsMethod::PkiMutualTls,
        ca_certificates: Vec::new(),
        client_certificate: None,
        expected_subject_dn: Some("CN=client-a".to_string()),
        certificate_bound_access_tokens: false,
    })
    .await
    .unwrap();
    m
}

#[tokio::test]
async fn a_certificate_from_a_look_alike_ca_is_not_accepted() {
    // The CA the server trusts.
    let real_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let real_root = ca_params("Trusted Root")
        .self_signed(&real_key)
        .unwrap()
        .der()
        .to_vec();
    let m = manager_trusting(real_root).await;

    // The attacker's CA: same subject name, different key, not trusted by anyone.
    let fake_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let fake_params = ca_params("Trusted Root");
    fake_params.self_signed(&fake_key).unwrap();
    let fake_issuer = Issuer::new(fake_params, fake_key);
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let forged = leaf_params("client-a")
        .signed_by(&leaf_key, &fake_issuer)
        .unwrap()
        .der()
        .to_vec();

    let result = m.authenticate_client("client-a", &forged).await.unwrap();
    assert!(
        !result.is_valid,
        "a certificate signed by a look-alike CA authenticated: {:?}",
        result.validation_errors
    );
}

#[tokio::test]
async fn a_certificate_from_the_trusted_ca_is_accepted() {
    // Control: the same helpers with the REAL issuer must authenticate, so the test above
    // fails because of the forgery and not because the setup is wrong.
    let real_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params("Trusted Root");
    let root = params
        .clone()
        .self_signed(&real_key)
        .unwrap()
        .der()
        .to_vec();
    let issuer = Issuer::new(params, real_key);
    let m = manager_trusting(root).await;

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = leaf_params("client-a")
        .signed_by(&leaf_key, &issuer)
        .unwrap()
        .der()
        .to_vec();
    let result = m.authenticate_client("client-a", &leaf).await.unwrap();
    assert!(result.is_valid, "{:?}", result.validation_errors);
}
