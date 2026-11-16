// SPDX-License-Identifier: MIT OR Apache-2.0
//! KM7: X.509 certificates for a [`LocalKey`]: a self-signed certificate, a certificate
//! signing request, the `x5t#S256` thumbprint (RFC 7515 section 4.1.8) and a JWK carrying
//! an `x5c` chain (section 4.1.6). The key stays in this process: rcgen builds the
//! certificate from the key's PKCS#8 bytes and nothing is written anywhere.
//!
//! Certificates issued by a CA stay in `server::security::x509_signing`; this module is
//! what a client or server needs to present its own key to a peer or to a CA.

use super::{KeyKind, LocalKey, spki_pem};
use crate::errors::{AuthError, Result};
use crate::server::security::x509_signing::{
    CertificateRequest, CertificateSubject as CaSubject, SubjectAltName,
};
use base64::Engine;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Who a certificate or request is for.
#[derive(Debug, Clone)]
pub struct CertSubject {
    /// Subject common name.
    pub common_name: String,
    /// DNS subject alternative names (may be empty).
    pub dns_names: Vec<String>,
    /// How long a self-signed certificate is valid from now; ignored by a request.
    pub valid_for: Duration,
}

fn key_pair(key: &LocalKey) -> Result<KeyPair> {
    // TLS and signing kinds only: an encryption key is not a certificate key.
    if !matches!(
        key.kind(),
        KeyKind::Mtls
            | KeyKind::JwsSigning
            | KeyKind::GnapClient
            | KeyKind::Dpop
            | KeyKind::HttpSig
    ) {
        return Err(AuthError::validation(format!(
            "{:?} is not a certificate key kind",
            key.kind()
        )));
    }
    KeyPair::try_from(key.to_pkcs8_der())
        .map_err(|e| AuthError::crypto(format!("key cannot back a certificate: {e}")))
}

fn params(subject: &CertSubject) -> Result<CertificateParams> {
    if subject.common_name.trim().is_empty() {
        return Err(AuthError::validation("a certificate needs a common name"));
    }
    let mut p = CertificateParams::new(subject.dns_names.clone())
        .map_err(|e| AuthError::validation(format!("bad subject alternative name: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject.common_name.clone());
    p.distinguished_name = dn;
    Ok(p)
}

/// A self-signed end-entity certificate for `key`, PEM encoded, valid from now for
/// `subject.valid_for` (which must be at least a minute and at most ten years).
pub fn self_signed_certificate(key: &LocalKey, subject: &CertSubject) -> Result<String> {
    let secs = subject.valid_for.as_secs();
    if !(60..=10 * 366 * 24 * 3600).contains(&secs) {
        return Err(AuthError::validation(
            "certificate validity must be between one minute and ten years",
        ));
    }
    let pair = key_pair(key)?;
    let mut p = params(subject)?;
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::minutes(1);
    p.not_after = now + time::Duration::seconds(secs as i64);
    let cert = p
        .self_signed(&pair)
        .map_err(|e| AuthError::crypto(format!("self-signing failed: {e}")))?;
    Ok(cert.pem())
}

/// A PKCS#10 certificate signing request for `key`, PEM encoded, to send to a CA.
pub fn certificate_signing_request(key: &LocalKey, subject: &CertSubject) -> Result<String> {
    let pair = key_pair(key)?;
    let p = params(subject)?;
    p.serialize_request(&pair)
        .and_then(|r| r.pem())
        .map_err(|e| AuthError::crypto(format!("request signing failed: {e}")))
}

fn pem_der(pem: &str) -> Result<Vec<u8>> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| AuthError::validation("not a PEM certificate"))?;
    if parsed.label != "CERTIFICATE" {
        return Err(AuthError::validation("PEM block is not a CERTIFICATE"));
    }
    Ok(parsed.contents)
}

/// The `x5t#S256` value of a PEM certificate: base64url of the SHA-256 of its DER.
pub fn x5t_s256(certificate_pem: &str) -> Result<String> {
    let der = pem_der(certificate_pem)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&der)))
}

/// The public JWK of `key` with an `x5c` array holding `certificate_pem` and its
/// `x5t#S256`. Refused when the certificate does not certify this key, so a JWK can never
/// advertise another key's certificate.
pub fn jwk_with_x5c(key: &LocalKey, certificate_pem: &str) -> Result<Value> {
    let der = pem_der(certificate_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|_| AuthError::validation("not a valid X.509 certificate"))?;
    let spki = key_pair(key)?.subject_public_key_info();
    if cert.tbs_certificate.subject_pki.raw != spki.as_slice() {
        return Err(AuthError::validation(
            "the certificate does not certify this key",
        ));
    }
    let mut jwk = key.public().to_value();
    jwk["x5c"] = json!([base64::engine::general_purpose::STANDARD.encode(&der)]);
    jwk["x5t#S256"] =
        json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&der)));
    Ok(jwk)
}

fn ca_request(
    common_name: &str,
    dns_names: Vec<String>,
    public_key_pem: String,
    profile: &str,
    requester: &str,
) -> Result<CertificateRequest> {
    if common_name.trim().is_empty() {
        return Err(AuthError::validation("a certificate needs a common name"));
    }
    Ok(CertificateRequest {
        request_id: format!("req-{}", uuid::Uuid::new_v4().simple()),
        subject: CaSubject {
            common_name: common_name.to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
            email: None,
        },
        profile: profile.to_string(),
        public_key_pem,
        subject_alt_names: dns_names.into_iter().map(SubjectAltName::DnsName).collect(),
        requested_at: chrono::Utc::now(),
        requester: requester.to_string(),
        attributes: std::collections::HashMap::new(),
    })
}

/// A request for the certificate authority in `server::security::x509_signing` to certify
/// `key`, ready for `X509CertificateManager::sign_certificate_request`. The caller holds
/// `key`, so no proof of possession is needed; a request that arrives from someone else
/// must go through [`certificate_request_from_csr`] instead. The authority still applies its
/// own profile, name and key policy and the caller still decides who may ask.
pub fn certificate_request_for_key(
    key: &LocalKey,
    subject: &CertSubject,
    profile: &str,
    requester: &str,
) -> Result<CertificateRequest> {
    let spki = key_pair(key)?.subject_public_key_info();
    ca_request(
        &subject.common_name,
        subject.dns_names.clone(),
        spki_pem(&spki),
        profile,
        requester,
    )
}

/// Turn a PKCS#10 request received from a client into a CA request **after verifying its
/// signature**, which proves the client holds the private key for the public key it asks
/// to have certified (`sign_certificate_request` takes a bare public key and checks no
/// such thing). Only the subject common name, the DNS subject alternative names and the
/// public key are taken; a request that asks for any other kind of name (IP address, e-mail,
/// URI) or has no single common name is refused rather than partly honoured. The caller must
/// still authenticate and authorise the requester and the names.
pub fn certificate_request_from_csr(
    csr_pem: &str,
    profile: &str,
    requester: &str,
) -> Result<CertificateRequest> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::FromDer;
    let (_, block) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())
        .map_err(|_| AuthError::validation("not a PEM certificate request"))?;
    if block.label != "CERTIFICATE REQUEST" && block.label != "NEW CERTIFICATE REQUEST" {
        return Err(AuthError::validation(
            "PEM block is not a CERTIFICATE REQUEST",
        ));
    }
    let (rest, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&block.contents)
            .map_err(|_| AuthError::validation("not a valid PKCS#10 request"))?;
    if !rest.is_empty() {
        return Err(AuthError::validation("trailing data after the request"));
    }
    csr.verify_signature().map_err(|_| {
        AuthError::validation("the request's signature does not verify: no proof of possession")
    })?;
    let info = &csr.certification_request_info;
    let mut names = info.subject.iter_common_name();
    let common_name = match (names.next(), names.next()) {
        (Some(cn), None) => cn
            .as_str()
            .map_err(|_| AuthError::validation("the common name is not text"))?
            .to_string(),
        _ => {
            return Err(AuthError::validation(
                "the request must carry exactly one common name",
            ));
        }
    };
    let mut dns_names = Vec::new();
    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(dns) => dns_names.push((*dns).to_string()),
                        _ => {
                            return Err(AuthError::validation(
                                "only DNS subject alternative names are supported",
                            ));
                        }
                    }
                }
            }
        }
    }
    ca_request(
        &common_name,
        dns_names,
        spki_pem(info.subject_pki.raw),
        profile,
        requester,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningAlg;
    use x509_parser::prelude::*;

    fn key(alg: SigningAlg) -> LocalKey {
        LocalKey::generate(KeyKind::Mtls, alg, None).unwrap()
    }

    fn subject() -> CertSubject {
        CertSubject {
            common_name: "client.example".into(),
            dns_names: vec!["client.example".into(), "alt.example".into()],
            valid_for: Duration::from_secs(3600),
        }
    }

    #[test]
    fn a_self_signed_certificate_names_the_subject_certifies_the_key_and_verifies() {
        for alg in [SigningAlg::Es256, SigningAlg::EdDsa, SigningAlg::Rs256] {
            let k = key(alg);
            let pem = self_signed_certificate(&k, &subject()).unwrap();
            let der = pem_der(&pem).unwrap();
            let (_, cert) = parse_x509_certificate(&der).unwrap();
            assert_eq!(
                cert.subject()
                    .iter_common_name()
                    .next()
                    .unwrap()
                    .as_str()
                    .unwrap(),
                "client.example",
                "{alg:?}"
            );
            let sans = cert.subject_alternative_name().unwrap().unwrap();
            assert_eq!(sans.value.general_names.len(), 2);
            let window =
                cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
            assert_eq!(
                window,
                3600 + 60,
                "{alg:?}: one hour plus the one-minute back-dating"
            );
            assert!(
                cert.verify_signature(None).is_ok(),
                "self-signature verifies for {alg:?}"
            );
            assert_eq!(
                cert.tbs_certificate.subject_pki.raw,
                key_pair(&k).unwrap().subject_public_key_info().as_slice(),
                "{alg:?}: certifies this key"
            );
        }
    }

    #[test]
    fn a_signing_request_carries_the_subject_and_its_proof_of_possession_verifies() {
        for alg in [SigningAlg::Es256, SigningAlg::EdDsa, SigningAlg::Rs256] {
            let k = key(alg);
            let pem = certificate_signing_request(&k, &subject()).unwrap();
            let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
            assert_eq!(block.label, "CERTIFICATE REQUEST");
            let (_, csr) = X509CertificationRequest::from_der(&block.contents).unwrap();
            assert_eq!(
                csr.certification_request_info
                    .subject
                    .iter_common_name()
                    .next()
                    .unwrap()
                    .as_str()
                    .unwrap(),
                "client.example"
            );
            assert!(csr.verify_signature().is_ok(), "{alg:?}");
        }
    }

    #[test]
    fn x5t_s256_is_the_sha256_of_the_der_and_the_jwk_carries_x5c_and_it() {
        let k = key(SigningAlg::Es256);
        let pem = self_signed_certificate(&k, &subject()).unwrap();
        let der = pem_der(&pem).unwrap();
        let want = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&der));
        assert_eq!(x5t_s256(&pem).unwrap(), want);
        let jwk = jwk_with_x5c(&k, &pem).unwrap();
        assert_eq!(jwk["x5t#S256"], want.as_str());
        let x5c = jwk["x5c"][0].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(x5c)
                .unwrap(),
            der
        );
        assert_eq!(jwk["kty"], "EC");
        assert!(jwk.get("d").is_none(), "no private member");
    }

    #[test]
    fn a_jwk_refuses_a_certificate_for_another_key() {
        let a = key(SigningAlg::Es256);
        let b = key(SigningAlg::Es256);
        let pem_b = self_signed_certificate(&b, &subject()).unwrap();
        assert!(jwk_with_x5c(&a, &pem_b).is_err());
        assert!(jwk_with_x5c(&b, &pem_b).is_ok());
    }

    #[test]
    fn bad_input_is_refused() {
        let k = key(SigningAlg::Es256);
        let mut s = subject();
        s.common_name = "  ".into();
        assert!(
            self_signed_certificate(&k, &s).is_err(),
            "empty common name"
        );
        assert!(certificate_signing_request(&k, &s).is_err());
        let mut s = subject();
        s.valid_for = Duration::from_secs(5);
        assert!(self_signed_certificate(&k, &s).is_err(), "too short");
        s.valid_for = Duration::from_secs(11 * 366 * 24 * 3600);
        assert!(self_signed_certificate(&k, &s).is_err(), "too long");
        assert!(x5t_s256("not pem").is_err());
        assert!(
            x5t_s256("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").is_err(),
            "wrong block type"
        );
    }

    #[test]
    fn a_tls_key_can_be_generated_and_an_encryption_key_still_cannot() {
        assert!(LocalKey::generate(KeyKind::Mtls, SigningAlg::Es256, None).is_ok());
        assert!(LocalKey::generate(KeyKind::JweEncryption, SigningAlg::Es256, None).is_err());
    }

    use crate::server::security::x509_signing::{
        CertificateProfile, CertificateType, EcdsaCurve, ExtendedKeyUsage, KeyType, KeyUsage,
        SanPolicy, X509CertificateManager, X509Config,
    };

    /// A manager over a throwaway root CA, with one ECDSA P-256 client profile.
    async fn ca(dir: &std::path::Path) -> X509CertificateManager {
        use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256};
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, "Test Root");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = p.self_signed(&ca_key).unwrap();
        let (cert_path, key_path) = (dir.join("root.crt"), dir.join("root.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, ca_key.serialize_pem()).unwrap();
        let mut config = X509Config {
            root_ca_path: cert_path.to_string_lossy().to_string(),
            root_ca_cert_path: cert_path.to_string_lossy().to_string(),
            root_ca_key_path: key_path.to_string_lossy().to_string(),
            ..X509Config::default()
        };
        config.certificate_profiles.insert(
            "client_ec".to_string(),
            CertificateProfile {
                name: "client_ec".to_string(),
                cert_type: CertificateType::TlsClient,
                key_usage: vec![KeyUsage::DigitalSignature],
                extended_key_usage: vec![ExtendedKeyUsage::ClientAuth],
                subject_alt_names: vec![],
                san_policy: SanPolicy::default(),
                validity_days: 30,
                preferred_key_type: KeyType::Ecdsa(EcdsaCurve::P256),
                extensions: std::collections::HashMap::new(),
            },
        );
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        manager
    }

    #[tokio::test]
    async fn a_ca_certifies_a_local_key_through_a_request_built_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let manager = ca(dir.path()).await;
        let k = key(SigningAlg::Es256);
        let req = certificate_request_for_key(&k, &subject(), "client_ec", "tester").unwrap();
        assert_eq!(req.subject.common_name, "client.example");
        assert_eq!(req.subject_alt_names.len(), 2);
        let issued = manager
            .sign_certificate_request(&req, "root_ca")
            .await
            .unwrap();
        let der = pem_der(&issued.certificate_pem).unwrap();
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        assert_eq!(
            cert.tbs_certificate.subject_pki.raw,
            key_pair(&k).unwrap().subject_public_key_info().as_slice(),
            "the issued certificate certifies this key"
        );
        assert!(
            jwk_with_x5c(&k, &issued.certificate_pem).is_ok(),
            "and publishes through x5c"
        );
        let mut bad = subject();
        bad.common_name = " ".into();
        assert!(certificate_request_for_key(&k, &bad, "client_ec", "t").is_err());
    }

    #[tokio::test]
    async fn a_verified_csr_becomes_a_request_the_ca_signs_for_the_requesters_key() {
        let dir = tempfile::tempdir().unwrap();
        let manager = ca(dir.path()).await;
        let k = key(SigningAlg::Es256);
        let csr = certificate_signing_request(&k, &subject()).unwrap();
        let req = certificate_request_from_csr(&csr, "client_ec", "tester").unwrap();
        assert_eq!(req.subject.common_name, "client.example");
        let mut dns: Vec<String> = req
            .subject_alt_names
            .iter()
            .map(|n| match n {
                SubjectAltName::DnsName(d) => d.clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        dns.sort();
        assert_eq!(dns, vec!["alt.example", "client.example"]);
        let issued = manager
            .sign_certificate_request(&req, "root_ca")
            .await
            .unwrap();
        assert!(jwk_with_x5c(&k, &issued.certificate_pem).is_ok());
    }

    #[test]
    fn a_csr_whose_signature_does_not_verify_is_refused() {
        let k = key(SigningAlg::Es256);
        let csr = certificate_signing_request(&k, &subject()).unwrap();
        assert!(certificate_request_from_csr(&csr, "p", "t").is_ok());
        let (_, block) = x509_parser::pem::parse_x509_pem(csr.as_bytes()).unwrap();
        let mut der = block.contents.clone();
        let at = der
            .windows(14)
            .position(|w| w == b"client.example")
            .expect("the common name is in the request");
        der[at] = b'd';
        let tampered = format!(
            "-----BEGIN CERTIFICATE REQUEST-----
{}
-----END CERTIFICATE REQUEST-----
",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        let err = certificate_request_from_csr(&tampered, "p", "t")
            .unwrap_err()
            .to_string();
        assert!(err.contains("proof of possession"), "{err}");
    }

    #[test]
    fn a_csr_with_other_name_types_or_no_single_common_name_is_refused() {
        use rcgen::SanType;
        let k = key(SigningAlg::Es256);
        let pair = key_pair(&k).unwrap();
        let mut ip = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "client.example");
        ip.distinguished_name = dn;
        ip.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
        let csr = ip.serialize_request(&pair).unwrap().pem().unwrap();
        assert!(
            certificate_request_from_csr(&csr, "p", "t").is_err(),
            "an IP name is not silently dropped"
        );
        let mut none = CertificateParams::new(Vec::<String>::new()).unwrap();
        none.distinguished_name = DistinguishedName::new();
        let csr = none.serialize_request(&pair).unwrap().pem().unwrap();
        assert!(
            certificate_request_from_csr(&csr, "p", "t").is_err(),
            "no common name"
        );
        assert!(certificate_request_from_csr("not pem", "p", "t").is_err());
        let cert = self_signed_certificate(&k, &subject()).unwrap();
        assert!(
            certificate_request_from_csr(&cert, "p", "t").is_err(),
            "a certificate is not a request"
        );
    }
}
