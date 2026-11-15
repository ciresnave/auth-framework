// SPDX-License-Identifier: MIT OR Apache-2.0
//! KM7: X.509 certificates for a [`LocalKey`]: a self-signed certificate, a certificate
//! signing request, the `x5t#S256` thumbprint (RFC 7515 section 4.1.8) and a JWK carrying
//! an `x5c` chain (section 4.1.6). The key stays in this process: rcgen builds the
//! certificate from the key's PKCS#8 bytes and nothing is written anywhere.
//!
//! Certificates issued by a CA stay in `server::security::x509_signing`; this module is
//! what a client or server needs to present its own key to a peer or to a CA.

use super::{KeyKind, LocalKey};
use crate::errors::{AuthError, Result};
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
}
