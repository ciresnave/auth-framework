//! Benchmarks for AuthFramework authentication hot paths.
//!
//! These benchmarks measure the latency of the most frequently executed operations
//! in a running auth service:
//!   - Password hashing (Argon2)
//!   - Password verification (Argon2)
//!   - JWT signing (HS256)
//!   - JWT validation (HS256)
//!   - Constant-time token comparison
//!
//! Run with:
//!   cargo bench --bench auth_hot_paths
//!
//! HTML reports are written to `target/criterion/` when the `html_reports` feature
//! is enabled (it is part of the default dev-dependency configuration).

use auth_framework::security::secure_jwt::{SecureJwtClaims, SecureJwtConfig, SecureJwtValidator};
use auth_framework::security::secure_utils::constant_time_compare;
use auth_framework::utils::password::{hash_password_argon2id, verify_password_argon2id};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashSet;
use std::hint::black_box;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helper: build a signed JWT for use in validation benchmarks
// ---------------------------------------------------------------------------

const BENCH_SECRET: &str = "bench-secret-key-must-be-at-least-32-chars-long";

fn make_claims() -> SecureJwtClaims {
    let now = chrono::Utc::now().timestamp();
    SecureJwtClaims {
        sub: "bench-user-001".to_string(),
        iss: "auth-framework".to_string(),
        aud: "bench-audience".to_string(),
        exp: now + 3600,
        nbf: now - 10,
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: "read write".to_string(),
        typ: "access".to_string(),
        sid: None,
        client_id: Some("bench-client".to_string()),
        auth_ctx_hash: None,
    }
}

fn signed_token() -> String {
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(BENCH_SECRET.as_bytes());
    encode(&header, &make_claims(), &key).expect("failed to sign bench token")
}

fn make_validator() -> SecureJwtValidator {
    let mut required_issuers = HashSet::new();
    required_issuers.insert("auth-framework".to_string());

    let config = SecureJwtConfig {
        allowed_algorithms: vec![Algorithm::HS256],
        required_issuers,
        required_audiences: HashSet::new(),
        max_token_lifetime: Duration::from_secs(7200),
        clock_skew: Duration::from_secs(30),
        require_jti: true,
        validate_nbf: true,
        allowed_token_types: {
            let mut s = HashSet::new();
            s.insert("access".to_string());
            s
        },
        require_secure_transport: false, // disabled for bench; no TLS in unit context
        jwt_secret: BENCH_SECRET.to_string(),
        rsa_public_key_pem: None,
        ec_public_key_pem: None,
        ed_public_key_pem: None,
    };
    SecureJwtValidator::new(config).expect("bench JWT config")
}

// ---------------------------------------------------------------------------
// Benchmark: password hashing
// ---------------------------------------------------------------------------

fn bench_password_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_hashing");
    // Argon2 is intentionally slow; reduce sample size to keep total bench time reasonable.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    for password in [
        "short",
        "medium-length-password-123",
        "a-much-longer-passphrase-with-symbols!@#$",
    ] {
        group.bench_with_input(
            BenchmarkId::new("argon2_hash", password.len()),
            password,
            |b, pw| {
                b.iter(|| {
                    let _ = black_box(hash_password_argon2id(black_box(pw)).unwrap());
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: password verification
// ---------------------------------------------------------------------------

fn bench_password_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_verification");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    // Pre-compute hashes so only the verify step is benchmarked.
    let passwords = [
        "short",
        "medium-length-password-123",
        "a-much-longer-passphrase-with-symbols!@#$",
    ];
    let hashes: Vec<(&str, String)> = passwords
        .iter()
        .map(|&pw| (pw, hash_password_argon2id(pw).unwrap()))
        .collect();

    for (pw, hash) in &hashes {
        group.bench_with_input(
            BenchmarkId::new("argon2_verify", pw.len()),
            &(pw, hash.as_str()),
            |b, &(pw, hash)| {
                b.iter(|| {
                    let _ = black_box(verify_password_argon2id(black_box(pw), black_box(hash)).unwrap());
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: JWT signing
// ---------------------------------------------------------------------------

fn bench_jwt_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("jwt");
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(BENCH_SECRET.as_bytes());

    group.bench_function("hs256_sign", |b| {
        b.iter(|| {
            let claims = make_claims();
            let _ =
                black_box(encode(black_box(&header), black_box(&claims), black_box(&key)).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: JWT validation
// ---------------------------------------------------------------------------

fn bench_jwt_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("jwt");
    let validator = make_validator();
    let decoding_key = validator.get_decoding_key();
    let token = signed_token();

    group.bench_function("hs256_validate", |b| {
        b.iter(|| {
            let _ = black_box(
                validator
                    .validate_token(black_box(&token), black_box(&decoding_key))
                    .unwrap(),
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: constant-time token comparison
// ---------------------------------------------------------------------------

fn bench_constant_time_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("security");

    let token_a = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SomeSignatureHere";
    let token_b = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SomeSignatureHere";
    let token_c = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.DifferentSignature";

    group.bench_function("constant_time_compare_equal", |b| {
        b.iter(|| {
            let _ = black_box(constant_time_compare(
                black_box(token_a),
                black_box(token_b),
            ));
        });
    });

    group.bench_function("constant_time_compare_unequal", |b| {
        b.iter(|| {
            let _ = black_box(constant_time_compare(
                black_box(token_a),
                black_box(token_c),
            ));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion configuration
// ---------------------------------------------------------------------------

criterion_group!(
    hot_paths,
    bench_password_hashing,
    bench_password_verification,
    bench_jwt_signing,
    bench_jwt_validation,
    bench_constant_time_compare,
);
criterion_main!(hot_paths);
