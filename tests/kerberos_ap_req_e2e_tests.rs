//! Kerberos AP-REQ end to end (ROADMAP A13, slice 2; design: docs/KERBEROS_E2E_TEST_DESIGN.md).
//!
//! `KerberosManager::authenticate` is an acceptor: it holds a service key and never contacts a
//! KDC. The "KDC" here is the `fixture` module below, which builds and encrypts the structures a
//! KDC and a client would produce, so a token goes through the public API exactly as a browser's
//! `Authorization: Negotiate` header would.
//!
//! The fixture does not call into the crate's own Kerberos code. Its crypto is checked against
//! values copied from the RFCs before any ticket depends on it: the RFC 3962 Appendix B
//! CBC-CTS vectors, the RFC 3961 Appendix A.1 n-fold vectors, and the RFC 3962 Appendix B
//! string-to-key vectors (the final AES key is `DK(PBKDF2 output, "kerberos")`, which exercises
//! the key-derivation function for 128- and 256-bit keys). The usage-key constants
//! (`usage || 0xAA` / `0x55`) take the same code path with a different constant; they have no RFC
//! vector and are covered by the MIT interop slice of the design note.

use auth_framework::protocols::kerberos::{KerberosConfig, KerberosManager};
use base64::Engine as _;

mod fixture {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};

    pub const REALM: &str = "EXAMPLE.TEST";
    pub const SERVICE: [&str; 2] = ["HTTP", "app.example.test"];
    pub const SERVICE_PRINCIPAL: &str = "HTTP/app.example.test@EXAMPLE.TEST";
    pub const KEY_USAGE_TICKET: u32 = 2;
    pub const KEY_USAGE_AP_REQ_AUTH: u32 = 11;
    pub const ETYPE_AES128: i32 = 17;
    pub const ETYPE_AES256: i32 = 18;

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ── Crypto: RFC 3961 / RFC 3962, written from the specifications ──

    fn ecb_encrypt(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
        let mut b = GenericArray::clone_from_slice(block);
        match key.len() {
            16 => aes::Aes128::new(GenericArray::from_slice(key)).encrypt_block(&mut b),
            32 => aes::Aes256::new(GenericArray::from_slice(key)).encrypt_block(&mut b),
            n => panic!("unsupported AES key length {n}"),
        }
        b.into()
    }

    fn gcd(a: usize, b: usize) -> usize {
        if b == 0 { a } else { gcd(b, a % b) }
    }

    /// RFC 3961 section 5.1: replicate the input to lcm(k, n) bits, rotating each copy 13 bits
    /// further right, then add the n-bit chunks with end-around carry.
    pub fn nfold(input: &[u8], out_bytes: usize) -> Vec<u8> {
        let k = input.len() * 8;
        let n = out_bytes * 8;
        let l = k / gcd(k, n) * n;
        let bits: Vec<u8> = input
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect();
        let mut big = Vec::with_capacity(l);
        for copy in 0..l / k {
            let r = (13 * copy) % k;
            for j in 0..k {
                big.push(bits[(j + k - r) % k]);
            }
        }
        let mut acc = vec![0u8; n];
        for chunk in big.chunks(n) {
            let mut carry = 0u8;
            for i in (0..n).rev() {
                let s = acc[i] + chunk[i] + carry;
                acc[i] = s & 1;
                carry = s >> 1;
            }
            let mut i = n;
            while carry == 1 {
                if i == 0 {
                    i = n;
                }
                i -= 1;
                let s = acc[i] + 1;
                acc[i] = s & 1;
                carry = s >> 1;
            }
        }
        acc.chunks(8)
            .map(|b| b.iter().fold(0u8, |v, bit| (v << 1) | bit))
            .collect()
    }

    /// RFC 3961 section 5.3: DK(key, constant) for AES (block size 16, random-to-key is the
    /// identity).
    pub fn dk(key: &[u8], constant: &[u8]) -> Vec<u8> {
        let mut block: [u8; 16] = nfold(constant, 16).try_into().unwrap();
        let mut out = Vec::new();
        while out.len() < key.len() {
            block = ecb_encrypt(key, &block);
            out.extend_from_slice(&block);
        }
        out.truncate(key.len());
        out
    }

    fn usage_key(base: &[u8], usage: u32, tag: u8) -> Vec<u8> {
        let mut c = usage.to_be_bytes().to_vec();
        c.push(tag);
        dk(base, &c)
    }

    /// CBC with ciphertext stealing, zero IV (RFC 3962 section 5, "CBC-CS3"): the last two
    /// ciphertext blocks are swapped, and the result is cut to the plaintext length.
    pub fn cts_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        assert!(plaintext.len() >= 16);
        if plaintext.len() == 16 {
            return ecb_encrypt(key, plaintext.try_into().unwrap()).to_vec();
        }
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let mut prev = [0u8; 16];
        let mut blocks: Vec<[u8; 16]> = Vec::new();
        for chunk in padded.chunks(16) {
            let mut x = [0u8; 16];
            for ((o, c), p) in x.iter_mut().zip(chunk).zip(prev) {
                *o = c ^ p;
            }
            prev = ecb_encrypt(key, &x);
            blocks.push(prev);
        }
        let m = blocks.len();
        blocks.swap(m - 2, m - 1);
        let mut out = blocks.concat();
        out.truncate(plaintext.len());
        out
    }

    fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// `aes*-cts-hmac-sha1-96` encryption (RFC 3962): `CTS(Ke, confounder | plaintext) |
    /// HMAC-SHA1(Ki, confounder | plaintext)[..12]`.
    pub fn encrypt(base: &[u8], usage: u32, plaintext: &[u8], confounder: [u8; 16]) -> Vec<u8> {
        let ke = usage_key(base, usage, 0xAA);
        let ki = usage_key(base, usage, 0x55);
        let mut body = confounder.to_vec();
        body.extend_from_slice(plaintext);
        let mut out = cts_encrypt(&ke, &body);
        out.extend_from_slice(&hmac_sha1(&ki, &body)[..12]);
        out
    }

    // ── DER writer (definite lengths, what a KDC emits) ──

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = content.len();
        if n < 128 {
            v.push(n as u8);
        } else if n < 256 {
            v.extend([0x81, n as u8]);
        } else {
            v.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(content);
        v
    }
    fn int(n: u64) -> Vec<u8> {
        let mut b: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|&x| x == 0)
            .collect();
        if b.is_empty() || b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        tlv(0x02, &b)
    }
    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }
    fn ctx(n: u8, inner: Vec<u8>) -> Vec<u8> {
        tlv(0xa0 | n, &inner)
    }
    fn app(n: u8, inner: Vec<u8>) -> Vec<u8> {
        tlv(0x60 | n, &inner)
    }
    fn gstr(s: &str) -> Vec<u8> {
        tlv(0x1b, s.as_bytes())
    }
    fn octets(b: &[u8]) -> Vec<u8> {
        tlv(0x04, b)
    }
    fn bitstring(b: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(b);
        tlv(0x03, &v)
    }
    fn gtime(secs: u64) -> Vec<u8> {
        let t = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap();
        tlv(0x18, t.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
    }
    fn principal(name_type: u64, parts: &[&str]) -> Vec<u8> {
        let names: Vec<Vec<u8>> = parts.iter().map(|p| gstr(p)).collect();
        seq(&[ctx(0, int(name_type)), ctx(1, seq(&names))])
    }
    fn encrypted_data(etype: i32, kvno: Option<u32>, cipher: &[u8]) -> Vec<u8> {
        let mut f = vec![ctx(0, int(etype as u64))];
        if let Some(k) = kvno {
            f.push(ctx(1, int(k as u64)));
        }
        f.push(ctx(2, octets(cipher)));
        seq(&f)
    }

    // ── What a KDC issues, and what a client sends ──

    /// Ticket flag bits are numbered from the most significant bit (RFC 4120 section 5.3).
    pub const FLAG_FORWARDABLE: u32 = 1;

    #[derive(Clone)]
    pub struct Ticket {
        pub client: String,
        pub crealm: String,
        pub service: Vec<String>,
        pub srealm: String,
        pub etype: i32,
        pub kvno: u32,
        /// The service's long-term key (what the keytab holds).
        pub service_key: Vec<u8>,
        pub session_key: Vec<u8>,
        pub flag_bits: Vec<u32>,
        pub auth_time: u64,
        pub start_time: Option<u64>,
        pub end_time: u64,
    }

    impl Ticket {
        pub fn valid(client: &str, etype: i32, service_key: &[u8]) -> Self {
            let now = now();
            Ticket {
                client: client.to_string(),
                crealm: REALM.to_string(),
                service: SERVICE.iter().map(|s| s.to_string()).collect(),
                srealm: REALM.to_string(),
                etype,
                kvno: 3,
                service_key: service_key.to_vec(),
                session_key: (0..service_key.len() as u8).map(|i| 0xC0 ^ i).collect(),
                flag_bits: vec![FLAG_FORWARDABLE],
                auth_time: now - 60,
                start_time: Some(now - 60),
                end_time: now + 3600,
            }
        }

        fn enc_ticket_part(&self) -> Vec<u8> {
            let mut flags = 0u32;
            for b in &self.flag_bits {
                flags |= 1 << (31 - b);
            }
            let mut f = vec![
                ctx(0, bitstring(&flags.to_be_bytes())),
                ctx(
                    1,
                    seq(&[
                        ctx(0, int(self.etype as u64)),
                        ctx(1, octets(&self.session_key)),
                    ]),
                ),
                ctx(2, gstr(&self.crealm)),
                ctx(3, principal(1, &[&self.client])),
                ctx(4, seq(&[ctx(0, int(0)), ctx(1, octets(b""))])),
                ctx(5, gtime(self.auth_time)),
            ];
            if let Some(s) = self.start_time {
                f.push(ctx(6, gtime(s)));
            }
            f.push(ctx(7, gtime(self.end_time)));
            app(3, seq(&f))
        }

        /// The `Ticket` structure, its `enc-part` encrypted under the service key.
        pub fn der(&self) -> Vec<u8> {
            let cipher = encrypt(
                &self.service_key,
                KEY_USAGE_TICKET,
                &self.enc_ticket_part(),
                [0x5A; 16],
            );
            let svc: Vec<&str> = self.service.iter().map(String::as_str).collect();
            app(
                1,
                seq(&[
                    ctx(0, int(5)),
                    ctx(1, gstr(&self.srealm)),
                    ctx(2, principal(2, &svc)),
                    ctx(3, encrypted_data(self.etype, Some(self.kvno), &cipher)),
                ]),
            )
        }
    }

    /// An AP-REQ carrying `ticket`, with an authenticator encrypted under `auth_key`.
    pub fn ap_req(
        ticket: &Ticket,
        auth_key: &[u8],
        client: &str,
        crealm: &str,
        ctime: u64,
        cusec: u32,
    ) -> Vec<u8> {
        let authenticator = app(
            2,
            seq(&[
                ctx(0, int(5)),
                ctx(1, gstr(crealm)),
                ctx(2, principal(1, &[client])),
                ctx(3, int(cusec as u64)),
                ctx(4, gtime(ctime)),
            ]),
        );
        let auth_cipher = encrypt(auth_key, KEY_USAGE_AP_REQ_AUTH, &authenticator, [0xA5; 16]);
        app(
            14,
            seq(&[
                ctx(0, int(5)),
                ctx(1, int(14)),
                ctx(2, bitstring(&[0, 0, 0, 0])),
                ctx(3, ticket.der()),
                ctx(4, encrypted_data(ticket.etype, None, &auth_cipher)),
            ]),
        )
    }

    /// Wrap an AP-REQ in a SPNEGO `NegTokenInit` offering Kerberos 5.
    pub fn spnego(ap_req: &[u8]) -> Vec<u8> {
        let spnego_oid = tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
        let krb5_oid = tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02],
        );
        let init = tlv(
            0xa0,
            &seq(&[ctx(0, seq(&[krb5_oid])), ctx(2, octets(ap_req))]),
        );
        tlv(0x60, &[spnego_oid, init].concat())
    }

    /// A version-2 keytab holding one key per `(kvno, etype, key)` for the service.
    pub fn keytab(entries: &[(u32, i32, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0x05, 0x02];
        for (kvno, etype, key) in entries {
            let mut e = Vec::new();
            e.extend((SERVICE.len() as u16).to_be_bytes());
            e.extend((REALM.len() as u16).to_be_bytes());
            e.extend(REALM.as_bytes());
            for c in SERVICE {
                e.extend((c.len() as u16).to_be_bytes());
                e.extend(c.as_bytes());
            }
            e.extend(1u32.to_be_bytes()); // name type
            e.extend(0u32.to_be_bytes()); // timestamp
            e.push(*kvno as u8);
            e.extend((*etype as u16).to_be_bytes());
            e.extend((key.len() as u16).to_be_bytes());
            e.extend(key);
            out.extend((e.len() as i32).to_be_bytes());
            out.extend(e);
        }
        out
    }
}

use fixture::*;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── The fixture's crypto against the RFCs ──

#[test]
fn fixture_cts_matches_rfc3962_appendix_b() {
    let key = b"chicken teriyaki";
    let input = b"I would like the General Gau's Chicken, please, and wonton soup.";
    let vectors = [
        (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
        (
            31,
            "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
        ),
        (
            32,
            "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
        ),
        (
            47,
            "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
        ),
        (
            48,
            "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
        ),
        (
            64,
            "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
        ),
    ];
    for (len, expected) in vectors {
        assert_eq!(
            cts_encrypt(key, &input[..len]),
            unhex(expected),
            "RFC 3962 CBC-CTS vector, {len} bytes"
        );
    }
}

#[test]
fn fixture_nfold_matches_rfc3961_appendix_a1() {
    assert_eq!(nfold(b"012345", 8), unhex("be072631276b1955"));
    assert_eq!(nfold(b"password", 7), unhex("78a07b6caf85fa"));
    assert_eq!(
        nfold(b"Rough Consensus, and Running Code", 8),
        unhex("bb6ed30870b7f0e0")
    );
    assert_eq!(
        nfold(b"password", 21),
        unhex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
    );
    assert_eq!(
        nfold(b"kerberos", 16),
        unhex("6b657262 65726f73 7b9b5b2b 93132b93")
    );
    assert_eq!(
        nfold(b"kerberos", 21),
        unhex("8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4")
    );
    assert_eq!(
        nfold(b"Q", 21),
        unhex("518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15")
    );
}

#[test]
fn fixture_key_derivation_matches_rfc3962_string_to_key() {
    // RFC 3962 Appendix B: the AES key is DK(PBKDF2 output, "kerberos").
    let cases = [
        (
            "cdedb5281bb2f801565a1122b2563515",
            "42263c6e89f4fc28b8df68ee09799f15",
        ),
        (
            "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837",
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        ),
        (
            "01dbee7f4a9e243e988b62c73cda935d",
            "c651bf29e2300ac27fa469d693bdda13",
        ),
        (
            "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13",
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
        ),
    ];
    for (tkey, key) in cases {
        assert_eq!(dk(&unhex(tkey), b"kerberos"), unhex(key), "tkey {tkey}");
    }
}

// ── Through the public API ──

const KEY256: [u8; 32] = [
    0x1f, 0x8a, 0x33, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x91, 0xa3, 0xb5, 0xc7, 0xd9, 0xeb, 0xfd, 0x0f,
    0x21, 0x33, 0x45, 0x57, 0x69, 0x7b, 0x8d, 0x9f, 0xa1, 0xb3, 0xc5, 0xd7, 0xe9, 0xfb, 0x0d, 0x1f,
];
const KEY128: [u8; 16] = [
    0x2e, 0x4c, 0x6a, 0x88, 0xa6, 0xc4, 0xe2, 0x00, 0x1e, 0x3c, 0x5a, 0x78, 0x96, 0xb4, 0xd2, 0xf0,
];

/// A manager holding the given keytab entries. The keytab goes through a real file, so
/// `load_keytab` and the keytab parser are part of the path.
async fn manager(tag: &str, entries: &[(u32, i32, Vec<u8>)]) -> KerberosManager {
    let path = std::env::temp_dir().join(format!("af-krb-e2e-{}-{tag}.keytab", std::process::id()));
    std::fs::write(&path, keytab(entries)).unwrap();
    let config = KerberosConfig::builder(SERVICE_PRINCIPAL, REALM).build();
    let mgr = KerberosManager::new(config).unwrap();
    let loaded = mgr.load_keytab(path.to_str().unwrap()).await.unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(loaded, entries.len(), "keytab entries loaded");
    mgr
}

fn b64(token: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(token)
}

#[tokio::test]
async fn a_valid_aes256_ap_req_is_accepted() {
    let mgr = manager("v256", &[(3, ETYPE_AES256, KEY256.to_vec())]).await;
    let ticket = Ticket::valid("alice", ETYPE_AES256, &KEY256);
    let token = ap_req(&ticket, &ticket.session_key, "alice", REALM, now(), 123);

    let result = mgr.authenticate(&b64(&token)).await.expect("valid AP-REQ");
    assert_eq!(result.client_principal, "alice@EXAMPLE.TEST");
    assert_eq!(result.realm, REALM);
    assert_eq!(result.end_time, ticket.end_time);
    assert_eq!(result.auth_time, ticket.auth_time);
    assert!(!result.is_delegated);
}

#[tokio::test]
async fn a_valid_aes128_ap_req_is_accepted() {
    let mgr = manager("v128", &[(3, ETYPE_AES128, KEY128.to_vec())]).await;
    let ticket = Ticket::valid("bob", ETYPE_AES128, &KEY128);
    let token = ap_req(&ticket, &ticket.session_key, "bob", REALM, now(), 7);

    let result = mgr.authenticate(&b64(&token)).await.expect("valid AP-REQ");
    assert_eq!(result.client_principal, "bob@EXAMPLE.TEST");
}

#[tokio::test]
async fn a_valid_ap_req_in_a_spnego_wrapper_is_accepted() {
    let mgr = manager("spnego", &[(3, ETYPE_AES256, KEY256.to_vec())]).await;
    let ticket = Ticket::valid("alice", ETYPE_AES256, &KEY256);
    let raw = ap_req(&ticket, &ticket.session_key, "alice", REALM, now(), 55);

    let wrapped = mgr.authenticate(&b64(&spnego(&raw))).await.expect("SPNEGO");
    assert_eq!(wrapped.client_principal, "alice@EXAMPLE.TEST");
    assert_eq!(wrapped.end_time, ticket.end_time);
}

/// Ciphertext length depends on the client name; names of 1..=20 characters make the ticket body
/// and the authenticator take every residue modulo the AES block size. A body that is an exact
/// multiple of 16 bytes is the case `aes_cts_decrypt` once refused (RFC 3962 swaps the last two
/// blocks then too).
#[tokio::test]
async fn tickets_of_every_length_modulo_the_block_size_are_accepted() {
    for etype_key in [
        (ETYPE_AES256, KEY256.to_vec()),
        (ETYPE_AES128, KEY128.to_vec()),
    ] {
        let (etype, key) = etype_key;
        for len in 1..=20usize {
            let name: String = "abcdefghijklmnopqrst".chars().take(len).collect();
            let mgr = manager(&format!("len{etype}-{len}"), &[(3, etype, key.clone())]).await;
            let ticket = Ticket::valid(&name, etype, &key);
            let token = ap_req(&ticket, &ticket.session_key, &name, REALM, now(), 1);
            let result = mgr.authenticate(&b64(&token)).await;
            assert!(
                result.is_ok(),
                "etype {etype}, client name of {len} characters: {:?}",
                result.err()
            );
        }
    }
}
