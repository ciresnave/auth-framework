# Kerberos / SPNEGO Deployment Guide

This guide covers deploying AuthFramework with Kerberos (SPNEGO) authentication for enterprise Single Sign-On through Active Directory or MIT Kerberos.

## Prerequisites

- A working Kerberos realm (Active Directory or MIT KDC)
- A service principal registered for the AuthFramework server
- A keytab file generated for the service principal
- Network access from the AuthFramework host to the KDC (TCP/UDP 88)
- Time synchronization (NTP) between all hosts

## Configuration

### KerberosConfig Fields

| Field                      | Type             | Default  | Description                                                      |
| -------------------------- | ---------------- | -------- | ---------------------------------------------------------------- |
| `service_principal`        | `String`         | —        | Service principal name, e.g. `HTTP/auth.example.com@EXAMPLE.COM` |
| `realm`                    | `String`         | —        | Kerberos realm, e.g. `EXAMPLE.COM`                               |
| `keytab_path`              | `Option<String>` | `None`   | Path to the keytab file on disk                                  |
| `kdc_addresses`            | `Vec<String>`    | `[]`     | **Deprecated, unused.** Validation is offline; no KDC is contacted |
| `max_clock_skew_secs`      | `u64`            | `300`    | Maximum clock skew tolerance in seconds                          |
| `allow_delegation`         | `bool`           | `false`  | Allow forwarded/delegated tickets                                |
| `replay_cache_max_entries` | `usize`          | `100000` | Maximum entries in the replay cache                              |

### Example Configuration

Preferred — use the builder:

```rust
use auth_framework::protocols::kerberos::KerberosConfig;

let config = KerberosConfig::builder(
        "HTTP/auth.example.com@EXAMPLE.COM",
        "EXAMPLE.COM",
    )
    .keytab_path("/etc/krb5/auth-framework.keytab")
    .build();
```

For Active Directory environments:

```rust
let config = KerberosConfig::active_directory(
    "HTTP/auth.example.com@CORP.EXAMPLE.COM",
    "CORP.EXAMPLE.COM",
);
```

Manual struct construction is still supported:

```rust
use auth_framework::protocols::kerberos::KerberosConfig;

let config = KerberosConfig {
    service_principal: "HTTP/auth.example.com@EXAMPLE.COM".to_string(),
    realm: "EXAMPLE.COM".to_string(),
    keytab_path: Some("/etc/krb5/auth-framework.keytab".to_string()),
    max_clock_skew_secs: 300,
    allow_delegation: false,
    replay_cache_max_entries: 100_000,
};
```

## Active Directory Setup

### 1. Create a Service Account

```powershell
# On the Domain Controller
New-ADUser -Name "svc-authframework" `
    -SamAccountName "svc-authframework" `
    -UserPrincipalName "svc-authframework@EXAMPLE.COM" `
    -AccountPassword (ConvertTo-SecureString "StrongPassword!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true
```

### 2. Register the Service Principal Name (SPN)

```powershell
setspn -S HTTP/auth.example.com svc-authframework
```

### 3. Generate the Keytab File

```powershell
ktpass -princ HTTP/auth.example.com@EXAMPLE.COM `
    -mapuser svc-authframework@EXAMPLE.COM `
    -pass "StrongPassword!" `
    -crypto AES256-SHA1 `
    -ptype KRB5_NT_PRINCIPAL `
    -out auth-framework.keytab
```

Transfer the keytab to the AuthFramework host securely and set appropriate permissions:

```bash
chmod 600 /etc/krb5/auth-framework.keytab
chown authframework:authframework /etc/krb5/auth-framework.keytab
```

### 4. Verify the Keytab

```bash
klist -kt /etc/krb5/auth-framework.keytab
```

## MIT Kerberos Setup

### 1. Add the Service Principal

```bash
kadmin -q "addprinc -randkey HTTP/auth.example.com@EXAMPLE.COM"
kadmin -q "ktadd -k /etc/krb5/auth-framework.keytab HTTP/auth.example.com@EXAMPLE.COM"
```

### 2. Configure `/etc/krb5.conf`

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    clockskew = 300

[realms]
    EXAMPLE.COM = {
        kdc = kdc1.example.com
        kdc = kdc2.example.com
        admin_server = kdc1.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

## SPNEGO Authentication Flow

1. Client sends a request without credentials
2. Server responds with `401 Unauthorized` and `WWW-Authenticate: Negotiate`
3. Client obtains a Kerberos service ticket from the KDC
4. Client sends the ticket as a Base64 SPNEGO token in `Authorization: Negotiate <token>`
5. AuthFramework validates the token using `KerberosAuthenticator::authenticate()`
6. On success, returns `KerberosAuthResult` with the client principal and ticket details

### Authenticating a Request

```rust
let spnego_token_b64 = "YIIBh..."; // from Authorization header
let result = authenticator.authenticate(spnego_token_b64).await?;

println!("Authenticated: {}", result.client_principal);
println!("Realm: {}", result.realm);
println!("Delegated: {}", result.is_delegated);
```

## Security Considerations

- **Keytab Protection**: The keytab is equivalent to a password. Store it with minimal permissions (`0600`) and restrict access.
- **Clock Synchronization**: Kerberos relies on synchronized clocks. Use NTP with a maximum drift under the configured `max_clock_skew_secs`.
- **Replay Protection**: The built-in replay cache prevents token replay attacks. Adjust `replay_cache_max_entries` for high-traffic deployments.
- **Delegation**: Only enable `allow_delegation` if downstream services require the user's Kerberos identity. Constrained delegation (S4U2Proxy) is preferred over unconstrained.
- **Encryption Types**: Use AES256-SHA1 or stronger. Avoid RC4-HMAC (arcfour) in new deployments.

## Troubleshooting

| Symptom                | Likely Cause                  | Solution                                                          |
| ---------------------- | ----------------------------- | ----------------------------------------------------------------- |
| `ClockSkew` error      | Time desynchronization        | Verify NTP is running; increase `max_clock_skew_secs` temporarily |
| `KeyNotFound` error    | Wrong keytab or SPN mismatch  | Verify SPN with `klist -kt`; ensure hostname matches              |
| `ReplayDetected` error | Duplicate token submission    | Expected behavior — client should retry with a fresh ticket       |
| `InvalidToken` error   | Corrupted or truncated Base64 | Check that the full `Authorization` header value is passed        |
