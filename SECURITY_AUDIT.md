# Security Audit Report - Known Issues

This document explains the security advisories that are currently allowed in the AuthFramework project and the rationale for each exception.

## Current Security Exceptions

### RUSTSEC-2023-0071: RSA Marvin Attack (Medium Severity)

**Status**: Temporarily Allowed  
**Affected Crate**: `rsa 0.9.8`  
**Used By**: `sqlx-mysql`, `openidconnect`  
**Issue**: Potential key recovery through timing sidechannels  

**Risk Assessment**: **LOW**
- AuthFramework does not directly expose RSA operations to untrusted input
- The vulnerability requires precise timing measurements which are difficult in network scenarios
- Both `sqlx` and `openidconnect` are essential dependencies with no current alternatives
- No fixed version is available upstream

**Mitigation**:
- Monitor for updates to `sqlx` and `openidconnect` that use patched RSA versions
- AuthFramework's JWT implementation primarily uses HMAC signing by default
- RSA operations are used only for specific advanced configurations

**Tracking**: Will be resolved when upstream dependencies provide fixes

### RUSTSEC-2024-0436: Paste Crate Unmaintained

**Status**: Temporarily Allowed  
**Affected Crate**: `paste 1.0.15`  
**Used By**: `ratatui` → `tui-input` (TUI features only)  
**Issue**: Crate is no longer maintained  

**Risk Assessment**: **VERY LOW**  
- Used only in optional TUI admin interface features
- `paste` is a macro-only crate with minimal security surface
- Functionality is stable and well-tested
- `ratatui` maintainers are working on alternatives

**Mitigation**:
- TUI features are optional and not used in production deployments
- Monitor `ratatui` project for migration to maintained alternatives
- Consider disabling TUI features in security-critical deployments

## Security Policy

1. **Regular Reviews**: Security exceptions are reviewed monthly
2. **Automatic Updates**: Dependencies are updated automatically when fixes become available  
3. **Monitoring**: We actively monitor RustSec advisory database for new issues
4. **Escalation**: High or critical severity issues require immediate attention

## Contact

For security concerns, please see our [Security Policy](SECURITY.md) or contact the maintainers directly.

Last Updated: September 28, 2025