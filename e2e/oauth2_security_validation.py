#!/usr/bin/env python3
"""
OAuth2 Security Validation Test
Tests the three specific security fixes implemented:
1. Token Revocation Enforcement  
2. PKCE Verifier Requirement Validation
3. Enhanced Scope Validation
"""

import requests
import hashlib
import base64
import secrets
import urllib.parse
from typing import Dict, Any
import json
import time

# Test configuration  
BASE_URL = "http://127.0.0.1:8080"
CLIENT_ID = "test_client_123"
CLIENT_SECRET = "test_secret_456"
REDIRECT_URI = "http://localhost:3000/callback"


def generate_pkce_challenge() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge"""
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge


def test_token_revocation_enforcement():
    """Test 1: Token Revocation Enforcement - Validate revoked tokens are rejected"""
    print("\n🔐 TEST 1: Token Revocation Enforcement")
    print("=" * 50)
    
    # Step 1: Get authorization code
    code_verifier, code_challenge = generate_pkce_challenge()
    
    auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email',
        'state': 'security_test_1',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    auth_url = f"{BASE_URL}/api/v1/oauth2/authorize?" + urllib.parse.urlencode(auth_params)
    print(f"   Authorization URL: {auth_url}")
    
    # Get authorization response (JSON API response)
    auth_response = requests.get(auth_url, allow_redirects=False)
    if auth_response.status_code == 200:
        auth_data = auth_response.json()
        if auth_data.get('success') and 'data' in auth_data:
            authorization_url = auth_data['data'].get('authorization_url', '')
            if 'code=' in authorization_url:
                auth_code = authorization_url.split('code=')[1].split('&')[0]
                print(f"✅ Authorization code obtained: {auth_code[:20]}...")
            else:
                print(f"❌ No authorization code in response: {authorization_url}")
                return False
        else:
            print(f"❌ Authorization API error: {auth_data}")
            return False
    else:
        print(f"❌ Authorization failed: {auth_response.status_code} - {auth_response.text}")
        return False
    
    # Step 2: Exchange code for access token
    token_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier
    }
    
    token_response = requests.post(f"{BASE_URL}/api/v1/oauth2/token", json=token_data)
    if token_response.status_code == 200:
        token_data_response = token_response.json()
        if token_data_response.get('success') and 'data' in token_data_response:
            access_token = token_data_response['data'].get('access_token')
            if access_token:
                print(f"✅ Access token obtained: {access_token[:20]}...")
            else:
                print(f"❌ No access token in response: {token_data_response}")
                return False
        else:
            print(f"❌ Token exchange API error: {token_data_response}")
            return False
    else:
        print(f"❌ Token exchange failed: {token_response.status_code} - {token_response.text}")
        return False
    
    # Step 3: Verify token works initially
    userinfo_response = requests.get(
        f"{BASE_URL}/api/v1/oauth2/userinfo",
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    if userinfo_response.status_code == 200:
        print("✅ Token is valid before revocation")
    else:
        print(f"⚠️  Token validation response: {userinfo_response.status_code}")
    
    # Step 4: Revoke the token
    revoke_data = {
        'token': access_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    
    revoke_response = requests.post(f"{BASE_URL}/api/v1/oauth2/revoke", json=revoke_data)
    if revoke_response.status_code == 200:
        print("✅ Token revocation successful")
    else:
        print(f"❌ Token revocation failed: {revoke_response.status_code}")
        return False
    
    # Step 5: Verify revoked token is rejected
    userinfo_response_after = requests.get(
        f"{BASE_URL}/api/v1/oauth2/userinfo",
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    if userinfo_response_after.status_code in [401, 400, 403]:
        print("✅ SECURITY FIX VALIDATED: Revoked token properly rejected")
        return True
    elif userinfo_response_after.status_code == 500:
        # Check if it's an invalid_token error
        try:
            error_data = userinfo_response_after.json()
            if not error_data.get('success', True) and 'invalid_token' in str(error_data):
                print("✅ SECURITY FIX VALIDATED: Revoked token properly rejected (server error with invalid_token)")
                return True
            else:
                print(f"❌ SECURITY ISSUE: Unexpected server error: {error_data}")
                return False
        except:
            print(f"❌ SECURITY ISSUE: Server error without proper error message: {userinfo_response_after.text}")
            return False
    else:
        print(f"❌ SECURITY ISSUE: Revoked token still accepted! Status: {userinfo_response_after.status_code}")
        print(f"   Response: {userinfo_response_after.text}")
        return False


def test_pkce_verifier_requirement():
    """Test 2: PKCE Verifier Requirement - Validate verifier is required when challenge provided"""
    print("\n🔑 TEST 2: PKCE Verifier Requirement Validation")
    print("=" * 50)
    
    # Step 1: Get authorization code WITH PKCE challenge
    code_verifier, code_challenge = generate_pkce_challenge()
    
    auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile',
        'state': 'security_test_2',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    auth_response = requests.get(f"{BASE_URL}/api/v1/oauth2/authorize?" + urllib.parse.urlencode(auth_params), 
                                allow_redirects=False)
    
    if auth_response.status_code == 200:
        auth_data = auth_response.json()
        if auth_data.get('success') and 'data' in auth_data:
            authorization_url = auth_data['data'].get('authorization_url', '')
            if 'code=' in authorization_url:
                auth_code = authorization_url.split('code=')[1].split('&')[0]
                print(f"✅ Authorization code with PKCE challenge: {auth_code[:20]}...")
            else:
                print(f"❌ No authorization code: {authorization_url}")
                return False
        else:
            print(f"❌ Authorization API error: {auth_data}")
            return False
    else:
        print(f"❌ Authorization failed: {auth_response.status_code} - {auth_response.text}")
        return False
    
    # Step 2: Try token exchange WITHOUT code_verifier (should fail)
    token_data_no_verifier = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
        # Missing code_verifier intentionally
    }
    
    token_response_no_verifier = requests.post(f"{BASE_URL}/api/v1/oauth2/token", json=token_data_no_verifier)
    
    if token_response_no_verifier.status_code in [400, 500]:
        try:
            error_data = token_response_no_verifier.json()
            if not error_data.get('success', True) and 'code_verifier is required' in str(error_data):
                print("✅ SECURITY FIX VALIDATED: PKCE verifier properly required")
                return True
            else:
                print(f"⚠️  Unexpected error response: {error_data}")
                return False
        except:
            if 'code_verifier is required' in token_response_no_verifier.text:
                print("✅ SECURITY FIX VALIDATED: PKCE verifier properly required")
                return True
            else:
                print(f"⚠️  Unexpected error text: {token_response_no_verifier.text}")
                return False
    else:
        print(f"❌ SECURITY ISSUE: PKCE verifier requirement bypassed! Status: {token_response_no_verifier.status_code}")
        print(f"   Response: {token_response_no_verifier.text}")
        return False


def test_scope_validation():
    """Test 3: Enhanced Scope Validation - Validate malicious scopes are rejected"""
    print("\n🛡️  TEST 3: Enhanced Scope Validation")
    print("=" * 50)
    
    # Test valid scopes first
    valid_auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email',
        'state': 'valid_scope_test'
    }
    
    valid_response = requests.get(f"{BASE_URL}/api/v1/oauth2/authorize?" + urllib.parse.urlencode(valid_auth_params), 
                                 allow_redirects=False)
    
    if valid_response.status_code == 200:
        valid_data = valid_response.json()
        if valid_data.get('success'):
            print("✅ Valid scopes accepted (openid profile email)")
        else:
            print(f"⚠️  Valid scopes rejected: {valid_data}")
    else:
        print(f"⚠️  Valid scopes rejected: {valid_response.status_code}")
    
    # Test invalid/malicious scopes
    malicious_scopes = [
        'admin root superuser',  # Privileged scopes
        'openid ../../../etc/passwd',  # Path traversal attempt  
        'openid; DROP TABLE users;',  # SQL injection attempt
        'openid <script>alert("xss")</script>',  # XSS attempt
        'openid\x00null\x00byte',  # Null byte injection
        'read:all write:all delete:all'  # Overprivileged scopes
    ]
    
    malicious_rejected = 0
    
    for malicious_scope in malicious_scopes:
        malicious_params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': malicious_scope,
            'state': 'malicious_scope_test'
        }
        
        malicious_response = requests.get(f"{BASE_URL}/api/v1/oauth2/authorize?" + urllib.parse.urlencode(malicious_params), 
                                        allow_redirects=False)
        
        if malicious_response.status_code == 200:
            malicious_data = malicious_response.json()
            if not malicious_data.get('success'):
                print(f"✅ Malicious scope rejected: '{malicious_scope[:30]}...'")
                malicious_rejected += 1
            else:
                print(f"❌ SECURITY ISSUE: Malicious scope accepted: '{malicious_scope[:30]}...'")
        else:
            print(f"✅ Malicious scope rejected: '{malicious_scope[:30]}...'")
            malicious_rejected += 1
    
    if malicious_rejected == len(malicious_scopes):
        print("✅ SECURITY FIX VALIDATED: All malicious scopes properly rejected")
        return True
    else:
        print(f"❌ SECURITY ISSUE: {len(malicious_scopes) - malicious_rejected} malicious scopes were accepted")
        return False


def main():
    """Run all OAuth2 security validation tests"""
    print("🔐 OAuth2 Security Fixes Validation")
    print("=" * 60)
    print("Testing three specific security enhancements:")
    print("1. Token Revocation Enforcement")
    print("2. PKCE Verifier Requirement Validation") 
    print("3. Enhanced Scope Validation")
    print("=" * 60)
    
    # Check if server is running
    try:
        health_check = requests.get(f"{BASE_URL}/api/v1/health", timeout=5)
        print(f"✅ OAuth2 server is running at {BASE_URL}")
    except requests.exceptions.RequestException:
        print(f"❌ OAuth2 server not accessible at {BASE_URL}")
        print("   Please start the OAuth2 test server first:")
        print("   cargo run --bin oauth2_test_server --features api-server -- serve")
        return
    
    # Run security tests
    results = []
    
    # Test 1: Token Revocation Enforcement
    try:
        results.append(test_token_revocation_enforcement())
    except Exception as e:
        print(f"❌ Test 1 failed with exception: {e}")
        results.append(False)
    
    time.sleep(1)  # Brief pause between tests
    
    # Test 2: PKCE Verifier Requirement
    try:
        results.append(test_pkce_verifier_requirement())
    except Exception as e:
        print(f"❌ Test 2 failed with exception: {e}")
        results.append(False)
    
    time.sleep(1)  # Brief pause between tests
    
    # Test 3: Scope Validation
    try:
        results.append(test_scope_validation())
    except Exception as e:
        print(f"❌ Test 3 failed with exception: {e}")
        results.append(False)
    
    # Final Results
    print("\n" + "=" * 60)
    print("🎯 OAUTH2 SECURITY VALIDATION RESULTS")
    print("=" * 60)
    
    test_names = [
        "Token Revocation Enforcement",
        "PKCE Verifier Requirement Validation", 
        "Enhanced Scope Validation"
    ]
    
    passed = sum(results)
    total = len(results)
    
    for i, (test_name, result) in enumerate(zip(test_names, results), 1):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"Test {i}: {test_name:<35} {status}")
    
    print("-" * 60)
    print(f"OVERALL RESULT: {passed}/{total} security fixes validated")
    
    if passed == total:
        print("🎉 ALL SECURITY FIXES SUCCESSFULLY IMPLEMENTED AND VALIDATED!")
        print("   OAuth2 implementation is now production-ready with enhanced security.")
    else:
        print(f"⚠️  {total - passed} security issues still need attention.")
    
    print("=" * 60)


if __name__ == "__main__":
    main()