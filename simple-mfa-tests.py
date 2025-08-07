#!/usr/bin/env python3
"""
Simple MFA Tests - Start with basic commands to test MFA triggers
Test on yourself first before trying on others
"""

import requests
from msal import PublicClientApplication
import json

# ===== CONFIGURATION - UPDATE THESE =====
TENANT_ID = "your-tenant.onmicrosoft.com"  # or your tenant GUID
CLIENT_ID = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph default, or your app ID
YOUR_EMAIL = "your.email@domain.com"  # Your own email to test with

# ===== TEST 1: Simple Authentication =====
def test_basic_auth():
    """
    Step 1: Just authenticate yourself and see what permissions you get
    """
    print("\n===== TEST 1: Basic Authentication =====")
    print("Let's see what permissions you have...\n")
    
    app = PublicClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}"
    )
    
    # Start with minimal scopes
    scopes = ["User.Read"]
    
    # Device code flow - no password needed
    flow = app.initiate_device_flow(scopes=scopes)
    
    print(f"1. Go to: {flow['verification_uri']}")
    print(f"2. Enter code: {flow['user_code']}")
    print(f"3. Sign in with your work account\n")
    
    # Wait for auth
    result = app.acquire_token_by_device_flow(flow)
    
    if "access_token" in result:
        print("✅ Authenticated successfully!")
        token = result["access_token"]
        
        # Test what we can see about ourselves
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers=headers
        )
        
        if response.status_code == 200:
            user_data = response.json()
            print(f"Logged in as: {user_data.get('displayName')}")
            print(f"Email: {user_data.get('userPrincipalName')}")
        
        return token
    else:
        print(f"❌ Authentication failed: {result.get('error')}")
        return None

# ===== TEST 2: Check Your Own MFA Methods =====
def test_check_mfa_methods(token, user_email=None):
    """
    Step 2: See what MFA methods are registered for a user
    """
    print("\n===== TEST 2: Check MFA Methods =====")
    
    if not user_email:
        user_email = YOUR_EMAIL
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try the authentication methods endpoint
    endpoints = [
        f"https://graph.microsoft.com/v1.0/users/{user_email}/authentication/methods",
        f"https://graph.microsoft.com/beta/users/{user_email}/authentication/methods",
        f"https://graph.microsoft.com/beta/me/authentication/methods"
    ]
    
    for url in endpoints:
        print(f"\nTrying: {url}")
        response = requests.get(url, headers=headers)
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ SUCCESS! Found MFA methods:")
            
            if "value" in data:
                for method in data["value"]:
                    method_type = method.get("@odata.type", "unknown").split(".")[-1]
                    print(f"  - {method_type}")
                    
                    # Show relevant details
                    if "phoneNumber" in method:
                        print(f"    Phone: {method.get('phoneNumber')}")
                    if "displayName" in method:
                        print(f"    Device: {method.get('displayName')}")
                        
                return data
        elif response.status_code == 403:
            print("❌ Access denied - need different permissions")
        elif response.status_code == 404:
            print("❌ Endpoint not found")
    
    return None

# ===== TEST 3: Try Simple MFA Trigger =====
def test_trigger_mfa_simple(token, user_email=None):
    """
    Step 3: Try the simplest possible MFA trigger methods
    """
    print("\n===== TEST 3: Simple MFA Trigger Attempts =====")
    
    if not user_email:
        user_email = YOUR_EMAIL
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Test 1: Try to create a sign-in request
    print("\n1. Testing sign-in request...")
    url = f"https://graph.microsoft.com/beta/users/{user_email}/authentication/operations"
    
    response = requests.get(url, headers=headers)
    print(f"   Can read operations? Status: {response.status_code}")
    
    # Test 2: Try the temporaryAccessPass endpoint (might work for self)
    print("\n2. Testing temporary access pass...")
    url = f"https://graph.microsoft.com/beta/users/{user_email}/authentication/temporaryAccessPassMethods"
    
    response = requests.get(url, headers=headers)
    print(f"   Can read TAP? Status: {response.status_code}")
    
    if response.status_code == 200:
        print("   ✅ Can read TAP methods!")
        # Try to create one (probably will fail without admin)
        tap_data = {
            "isUsableOnce": True,
            "lifetimeInMinutes": 60
        }
        create_response = requests.post(url, json=tap_data, headers=headers)
        print(f"   Can create TAP? Status: {create_response.status_code}")
        if create_response.status_code in [200, 201]:
            print("   ✅ WOW! Can create temporary access pass!")
            print(f"   Response: {create_response.json()}")
    
    # Test 3: Check if we can see recent authentications
    print("\n3. Checking recent authentication activity...")
    url = f"https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userPrincipalName eq '{user_email}'&$top=1"
    
    response = requests.get(url, headers=headers)
    print(f"   Can read sign-ins? Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get("value"):
            latest = data["value"][0]
            print(f"   Last sign-in: {latest.get('createdDateTime')}")
            print(f"   MFA required: {latest.get('isMultiFactorAuthentication')}")

# ===== TEST 4: Test Microsoft Authenticator Push =====
def test_authenticator_push(token, user_email=None):
    """
    Step 4: Specifically test Microsoft Authenticator push methods
    """
    print("\n===== TEST 4: Microsoft Authenticator Push Test =====")
    
    if not user_email:
        user_email = YOUR_EMAIL
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # First, find Microsoft Authenticator methods
    print("\n1. Looking for Authenticator app registrations...")
    url = f"https://graph.microsoft.com/beta/users/{user_email}/authentication/microsoftAuthenticatorMethods"
    
    response = requests.get(url, headers=headers)
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get("value"):
            print(f"   ✅ Found {len(data['value'])} authenticator app(s)")
            
            for auth_method in data["value"]:
                device_name = auth_method.get("displayName", "Unknown device")
                method_id = auth_method.get("id")
                print(f"\n   Device: {device_name}")
                print(f"   ID: {method_id}")
                
                # Try to trigger a push to this device
                if method_id:
                    print(f"   Attempting to trigger push...")
                    
                    # Try different endpoints that might work
                    push_endpoints = [
                        f"{url}/{method_id}/challenge",
                        f"{url}/{method_id}/verify",
                        f"https://graph.microsoft.com/beta/users/{user_email}/authentication/operations"
                    ]
                    
                    for endpoint in push_endpoints:
                        print(f"   Trying: {endpoint.split('/')[-1]}...")
                        
                        # For operations endpoint, need different payload
                        if "operations" in endpoint:
                            payload = {
                                "challengeType": "microsoftAuthenticatorPush",
                                "targetMethodId": method_id
                            }
                        else:
                            payload = {}
                        
                        push_response = requests.post(endpoint, json=payload, headers=headers)
                        print(f"      Status: {push_response.status_code}")
                        
                        if push_response.status_code in [200, 201, 202]:
                            print(f"      ✅ SUCCESS! Push might have been sent!")
                            print(f"      Response: {push_response.json()}")
                            print(f"      CHECK YOUR PHONE for Microsoft Authenticator notification!")
                            return True
                        elif push_response.status_code == 403:
                            print(f"      ❌ Access denied")
        else:
            print("   No authenticator apps found")
    
    return False

# ===== TEST 5: Test Passwordless Phone Sign-in =====
def test_passwordless_signin(token, user_email=None):
    """
    Step 5: Test if passwordless phone sign-in can be triggered
    """
    print("\n===== TEST 5: Passwordless Phone Sign-in Test =====")
    
    if not user_email:
        user_email = YOUR_EMAIL
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Check for passwordless methods
    print("\n1. Checking for passwordless methods...")
    url = f"https://graph.microsoft.com/beta/users/{user_email}/authentication/passwordlessMicrosoftAuthenticatorMethods"
    
    response = requests.get(url, headers=headers)
    print(f"   Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        if data.get("value"):
            print(f"   ✅ Passwordless is configured!")
            
            for method in data["value"]:
                method_id = method.get("id")
                print(f"   Method ID: {method_id}")
                
                # Try to initiate passwordless sign-in
                if method_id:
                    challenge_url = f"{url}/{method_id}/challenge"
                    print(f"   Attempting passwordless challenge...")
                    
                    challenge_response = requests.post(challenge_url, headers=headers)
                    print(f"   Status: {challenge_response.status_code}")
                    
                    if challenge_response.status_code in [200, 201, 202]:
                        print("   ✅ Passwordless challenge sent! Check your phone!")
                        return True
        else:
            print("   No passwordless methods configured")
    
    return False

# ===== MAIN TEST RUNNER =====
def run_simple_tests():
    """
    Run all simple tests in sequence
    """
    print("""
╔══════════════════════════════════════════════════════════════╗
║          SIMPLE MFA TRIGGER TESTS - TEST ON YOURSELF        ║
╚══════════════════════════════════════════════════════════════╝

This will run simple tests to see if we can trigger MFA.
We'll test on YOUR account first before trying on others.

Make sure you have:
1. Updated the configuration variables at the top
2. Your phone with Microsoft Authenticator ready
3. Your work account credentials
""")
    
    input("\nPress Enter to start...")
    
    # Test 1: Authenticate
    token = test_basic_auth()
    
    if not token:
        print("\n❌ Cannot proceed without authentication")
        return
    
    input("\n✅ Authenticated! Press Enter to check your MFA methods...")
    
    # Test 2: Check MFA methods
    mfa_methods = test_check_mfa_methods(token)
    
    input("\nPress Enter to try triggering MFA to yourself...")
    
    # Test 3: Simple trigger attempts
    test_trigger_mfa_simple(token)
    
    input("\nPress Enter to test Microsoft Authenticator push...")
    
    # Test 4: Authenticator push
    push_sent = test_authenticator_push(token)
    
    if push_sent:
        print("\n🎉 Push notification might have been sent! Check your phone!")
        time.sleep(5)  # Give time to check phone
    
    input("\nPress Enter to test passwordless sign-in...")
    
    # Test 5: Passwordless
    passwordless_sent = test_passwordless_signin(token)
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print("""
Based on the tests above:
1. Can you see MFA methods? (Important for verification)
2. Did any push notifications work? (Key for the solution)
3. Can you read sign-in logs? (Needed to verify MFA completion)

If any MFA trigger worked on yourself, try changing the 
user_email parameter to test with another user.

Next steps:
- If push worked: Build the full solution around that
- If only read worked: Need IT to provide unlock service
- If nothing worked: Need different approach or permissions
""")

# ===== QUICK TEST FOR ANOTHER USER =====
def quick_test_other_user(token, other_user_email):
    """
    Quick test to see if you can trigger MFA for another user
    """
    print(f"\n===== TESTING MFA TRIGGER FOR: {other_user_email} =====")
    
    # Check their MFA methods
    print("\n1. Checking their MFA methods...")
    test_check_mfa_methods(token, other_user_email)
    
    # Try to trigger push
    print("\n2. Attempting push notification...")
    test_authenticator_push(token, other_user_email)
    
    print("\n3. Attempting passwordless...")
    test_passwordless_signin(token, other_user_email)
    
    print(f"\nDone testing for {other_user_email}")
    print("Ask them if they received any notifications!")

# ===== ENTRY POINT =====
if __name__ == "__main__":
    import sys
    import time
    
    # Check if testing specific user
    if len(sys.argv) > 1 and sys.argv[1] == "--test-other":
        print("First, authenticate yourself...")
        token = test_basic_auth()
        if token and len(sys.argv) > 2:
            other_email = sys.argv[2]
            quick_test_other_user(token, other_email)
        else:
            print("Usage: python script.py --test-other user@domain.com")
    else:
        # Run full test suite on yourself
        run_simple_tests()
                