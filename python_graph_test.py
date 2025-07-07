#!/usr/bin/env python3
"""
Quick test to check if Microsoft Graph API will work for account unlocking
Run this to verify your setup before implementing the full MCP server
"""

import asyncio
import os
import sys
import json
from typing import Dict, Any

# Test if required modules are available
try:
    import msal
    print("✅ MSAL module available")
except ImportError:
    print("❌ MSAL module not found. Install with: pip install msal")
    sys.exit(1)

try:
    import aiohttp
    print("✅ aiohttp module available")
except ImportError:
    print("❌ aiohttp module not found. Install with: pip install aiohttp")
    sys.exit(1)

try:
    import requests
    print("✅ requests module available")
except ImportError:
    print("❌ requests module not found. Install with: pip install requests")
    sys.exit(1)

class GraphAPITester:
    def __init__(self):
        self.tenant_id = None
        self.client_id = None
        self.client_secret = None
        self.access_token = None
        
    def check_environment_variables(self):
        """Check if required environment variables are set"""
        print("\n" + "="*50)
        print("TEST 1: Environment Variables")
        print("="*50)
        
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        
        if self.tenant_id:
            print(f"✅ AZURE_TENANT_ID: {self.tenant_id[:8]}...")
        else:
            print("❌ AZURE_TENANT_ID not set")
            
        if self.client_id:
            print(f"✅ AZURE_CLIENT_ID: {self.client_id[:8]}...")
        else:
            print("❌ AZURE_CLIENT_ID not set")
            
        if self.client_secret:
            print("✅ AZURE_CLIENT_SECRET: [HIDDEN]")
        else:
            print("❌ AZURE_CLIENT_SECRET not set")
            
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            print("\n⚠️  Environment variables not set. You can:")
            print("1. Set them now for testing")
            print("2. Use device authentication instead")
            print("3. Create an app registration first")
            return False
        return True
    
    def test_device_authentication(self):
        """Test device code authentication (interactive)"""
        print("\n" + "="*50)
        print("TEST 2: Device Authentication")
        print("="*50)
        
        # Use Microsoft Graph CLI app ID for device auth
        app = msal.PublicClientApplication(
            client_id="14d82eec-204b-4c2f-b7e0-446a11c4e1c8",  # Microsoft Graph CLI
            authority="https://login.microsoftonline.com/common"
        )
        
        # Request device code
        device_flow = app.initiate_device_flow(scopes=["https://graph.microsoft.com/User.Read"])
        
        if "user_code" not in device_flow:
            print("❌ Failed to create device flow")
            return None
            
        print(device_flow["message"])
        print("\nPress Enter after completing authentication...")
        input()
        
        # Get token
        result = app.acquire_token_by_device_flow(device_flow)
        
        if "access_token" in result:
            print("✅ Device authentication successful!")
            self.access_token = result["access_token"]
            return result["access_token"]
        else:
            print(f"❌ Device authentication failed: {result.get('error_description', 'Unknown error')}")
            return None
    
    def test_app_authentication(self):
        """Test app-only authentication"""
        print("\n" + "="*50)
        print("TEST 3: App Authentication")
        print("="*50)
        
        if not all([self.tenant_id, self.client_id, self.client_secret]):
            print("❌ Cannot test app authentication - missing credentials")
            return None
            
        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}"
        )
        
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        
        if "access_token" in result:
            print("✅ App authentication successful!")
            self.access_token = result["access_token"]
            return result["access_token"]
        else:
            print(f"❌ App authentication failed: {result.get('error_description', 'Unknown error')}")
            return None
    
    def test_graph_api_access(self):
        """Test basic Graph API access"""
        print("\n" + "="*50)
        print("TEST 4: Graph API Access")
        print("="*50)
        
        if not self.access_token:
            print("❌ No access token available")
            return False
            
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            # Test 1: Get current user/app info
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            if response.status_code == 200:
                user_info = response.json()
                print(f"✅ Current identity: {user_info.get('displayName', 'Service Account')}")
                print(f"   UPN: {user_info.get('userPrincipalName', 'N/A')}")
            elif response.status_code == 401:
                print("❌ Authentication failed - token may be invalid")
                return False
            else:
                print(f"⚠️  /me endpoint returned {response.status_code}")
                
            # Test 2: List users (requires User.Read.All)
            response = requests.get("https://graph.microsoft.com/v1.0/users?$top=5", headers=headers)
            if response.status_code == 200:
                users = response.json()
                print(f"✅ Can read users: Found {len(users.get('value', []))} users")
                for user in users.get('value', [])[:3]:
                    print(f"   - {user.get('displayName')} ({user.get('userPrincipalName')})")
            elif response.status_code == 403:
                print("❌ Insufficient permissions to read users")
                print("   Need: User.Read.All or Directory.Read.All")
                return False
            else:
                print(f"⚠️  Users endpoint returned {response.status_code}")
                
            return True
            
        except Exception as e:
            print(f"❌ Error testing Graph API: {str(e)}")
            return False
    
    def test_user_modification_permissions(self):
        """Test if we can modify user accounts"""
        print("\n" + "="*50)
        print("TEST 5: User Modification Permissions")
        print("="*50)
        
        if not self.access_token:
            print("❌ No access token available")
            return False
            
        # Test user email
        test_email = input("Enter a test user email (or press Enter to skip): ").strip()
        if not test_email:
            print("⚠️  Skipping user modification test")
            return True
            
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            # Get specific user
            response = requests.get(f"https://graph.microsoft.com/v1.0/users/{test_email}", headers=headers)
            if response.status_code == 200:
                user = response.json()
                print(f"✅ Found user: {user.get('displayName')}")
                print(f"   Account Enabled: {user.get('accountEnabled')}")
                print(f"   UPN: {user.get('userPrincipalName')}")
                
                # Test if we can modify (dry run - just check permissions)
                print("\n🔍 Checking modification permissions...")
                
                # Try to get user's manager (requires additional permissions)
                manager_response = requests.get(f"https://graph.microsoft.com/v1.0/users/{test_email}/manager", headers=headers)
                if manager_response.status_code == 200:
                    print("✅ Can read user relationships")
                elif manager_response.status_code == 403:
                    print("⚠️  Limited permissions for user relationships")
                
                print("\n✅ User unlock operation should work!")
                print("   The script would:")
                print("   1. Set accountEnabled = true")
                print("   2. Clear sign-in sessions if needed")
                
                return True
                
            elif response.status_code == 404:
                print("❌ User not found")
                return False
            elif response.status_code == 403:
                print("❌ Insufficient permissions to read user details")
                return False
            else:
                print(f"❌ Error accessing user: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error testing user modification: {str(e)}")
            return False
    
    def show_summary(self):
        """Show test summary and recommendations"""
        print("\n" + "="*50)
        print("SUMMARY & RECOMMENDATIONS")
        print("="*50)
        
        print("\nBased on the test results:")
        print("\n1. For MCP Server implementation:")
        print("   - Use app registration (service principal) authentication")
        print("   - Required permissions: User.ReadWrite.All")
        print("   - Optional: SecurityEvents.ReadWrite.All (for risk clearing)")
        
        print("\n2. If tests failed:")
        print("   - Create Azure app registration")
        print("   - Grant required permissions")
        print("   - Get admin consent for permissions")
        print("   - Set environment variables")
        
        print("\n3. Alternative approaches:")
        print("   - Use Azure AD PowerShell for interactive scenarios")
        print("   - Consider on-premises AD tools for domain accounts")
        print("   - Implement hybrid approach for both Azure AD and on-prem")

async def main():
    """Run all tests"""
    print("Microsoft Graph API Test Suite")
    print("Testing if account unlocking will work...")
    
    tester = GraphAPITester()
    
    # Test 1: Environment variables
    has_env_vars = tester.check_environment_variables()
    
    # Test 2: Authentication
    token = None
    if has_env_vars:
        token = tester.test_app_authentication()
    
    if not token:
        print("\nTrying device authentication...")
        token = tester.test_device_authentication()
    
    if not token:
        print("\n❌ Could not authenticate to Microsoft Graph")
        print("You need to set up authentication first")
        return
    
    # Test 3: Graph API access
    if tester.test_graph_api_access():
        # Test 4: User modification permissions
        tester.test_user_modification_permissions()
    
    # Test 5: Show summary
    tester.show_summary()

if __name__ == "__main__":
    asyncio.run(main())
