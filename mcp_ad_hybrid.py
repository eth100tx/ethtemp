#!/usr/bin/env python3
"""
MCP AD Service - Uses PowerShell only for authentication, LDAP for all operations
Design: PowerShell solves the password problem, LDAP handles AD operations
"""

import os
import socket
import json
import subprocess
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE, MODIFY_REPLACE

class ADService:
    def __init__(self):
        self.conn = None
        self.server = None
        self.domain_dn = None
        self.ldap_server = None
        self.admin_username = None
        self.admin_password = None
        self.authenticated = False
        
    def get_credentials_via_powershell(self):
        """Use PowerShell to get current user credentials for LDAP"""
        try:
            # Method 1: Extract current user info and try to get stored credentials
            ps_script = """
            # Get current domain user info
            $domain = $env:USERDOMAIN
            $username = $env:USERNAME
            $fqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
            
            # Try to get stored credentials from Windows Credential Manager
            try {
                # Look for stored AD credentials
                $credTarget = "AD_Service_Creds"
                $cred = Get-StoredCredential -Target $credTarget -ErrorAction SilentlyContinue
                if ($cred) {
                    $storedUser = $cred.UserName
                    $storedPass = $cred.GetNetworkCredential().Password
                    Write-Output "STORED_CREDS:$storedUser|$storedPass"
                    exit 0
                }
            } catch {
                # Credential Manager method failed, continue
            }
            
            # If no stored creds, return current user info for environment variable fallback
            Write-Output "CURRENT_USER:$domain\\$username|$fqdn"
            """
            
            result = subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                output = result.stdout.strip()
                
                if output.startswith("STORED_CREDS:"):
                    # Found stored credentials
                    cred_data = output.replace("STORED_CREDS:", "")
                    username, password = cred_data.split("|", 1)
                    print(f"✓ Retrieved stored credentials for: {username}")
                    return username, password
                    
                elif output.startswith("CURRENT_USER:"):
                    # Get current user info, check for environment password
                    user_data = output.replace("CURRENT_USER:", "")
                    current_user, fqdn = user_data.split("|", 1)
                    
                    # Check if password is in environment variable
                    env_password = os.environ.get('CURRENT_USER_PASSWORD')
                    if env_password:
                        print(f"✓ Using current user with env password: {current_user}")
                        return current_user, env_password
                    
                    print(f"ℹ️  Current user: {current_user}, but no password available")
                    print("   Set CURRENT_USER_PASSWORD env var or store credentials in Credential Manager")
                    return None, None
            
            print("✗ PowerShell credential extraction failed")
            return None, None
            
        except Exception as e:
            print(f"✗ Error getting credentials via PowerShell: {e}")
            return None, None
    
    def store_credentials_powershell(self, username, password):
        """Helper: Store credentials in Windows Credential Manager via PowerShell"""
        try:
            ps_script = f"""
            # Store credentials in Windows Credential Manager
            $secPassword = ConvertTo-SecureString "{password}" -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential("{username}", $secPassword)
            
            # Store using cmdkey (more reliable than PowerShell credential cmdlets)
            cmdkey /add:AD_Service_Creds /user:"{username}" /pass:"{password}"
            Write-Output "Credentials stored successfully"
            """
            
            result = subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, text=True, timeout=10)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"Error storing credentials: {e}")
            return False
    
    def test_ad_access_powershell(self):
        """Use PowerShell to verify we have AD access (minimal usage)"""
        try:
            result = subprocess.run([
                'powershell', '-Command', 
                'Import-Module ActiveDirectory; Get-ADDomain | Select-Object Name'
            ], capture_output=True, text=True, timeout=20)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"PowerShell AD access test failed: {e}")
            return False
    
    def discover_domain_info(self):
        """Auto-discover domain information"""
        domain = os.environ.get('USERDOMAIN', '')
        
        try:
            fqdn = socket.getfqdn()
            if '.' in fqdn:
                domain_fqdn = '.'.join(fqdn.split('.')[1:])
                self.domain_dn = f"DC={domain_fqdn.replace('.', ',DC=')}"
                self.ldap_server = f"ldap://{domain_fqdn}"
            else:
                self.domain_dn = f"DC={domain.lower()},DC=local"
                self.ldap_server = f"ldap://{domain.lower()}"
        except:
            self.domain_dn = f"DC={domain.lower()},DC=local"
            self.ldap_server = f"ldap://{domain.lower()}"
    
    def connect_to_ad(self):
        """Connect to AD via LDAP using PowerShell-obtained credentials"""
        if self.conn and self.conn.bound:
            return True
        
        # Step 1: Verify we have AD access via PowerShell (minimal usage)
        print("Verifying AD access...")
        if not self.test_ad_access_powershell():
            print("❌ No AD access available")
            return False
        
        # Step 2: Get credentials via PowerShell
        print("Getting credentials via PowerShell...")
        username, password = self.get_credentials_via_powershell()
        
        if not username or not password:
            print("❌ Could not obtain credentials")
            print("\nTo fix this, either:")
            print("1. Set environment variable: CURRENT_USER_PASSWORD=your_password")
            print("2. Store credentials: cmdkey /add:AD_Service_Creds /user:domain\\username /pass:password")
            return False
        
        # Step 3: Discover domain info
        self.discover_domain_info()
        
        # Step 4: Connect via LDAP using Simple authentication
        try:
            print(f"Connecting to LDAP: {self.ldap_server}")
            self.server = Server(self.ldap_server, get_info=ALL)
            self.conn = Connection(
                self.server,
                user=username,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )
            
            if self.conn.bound:
                print("✓ LDAP connection successful")
                self.admin_username = username
                self.admin_password = password
                self.authenticated = True
                return True
            else:
                print("❌ LDAP bind failed")
                return False
                
        except Exception as e:
            print(f"❌ LDAP connection error: {e}")
            return False
    
    def get_user_info(self, username):
        """Get user information via LDAP"""
        if not self.connect_to_ad():
            return None
        
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        attributes = [
            'sAMAccountName', 'displayName', 'distinguishedName', 
            'mail', 'telephoneNumber', 'department', 'title',
            'lockoutTime', 'userAccountControl', 'badPwdCount',
            'lastLogon', 'whenCreated', 'memberOf'
        ]
        
        try:
            self.conn.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            
            if self.conn.entries:
                return self.conn.entries[0]
            return None
            
        except Exception as e:
            print(f"Error searching for user via LDAP: {e}")
            return None
    
    def unlock_user(self, username):
        """Unlock user via LDAP"""
        if not self.connect_to_ad():
            return False, "Failed to connect to Active Directory"
            
        user = self.get_user_info(username)
        if not user:
            return False, f"User '{username}' not found"
        
        try:
            user_dn = str(user.distinguishedName.value)
            lockout_time = user.lockoutTime.value if user.lockoutTime else 0
            
            if lockout_time == 0:
                return True, f"User '{username}' is not locked"
            
            self.conn.modify(user_dn, {
                'lockoutTime': [(MODIFY_REPLACE, [0])]
            })
            
            if self.conn.result['result'] == 0:
                return True, f"User '{username}' unlocked successfully"
            else:
                return False, f"Failed to unlock user: {self.conn.result}"
                
        except Exception as e:
            return False, f"Error unlocking user: {e}"
    
    def format_user_info(self, user):
        """Format LDAP user information for MCP response"""
        if not user:
            return {"error": "User not found"}
        
        def safe_get_value(attr):
            try:
                if attr and hasattr(attr, 'value'):
                    return attr.value
                return None
            except:
                return None
        
        uac = safe_get_value(user.userAccountControl) or 0
        lockout_time = safe_get_value(user.lockoutTime) or 0
        bad_pwd_count = safe_get_value(user.badPwdCount) or 0
        
        try:
            uac = int(uac)
            lockout_time = int(lockout_time)
            bad_pwd_count = int(bad_pwd_count)
        except:
            uac = lockout_time = bad_pwd_count = 0
        
        account_enabled = not (uac & 2)
        account_locked = lockout_time > 0
        
        groups = []
        if user.memberOf:
            for group_dn in user.memberOf:
                try:
                    group_name = str(group_dn).split(',')[0].replace('CN=', '')
                    groups.append(group_name)
                except:
                    groups.append(str(group_dn))
        
        return {
            "name": safe_get_value(user.displayName),
            "username": safe_get_value(user.sAMAccountName),
            "email": safe_get_value(user.mail),
            "department": safe_get_value(user.department),
            "title": safe_get_value(user.title),
            "phone": safe_get_value(user.telephoneNumber),
            "enabled": account_enabled,
            "locked": account_locked,
            "bad_password_count": bad_pwd_count,
            "created": str(safe_get_value(user.whenCreated)) if safe_get_value(user.whenCreated) else None,
            "dn": safe_get_value(user.distinguishedName),
            "groups": groups
        }

# Global service instance
_ad_service = ADService()

# MCP Interface Functions
def mcp_get_user_info(username):
    """MCP function to get user information"""
    user = _ad_service.get_user_info(username)
    return _ad_service.format_user_info(user)

def mcp_unlock_user(username):
    """MCP function to unlock a user"""
    success, message = _ad_service.unlock_user(username)
    return {"success": success, "message": message, "username": username}

def mcp_check_user_lock_status(username):
    """MCP function to check if user is locked"""
    user = _ad_service.get_user_info(username)
    if user:
        user_info = _ad_service.format_user_info(user)
        return {
            "username": username, 
            "locked": user_info.get("locked", False),
            "bad_password_count": user_info.get("bad_password_count", 0)
        }
    return {"username": username, "locked": None, "error": "User not found"}

# Helper function for one-time credential setup
def setup_credentials(username, password):
    """One-time setup to store credentials securely"""
    service = ADService()
    if service.store_credentials_powershell(username, password):
        print("✓ Credentials stored successfully in Windows Credential Manager")
        return True
    else:
        print("❌ Failed to store credentials")
        return False

# Example usage and testing
if __name__ == "__main__":
    print("AD Service - Hybrid (PowerShell Auth + LDAP Operations)")
    print("=====================================================")
    print("Uses PowerShell only for authentication, LDAP for all AD operations")
    print()
    
    # Test connection
    if _ad_service.connect_to_ad():
        print("✓ Authentication successful - ready for LDAP operations")
        
        # Test the service
        test_user = input("Enter username to test (default: ethantestuser): ").strip()
        if not test_user:
            test_user = "ethantestuser"
        
        print(f"\n1. Getting info for user: {test_user} (via LDAP)")
        user_info = mcp_get_user_info(test_user)
        print(json.dumps(user_info, indent=2, default=str))
        
        print(f"\n2. Checking lock status for: {test_user} (via LDAP)")
        lock_status = mcp_check_user_lock_status(test_user)
        print(json.dumps(lock_status, indent=2))
        
        if lock_status and lock_status.get("locked"):
            print(f"\n3. User is locked. Testing unlock... (via LDAP)")
            unlock_result = mcp_unlock_user(test_user)
            print(json.dumps(unlock_result, indent=2))
        else:
            print(f"\n3. User is not locked - no unlock needed")
    else:
        print("❌ Could not establish authentication")
        print("\nSetup options:")
        print("1. Set environment variable: CURRENT_USER_PASSWORD=your_password")
        print("2. Store credentials once: cmdkey /add:AD_Service_Creds /user:domain\\username /pass:password")
        print("3. Or run setup_credentials('domain\\username', 'password') once")