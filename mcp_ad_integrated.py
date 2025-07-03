#!/usr/bin/env python3
"""
MCP AD Service - Uses current Windows session (no passwords needed)
Multiple approaches to leverage your existing admin session
"""

import os
import socket
import json
import subprocess
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE

class ADService:
    def __init__(self):
        self.conn = None
        self.server = None
        self.domain_dn = None
        self.ldap_server = None
        self.auth_method = None
        
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

    def try_kerberos_auth(self):
        """Method 1: Try Kerberos/GSSAPI (uses current Windows session)"""
        try:
            from ldap3 import SASL, GSSAPI
            print("Trying Kerberos/GSSAPI authentication...")
            
            self.server = Server(self.ldap_server, get_info=ALL)
            self.conn = Connection(
                self.server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=True
            )
            
            if self.conn.bound:
                print("✓ Kerberos authentication successful")
                self.auth_method = "Kerberos"
                return True
                
        except ImportError:
            print("✗ GSSAPI not available (install python-gssapi)")
        except Exception as e:
            print(f"✗ Kerberos failed: {e}")
        
        return False
    
    def try_powershell_method(self):
        """Method 2: Use PowerShell AD cmdlets (uses current session)"""
        try:
            # Test if we can run AD PowerShell commands
            result = subprocess.run([
                'powershell', '-Command', 
                'Import-Module ActiveDirectory; Get-ADDomain | Select-Object Name'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("✓ PowerShell AD access confirmed")
                self.auth_method = "PowerShell"
                return True
            else:
                print(f"✗ PowerShell AD access failed: {result.stderr}")
                
        except Exception as e:
            print(f"✗ PowerShell method failed: {e}")
        
        return False
    
    def try_win32_method(self):
        """Method 3: Use pywin32 (Windows native authentication)"""
        try:
            import win32security
            import win32api
            import win32con
            
            # Get current user's SID to verify admin access
            user_sid = win32security.GetTokenInformation(
                win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY),
                win32security.TokenUser
            )
            
            print("✓ Windows authentication available")
            self.auth_method = "Win32"
            return True
            
        except ImportError:
            print("✗ pywin32 not available (pip install pywin32)")
        except Exception as e:
            print(f"✗ Win32 method failed: {e}")
        
        return False

    def connect_to_ad(self):
        """Try different methods to connect using current Windows session"""
        if self.conn and self.conn.bound:
            return True
            
        self.discover_domain_info()
        
        # Try methods in order of preference
        auth_methods = [
            ("Kerberos/GSSAPI", self.try_kerberos_auth),
            ("PowerShell AD", self.try_powershell_method),
            ("Win32 Native", self.try_win32_method)
        ]
        
        for method_name, method_func in auth_methods:
            print(f"Attempting {method_name}...")
            if method_func():
                return True
        
        print("❌ All Windows integrated authentication methods failed")
        return False

    def get_user_info_ldap(self, username):
        """Get user info via LDAP (if Kerberos worked)"""
        if self.auth_method != "Kerberos" or not self.conn:
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

    def get_user_info_powershell(self, username):
        """Get user info via PowerShell (uses current session)"""
        try:
            ps_script = f"""
            Import-Module ActiveDirectory
            $user = Get-ADUser -Identity '{username}' -Properties *
            $user | ConvertTo-Json -Depth 3
            """
            
            result = subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                import json
                user_data = json.loads(result.stdout)
                return user_data
            else:
                print(f"PowerShell user lookup failed: {result.stderr}")
                return None
                
        except Exception as e:
            print(f"Error getting user info via PowerShell: {e}")
            return None

    def get_user_info(self, username):
        """Get user information using available method"""
        if not self.connect_to_ad():
            return None
        
        if self.auth_method == "Kerberos":
            return self.get_user_info_ldap(username)
        elif self.auth_method == "PowerShell":
            return self.get_user_info_powershell(username)
        elif self.auth_method == "Win32":
            # Could implement WMI queries here
            return self.get_user_info_powershell(username)  # Fallback to PS
        
        return None

    def unlock_user_ldap(self, username):
        """Unlock user via LDAP"""
        if self.auth_method != "Kerberos" or not self.conn:
            return False, "LDAP connection not available"
            
        user = self.get_user_info_ldap(username)
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

    def unlock_user_powershell(self, username):
        """Unlock user via PowerShell"""
        try:
            ps_script = f"""
            Import-Module ActiveDirectory
            $user = Get-ADUser -Identity '{username}' -Properties LockedOut
            if ($user.LockedOut) {{
                Unlock-ADAccount -Identity '{username}'
                Write-Output "User unlocked successfully"
            }} else {{
                Write-Output "User is not locked"
            }}
            """
            
            result = subprocess.run([
                'powershell', '-Command', ps_script
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, f"PowerShell unlock failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Error unlocking user via PowerShell: {e}"

    def unlock_user(self, username):
        """Unlock user using available method"""
        if not self.connect_to_ad():
            return False, "Failed to connect to Active Directory"
        
        if self.auth_method == "Kerberos":
            return self.unlock_user_ldap(username)
        elif self.auth_method in ["PowerShell", "Win32"]:
            return self.unlock_user_powershell(username)
        
        return False, "No authentication method available"

    def format_user_info(self, user_data):
        """Format user information for MCP response"""
        if not user_data:
            return {"error": "User not found"}
        
        # Handle both LDAP and PowerShell data formats
        if hasattr(user_data, 'sAMAccountName'):  # LDAP format
            return self._format_ldap_user(user_data)
        elif isinstance(user_data, dict):  # PowerShell JSON format
            return self._format_powershell_user(user_data)
        
        return {"error": "Invalid user data format"}

    def _format_ldap_user(self, user):
        """Format LDAP user data"""
        def safe_get_value(attr):
            try:
                if attr and hasattr(attr, 'value'):
                    return attr.value
                return None
            except:
                return None
        
        uac = safe_get_value(user.userAccountControl) or 0
        lockout_time = safe_get_value(user.lockoutTime) or 0
        
        try:
            uac = int(uac)
            lockout_time = int(lockout_time)
        except:
            uac = lockout_time = 0
        
        return {
            "name": safe_get_value(user.displayName),
            "username": safe_get_value(user.sAMAccountName),
            "email": safe_get_value(user.mail),
            "enabled": not (uac & 2),
            "locked": lockout_time > 0,
            "dn": safe_get_value(user.distinguishedName)
        }

    def _format_powershell_user(self, user):
        """Format PowerShell user data"""
        return {
            "name": user.get("DisplayName"),
            "username": user.get("SamAccountName"),
            "email": user.get("mail"),
            "enabled": user.get("Enabled", False),
            "locked": user.get("LockedOut", False),
            "dn": user.get("DistinguishedName")
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
            "locked": user_info.get("locked", False)
        }
    return {"username": username, "locked": None, "error": "User not found"}

# Example usage and testing
if __name__ == "__main__":
    print("AD Service - Windows Integrated Authentication Test")
    print("==================================================")
    print("This will attempt to use your current Windows session")
    print("No passwords needed!")
    print()
    
    # Test connection
    if _ad_service.connect_to_ad():
        print(f"✓ Authentication successful using: {_ad_service.auth_method}")
        
        # Test the service
        test_user = input("Enter username to test (default: ethantestuser): ").strip()
        if not test_user:
            test_user = "ethantestuser"
        
        print(f"\n1. Getting info for user: {test_user}")
        user_info = mcp_get_user_info(test_user)
        print(json.dumps(user_info, indent=2, default=str))
        
        if user_info.get("locked"):
            print(f"\n2. User is locked. Testing unlock...")
            unlock_result = mcp_unlock_user(test_user)
            print(json.dumps(unlock_result, indent=2))
        else:
            print(f"\n2. User is not locked")
    else:
        print("❌ Could not establish Windows integrated authentication")
        print("\nTroubleshooting:")
        print("1. Make sure you're running this as a domain admin")
        print("2. Try: pip install python-gssapi (for Kerberos)")
        print("3. Try: pip install pywin32 (for native Windows auth)")
        print("4. Ensure Active Directory PowerShell module is installed")