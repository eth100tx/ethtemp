#!/usr/bin/env python3
"""
Simple script to show AD user information and unlock users
Uses Simple authentication
"""

import os
import socket
import getpass
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE, MODIFY_REPLACE

def get_user_info(username=None):
    """Get user information from Active Directory"""
    
    # Auto-discover domain info
    domain = os.environ.get('USERDOMAIN', '')
    current_user = os.environ.get('USERNAME', '')
    
    # Get username to look up
    if not username:
        lookup_user = input(f"Username to lookup (default: {current_user}): ").strip()
        if not lookup_user:
            lookup_user = current_user
    else:
        lookup_user = username
    
    print(f"Domain: {domain}")
    print(f"Looking up user: {lookup_user}")
    print("-" * 50)
    
    # Get admin credentials
    admin_username = input(f"Admin username (default: {current_user}): ").strip()
    if not admin_username:
        admin_username = current_user
    
    admin_password = getpass.getpass("Admin password: ")
    admin_user = f"{domain}\\{admin_username}"
    
    # Try to get domain controller
    try:
        fqdn = socket.getfqdn()
        if '.' in fqdn:
            domain_fqdn = '.'.join(fqdn.split('.')[1:])
            domain_dn = f"DC={domain_fqdn.replace('.', ',DC=')}"
            ldap_server = f"ldap://{domain_fqdn}"
        else:
            # Fallback - try with domain name
            domain_dn = f"DC={domain.lower()},DC=local"
            ldap_server = f"ldap://{domain.lower()}"
    except:
        print("Could not auto-discover domain. Using defaults...")
        domain_dn = f"DC={domain.lower()},DC=local"
        ldap_server = f"ldap://{domain.lower()}"
    
    print(f"Connecting as: {admin_user}")
    print(f"LDAP Server: {ldap_server}")
    print("-" * 50)
    
    try:
        # Connect using Simple authentication
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(
            server, 
            user=admin_user, 
            password=admin_password, 
            authentication=SIMPLE, 
            auto_bind=True
        )
        
        print("✓ Connected to Active Directory")
        
        # Search for the user
        search_filter = f"(&(objectClass=user)(sAMAccountName={lookup_user}))"
        attributes = [
            'sAMAccountName', 'displayName', 'distinguishedName', 
            'mail', 'telephoneNumber', 'department', 'title',
            'lockoutTime', 'userAccountControl', 'badPwdCount',
            'lastLogon', 'whenCreated', 'memberOf'
        ]
        
        conn.search(
            search_base=domain_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )
        
        if not conn.entries:
            print(f"❌ User '{lookup_user}' not found")
            return
        
        user = conn.entries[0]
        user_dn = str(user.distinguishedName.value)
        
        print(f"\n✓ Found user: {lookup_user}")
        print("=" * 60)
        
        # Basic Information - formatted nicely
        print("USER INFORMATION:")
        
        def safe_get_value(attr):
            """Safely get attribute value"""
            try:
                if attr and hasattr(attr, 'value'):
                    return attr.value
                return 'N/A'
            except:
                return 'N/A'
        
        print(f"  Name: {safe_get_value(user.displayName)}")
        print(f"  Username: {safe_get_value(user.sAMAccountName)}")
        print(f"  Email: {safe_get_value(user.mail)}")
        print(f"  Department: {safe_get_value(user.department)}")
        print(f"  Title: {safe_get_value(user.title)}")
        print(f"  Phone: {safe_get_value(user.telephoneNumber)}")
        
        # Account Status
        print(f"\nACCOUNT STATUS:")
        uac = safe_get_value(user.userAccountControl)
        lockout_time = safe_get_value(user.lockoutTime)
        bad_pwd_count = safe_get_value(user.badPwdCount)
        
        # Convert to proper types
        try:
            uac = int(uac) if uac != 'N/A' else 0
            lockout_time = int(lockout_time) if lockout_time != 'N/A' else 0
            bad_pwd_count = int(bad_pwd_count) if bad_pwd_count != 'N/A' else 0
        except:
            uac = lockout_time = bad_pwd_count = 0
        
        account_enabled = not (uac & 2)
        account_locked = lockout_time > 0
        
        print(f"  Enabled: {'✓ Yes' if account_enabled else '✗ No'}")
        print(f"  Locked: {'⚠️  YES' if account_locked else '✓ No'}")
        print(f"  Bad Password Count: {bad_pwd_count}")
        
        # Format creation date nicely
        created_date = safe_get_value(user.whenCreated)
        if created_date != 'N/A':
            print(f"  Created: {created_date}")
        
        # Show group memberships nicely formatted
        if user.memberOf:
            group_count = len(user.memberOf)
            print(f"\nGROUP MEMBERSHIPS ({group_count}):")
            for group_dn in user.memberOf[:5]:  # Show first 5 groups
                # Extract group name from DN
                try:
                    group_name = str(group_dn).split(',')[0].replace('CN=', '')
                    print(f"  • {group_name}")
                except:
                    print(f"  • {group_dn}")
            if group_count > 5:
                print(f"  ... and {group_count - 5} more groups")
        else:
            print(f"\nGROUP MEMBERSHIPS: None")
        
        print(f"\nDISTINGUISHED NAME:")
        print(f"  {user_dn}")
        
        print("=" * 60)
        
        # Handle unlock logic
        if not account_locked:
            print(f"\n✅ User '{lookup_user}' is not locked.")
        else:
            print(f"\n🔒 User '{lookup_user}' is LOCKED OUT!")
            unlock_choice = input("Do you want to unlock this user? (y/N): ").strip().lower()
            
            if unlock_choice == 'y':
                try:
                    print("Unlocking user...")
                    conn.modify(user_dn, {
                        'lockoutTime': [(MODIFY_REPLACE, [0])]
                    })
                    
                    if conn.result['result'] == 0:
                        print("✅ User unlocked successfully!")
                    else:
                        print(f"❌ Failed to unlock user: {conn.result}")
                        
                except Exception as unlock_error:
                    print(f"❌ Error unlocking user: {unlock_error}")
            else:
                print("User remains locked.")
        
        conn.unbind()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    get_user_info()