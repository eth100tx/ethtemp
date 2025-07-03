#!/usr/bin/env python3
"""
Simple script to show AD user information
Uses current user's credentials (assumes admin privileges)
"""

import os
import socket
import getpass
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

def get_user_info(username="ehennenh"):
    """Get user information from Active Directory"""
    
    # Auto-discover domain info
    domain = os.environ.get('USERDOMAIN', '')
    current_user = os.environ.get('USERNAME', '')
    
    print(f"Domain: {domain}")
    print(f"Current User: {current_user}")
    print(f"Looking for user: {username}")
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
            domain_dn = f"DC={domain.lower()},DC=local"  # Adjust as needed
            ldap_server = f"ldap://{domain.lower()}"
    except:
        print("Could not auto-discover domain. Using defaults...")
        domain_dn = f"DC={domain.lower()},DC=local"
        ldap_server = f"ldap://{domain.lower()}"
    
    print(f"Connecting as: {admin_user}")
    print(f"Domain DN: {domain_dn}")
    print(f"LDAP Server: {ldap_server}")
    print("-" * 50)
    
    try:
        # Connect using NTLM with explicit credentials
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(
            server, 
            user=admin_user, 
            password=admin_password, 
            authentication=NTLM, 
            auto_bind=True
        )
        
        print("✓ Connected to Active Directory")
        
        # Search for the user
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        attributes = [
            'sAMAccountName', 'displayName', 'distinguishedName', 
            'mail', 'telephoneNumber', 'department', 'title',
            'lockoutTime', 'userAccountControl', 'badPwdCount',
            'lastLogon', 'passwordLastSet', 'whenCreated',
            'memberOf'
        ]
        
        conn.search(
            search_base=domain_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )
        
        if not conn.entries:
            print(f"❌ User '{username}' not found")
            return
        
        user = conn.entries[0]
        
        print(f"✓ Found user: {username}")
        print("=" * 60)
        
        # Basic Information
        print("BASIC INFORMATION:")
        print(f"  Username (SAM): {user.sAMAccountName.value if user.sAMAccountName else 'N/A'}")
        print(f"  Display Name: {user.displayName.value if user.displayName else 'N/A'}")
        print(f"  Email: {user.mail.value if user.mail else 'N/A'}")
        print(f"  Phone: {user.telephoneNumber.value if user.telephoneNumber else 'N/A'}")
        print(f"  Department: {user.department.value if user.department else 'N/A'}")
        print(f"  Title: {user.title.value if user.title else 'N/A'}")
        print(f"  DN: {user.distinguishedName.value}")
        
        # Account Status
        print("\nACCOUNT STATUS:")
        uac = user.userAccountControl.value if user.userAccountControl else 0
        lockout_time = user.lockoutTime.value if user.lockoutTime else 0
        bad_pwd_count = user.badPwdCount.value if user.badPwdCount else 0
        
        print(f"  Account Enabled: {'No' if uac & 2 else 'Yes'}")
        print(f"  Account Locked: {'Yes' if lockout_time > 0 else 'No'}")
        print(f"  Bad Password Count: {bad_pwd_count}")
        
        # Dates
        print("\nDATES:")
        if user.whenCreated:
            print(f"  Created: {user.whenCreated.value}")
        if user.passwordLastSet:
            print(f"  Password Last Set: {user.passwordLastSet.value}")
        if user.lastLogon:
            print(f"  Last Logon: {user.lastLogon.value}")
        
        # Group Memberships
        if user.memberOf:
            print(f"\nGROUP MEMBERSHIPS ({len(user.memberOf)}):")
            for group_dn in user.memberOf:
                # Extract just the group name from DN
                group_name = group_dn.split(',')[0].replace('CN=', '')
                print(f"  - {group_name}")
        
        print("=" * 60)
        
        conn.unbind()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nTroubleshooting tips:")
        print("- Make sure you're running this on a domain-joined machine")
        print("- Ensure you have admin privileges")
        print("- Try running from an elevated command prompt")

if __name__ == "__main__":
    get_user_info("ehennenh")
