#!/usr/bin/env python3
"""
Simple script to show AD user information
Uses current user's credentials (assumes admin privileges)
Fixed for MD4 hash issues with NTLM
"""

import os
import socket
import getpass
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE

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
        
        # Print the raw entry information
        print("RAW USER RECORD:")
        print(user)
        
        print("\n" + "=" * 60)
        print("ENTRY DETAILS:")
        print(f"DN: {user.entry_dn}")
        
        print("\nALL ATTRIBUTES:")
        for attr_name in user.entry_attributes:
            try:
                attr_value = user[attr_name].value
                print(f"  {attr_name}: {attr_value}")
            except Exception as e:
                print(f"  {attr_name}: <Error reading: {e}>")
        
        print("\n" + "=" * 60)
        
        conn.unbind()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nTroubleshooting tips:")
        print("- Make sure you're running this on a domain-joined machine")
        print("- Ensure you have admin privileges")
        print("- Try running from an elevated command prompt")

if __name__ == "__main__":
    get_user_info("ehennenh")
