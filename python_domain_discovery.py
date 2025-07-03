#!/usr/bin/env python3
"""
Python script to discover AD domain information using ldap3
"""

import os
import socket
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

def get_domain_info():
    """Discover basic domain information"""
    
    # Get domain from environment
    domain = os.environ.get('USERDOMAIN', '')
    username = os.environ.get('USERNAME', '')
    
    print("=== Active Directory Domain Discovery ===")
    print(f"NetBIOS Domain: {domain}")
    print(f"Current User: {username}")
    print(f"Full Username: {domain}\\{username}")
    
    # Try to get FQDN from DNS
    try:
        fqdn = socket.getfqdn()
        if '.' in fqdn:
            domain_fqdn = '.'.join(fqdn.split('.')[1:])
            print(f"Likely FQDN: {domain_fqdn}")
            print(f"Domain DN: DC={domain_fqdn.replace('.', ',DC=')}")
        else:
            print("Could not determine FQDN from hostname")
    except Exception as e:
        print(f"Error getting FQDN: {e}")
    
    return domain, username

def find_domain_controllers():
    """Find domain controllers using DNS"""
    import subprocess
    
    print("\n=== Finding Domain Controllers ===")
    try:
        # Use nslookup to find DCs
        result = subprocess.run(['nslookup', '-type=SRV', '_ldap._tcp.dc._msdcs'], 
                               capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("Domain Controllers found via DNS:")
            lines = result.stdout.split('\n')
            for line in lines:
                if 'service' in line.lower() and '.dc._msdcs' in line:
                    parts = line.strip().split()
                    if len(parts) > 3:
                        dc_name = parts[-1].rstrip('.')
                        print(f"  {dc_name}")
        else:
            print("Could not find DCs via DNS SRV records")
            
    except Exception as e:
        print(f"Error finding DCs: {e}")

def test_ldap_connection(server_name, domain, username):
    """Test LDAP connection with current credentials"""
    
    print(f"\n=== Testing LDAP Connection to {server_name} ===")
    
    try:
        # Try different server formats
        server_urls = [
            f"ldap://{server_name}",
            f"ldap://{server_name}:389",
            f"ldaps://{server_name}:636"
        ]
        
        for server_url in server_urls:
            try:
                print(f"Trying: {server_url}")
                server = Server(server_url, get_info=ALL, connect_timeout=5)
                
                # Try anonymous bind first
                conn = Connection(server, auto_bind=True)
                if conn.bound:
                    print(f"✓ Anonymous connection successful to {server_url}")
                    
                    # Get domain info
                    domain_dn = server.info.naming_contexts[0] if server.info.naming_contexts else None
                    if domain_dn:
                        print(f"Domain DN: {domain_dn}")
                    
                    conn.unbind()
                    return server_url, domain_dn
                    
            except Exception as e:
                print(f"✗ Failed: {e}")
                continue
                
        print("All connection attempts failed")
        return None, None
        
    except Exception as e:
        print(f"Error testing connection: {e}")
        return None, None

def search_user(server_url, domain_dn, username_to_find):
    """Search for a specific user"""
    
    if not server_url or not domain_dn:
        print("Need valid server and domain DN to search")
        return None
    
    print(f"\n=== Searching for user: {username_to_find} ===")
    
    try:
        server = Server(server_url, get_info=ALL)
        conn = Connection(server, auto_bind=True)  # Anonymous
        
        # Search for user
        search_filter = f"(&(objectClass=user)(sAMAccountName={username_to_find}))"
        conn.search(
            search_base=domain_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'displayName', 'sAMAccountName', 'userAccountControl']
        )
        
        if conn.entries:
            for entry in conn.entries:
                print(f"Found user:")
                print(f"  DN: {entry.distinguishedName}")
                print(f"  Display Name: {entry.displayName}")
                print(f"  SAM Account: {entry.sAMAccountName}")
                return str(entry.distinguishedName)
        else:
            print("User not found")
            return None
            
    except Exception as e:
        print(f"Error searching for user: {e}")
        return None

def main():
    # Get basic info
    domain, username = get_domain_info()
    
    # Find DCs
    find_domain_controllers()
    
    # Test connection (you'll need to provide a DC name)
    print(f"\nEnter a domain controller name to test (or press Enter to skip):")
    dc_name = input().strip()
    
    if dc_name:
        server_url, domain_dn = test_ldap_connection(dc_name, domain, username)
        
        if server_url:
            print(f"\n=== Configuration for your script ===")
            print(f"domain = '{domain}'")
            print(f"user = '{domain}\\\\your_admin_username'")
            print(f"ldap_server = '{server_url}'")
            if domain_dn:
                print(f"# Base DN: {domain_dn}")
            
            # Search for a user
            target_user = input(f"\nEnter username to find DN (or press Enter to skip): ").strip()
            if target_user:
                user_dn = search_user(server_url, domain_dn, target_user)
                if user_dn:
                    print(f"target_user_dn = '{user_dn}'")

if __name__ == "__main__":
    main()