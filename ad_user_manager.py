#!/usr/bin/env python3
"""
Active Directory User Lock Management Tool
Discovers domain info and provides menu for managing user account locks
"""

import os
import socket
import getpass
import sys
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE

class ADManager:
    def __init__(self):
        self.server = None
        self.conn = None
        self.domain = None
        self.domain_dn = None
        self.ldap_server = None
        self.admin_user = None
        self.admin_password = None
        
    def discover_domain_info(self):
        """Auto-discover domain information"""
        print("=== Discovering Domain Information ===")
        
        # Get domain from environment
        self.domain = os.environ.get('USERDOMAIN', '')
        current_user = os.environ.get('USERNAME', '')
        
        print(f"NetBIOS Domain: {self.domain}")
        print(f"Current User: {current_user}")
        
        # Try to get FQDN and construct DN
        try:
            fqdn = socket.getfqdn()
            if '.' in fqdn:
                domain_fqdn = '.'.join(fqdn.split('.')[1:])
                self.domain_dn = f"DC={domain_fqdn.replace('.', ',DC=')}"
                print(f"Domain FQDN: {domain_fqdn}")
                print(f"Domain DN: {self.domain_dn}")
                
                # Try to find a domain controller
                try:
                    import subprocess
                    result = subprocess.run(['nltest', '/dclist:'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if '\\\\' in line and 'PDC' not in line:
                                dc_name = line.strip().split('\\\\')[1].split()[0]
                                self.ldap_server = f"ldap://{dc_name}"
                                print(f"Found DC: {dc_name}")
                                break
                except:
                    pass
                    
        except Exception as e:
            print(f"Could not auto-discover FQDN: {e}")
    
    def get_missing_info(self):
        """Prompt for any missing information"""
        print("\n=== Configuration ===")
        
        if not self.domain:
            self.domain = input("Enter domain (NetBIOS name): ").strip()
        
        if not self.domain_dn:
            domain_fqdn = input("Enter domain FQDN (e.g., corp.company.com): ").strip()
            if domain_fqdn:
                self.domain_dn = f"DC={domain_fqdn.replace('.', ',DC=')}"
        
        if not self.ldap_server:
            dc_name = input("Enter domain controller name or IP: ").strip()
            if dc_name:
                self.ldap_server = f"ldap://{dc_name}"
        
        # Get admin credentials
        print(f"\nEnter admin credentials for domain: {self.domain}")
        admin_username = input("Admin username (without domain): ").strip()
        self.admin_user = f"{self.domain}\\{admin_username}"
        self.admin_password = getpass.getpass("Admin password: ")
        
        print(f"\nUsing configuration:")
        print(f"Domain: {self.domain}")
        print(f"Domain DN: {self.domain_dn}")
        print(f"LDAP Server: {self.ldap_server}")
        print(f"Admin User: {self.admin_user}")
    
    def connect_to_ad(self):
        """Establish connection to Active Directory"""
        try:
            print(f"\nConnecting to {self.ldap_server}...")
            self.server = Server(self.ldap_server, get_info=ALL)
            self.conn = Connection(
                self.server, 
                user=self.admin_user, 
                password=self.admin_password, 
                authentication=NTLM, 
                auto_bind=True
            )
            print("✓ Successfully connected to Active Directory")
            return True
        except Exception as e:
            print(f"✗ Failed to connect: {e}")
            return False
    
    def search_users(self, search_filter, attributes=None):
        """Search for users with given filter"""
        if attributes is None:
            attributes = ['sAMAccountName', 'displayName', 'distinguishedName', 
                         'lockoutTime', 'userAccountControl', 'badPwdCount']
        
        try:
            self.conn.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            return self.conn.entries
        except Exception as e:
            print(f"Search error: {e}")
            return []
    
    def list_locked_users(self):
        """List all locked user accounts"""
        print("\n=== Locked User Accounts ===")
        
        # Search for users with lockoutTime > 0
        search_filter = "(&(objectClass=user)(lockoutTime>=1))"
        entries = self.search_users(search_filter)
        
        if not entries:
            print("No locked users found.")
            return
        
        print(f"Found {len(entries)} locked user(s):")
        print("-" * 80)
        
        for entry in entries:
            username = entry.sAMAccountName.value if entry.sAMAccountName else "N/A"
            display_name = entry.displayName.value if entry.displayName else "N/A"
            lockout_time = entry.lockoutTime.value if entry.lockoutTime else "0"
            bad_pwd_count = entry.badPwdCount.value if entry.badPwdCount else "0"
            
            print(f"Username: {username}")
            print(f"Display Name: {display_name}")
            print(f"Lockout Time: {lockout_time}")
            print(f"Bad Password Count: {bad_pwd_count}")
            print(f"DN: {entry.distinguishedName}")
            print("-" * 80)
    
    def find_user(self, username):
        """Find a specific user by username"""
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        entries = self.search_users(search_filter)
        
        if entries:
            return entries[0]
        return None
    
    def unlock_user(self, username):
        """Unlock a user account"""
        print(f"\n=== Unlocking User: {username} ===")
        
        # Find the user
        user_entry = self.find_user(username)
        if not user_entry:
            print(f"User '{username}' not found.")
            return False
        
        user_dn = str(user_entry.distinguishedName)
        print(f"Found user: {user_entry.displayName} ({user_dn})")
        
        # Check if user is actually locked
        lockout_time = user_entry.lockoutTime.value if user_entry.lockoutTime else 0
        if lockout_time == 0:
            print("User is not currently locked.")
            return True
        
        try:
            # Unlock by setting lockoutTime to 0
            self.conn.modify(user_dn, {
                'lockoutTime': [(MODIFY_REPLACE, [0])]
            })
            
            if self.conn.result['result'] == 0:
                print("✓ User unlocked successfully.")
                return True
            else:
                print(f"✗ Failed to unlock user: {self.conn.result}")
                return False
                
        except Exception as e:
            print(f"✗ Error unlocking user: {e}")
            return False
    
    def lock_user(self, username):
        """Lock a user account by disabling it"""
        print(f"\n=== Locking User: {username} ===")
        
        # Find the user
        user_entry = self.find_user(username)
        if not user_entry:
            print(f"User '{username}' not found.")
            return False
        
        user_dn = str(user_entry.distinguishedName)
        print(f"Found user: {user_entry.displayName} ({user_dn})")
        
        # Check current userAccountControl
        uac = user_entry.userAccountControl.value if user_entry.userAccountControl else 0
        
        # Check if already disabled (bit 1 = ACCOUNTDISABLE)
        if uac & 2:
            print("User account is already disabled.")
            return True
        
        try:
            # Disable account by setting ACCOUNTDISABLE flag
            new_uac = uac | 2  # Set bit 1 (ACCOUNTDISABLE)
            
            self.conn.modify(user_dn, {
                'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
            })
            
            if self.conn.result['result'] == 0:
                print("✓ User account disabled successfully.")
                return True
            else:
                print(f"✗ Failed to disable user: {self.conn.result}")
                return False
                
        except Exception as e:
            print(f"✗ Error disabling user: {e}")
            return False
    
    def show_menu(self):
        """Display main menu"""
        while True:
            print("\n" + "="*50)
            print("AD User Lock Management")
            print("="*50)
            print("1. List locked users")
            print("2. Unlock a user")
            print("3. Lock/Disable a user")
            print("4. Check user status")
            print("5. Reconnect to AD")
            print("0. Exit")
            print("-"*50)
            
            choice = input("Select an option: ").strip()
            
            if choice == '1':
                self.list_locked_users()
                
            elif choice == '2':
                username = input("Enter username to unlock: ").strip()
                if username:
                    self.unlock_user(username)
                    
            elif choice == '3':
                username = input("Enter username to lock/disable: ").strip()
                if username:
                    confirm = input(f"Are you sure you want to disable '{username}'? (yes/no): ").strip().lower()
                    if confirm == 'yes':
                        self.lock_user(username)
                    else:
                        print("Operation cancelled.")
                        
            elif choice == '4':
                username = input("Enter username to check: ").strip()
                if username:
                    user_entry = self.find_user(username)
                    if user_entry:
                        print(f"\nUser Status for: {username}")
                        print(f"Display Name: {user_entry.displayName}")
                        print(f"DN: {user_entry.distinguishedName}")
                        
                        lockout_time = user_entry.lockoutTime.value if user_entry.lockoutTime else 0
                        uac = user_entry.userAccountControl.value if user_entry.userAccountControl else 0
                        bad_pwd_count = user_entry.badPwdCount.value if user_entry.badPwdCount else 0
                        
                        print(f"Locked: {'Yes' if lockout_time > 0 else 'No'}")
                        print(f"Disabled: {'Yes' if uac & 2 else 'No'}")
                        print(f"Bad Password Count: {bad_pwd_count}")
                    else:
                        print(f"User '{username}' not found.")
                        
            elif choice == '5':
                if self.connect_to_ad():
                    print("Reconnected successfully.")
                else:
                    print("Reconnection failed.")
                    
            elif choice == '0':
                print("Goodbye!")
                break
                
            else:
                print("Invalid option. Please try again.")
    
    def run(self):
        """Main execution flow"""
        print("Active Directory User Lock Management Tool")
        print("==========================================")
        
        # Discover what we can
        self.discover_domain_info()
        
        # Get missing information
        self.get_missing_info()
        
        # Connect to AD
        if not self.connect_to_ad():
            print("Cannot continue without AD connection.")
            sys.exit(1)
        
        # Show menu
        try:
            self.show_menu()
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            if self.conn:
                self.conn.unbind()

if __name__ == "__main__":
    manager = ADManager()
    manager.run()