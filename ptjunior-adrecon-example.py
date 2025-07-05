#!/usr/bin/env python3
"""
PTJunior ADRecon Integration Example
=====================================

This script demonstrates how PTJunior can integrate with bash-adrecon tools
for automated Active Directory reconnaissance during penetration testing.

Usage:
    python3 ptjunior-adrecon-example.py --target 192.168.1.10 --domain example.com --username admin --password password

Requirements:
    - bash-adrecon.sh and bash-adrecon-json.sh in the same directory
    - Python 3.6+ with subprocess and json modules
    - All bash-adrecon dependencies installed
"""

import argparse
import json
import subprocess
import sys
import time
import os
from pathlib import Path

class PTJuniorADRecon:
    def __init__(self, target, domain, username, password):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dir = Path(__file__).parent
        self.results = {}
        
    def check_dependencies(self):
        """Check if required scripts are available"""
        required_scripts = [
            'bash-adrecon.sh',
            'bash-adrecon-json.sh'
        ]
        
        missing = []
        for script in required_scripts:
            script_path = self.base_dir / script
            if not script_path.exists():
                missing.append(script)
            else:
                # Make sure it's executable
                script_path.chmod(0o755)
        
        if missing:
            print(f"❌ Missing required scripts: {missing}")
            return False
        
        print("✅ All required scripts found")
        return True
    
    def run_full_enumeration(self):
        """Run complete AD enumeration using bash-adrecon.sh"""
        print("🔍 Starting full AD enumeration...")
        
        cmd = [
            './bash-adrecon.sh',
            '-d', self.target,
            '-D', self.domain,
            '-u', self.username,
            '-p', self.password,
            '-v'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                print("✅ Full enumeration completed successfully")
                return result.stdout
            else:
                print(f"❌ Full enumeration failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("❌ Full enumeration timed out")
            return None
        except Exception as e:
            print(f"❌ Error running full enumeration: {e}")
            return None
    
    def run_json_enumeration(self, modules=None):
        """Run targeted enumeration with JSON output"""
        print("📊 Starting JSON enumeration...")
        
        cmd = [
            './bash-adrecon-json.sh',
            '-d', self.target,
            '-D', self.domain,
            '-u', self.username,
            '-p', self.password,
            '-v'
        ]
        
        if modules:
            cmd.extend(['-c', ','.join(modules)])
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=180  # 3 minute timeout
            )
            
            if result.returncode == 0:
                print("✅ JSON enumeration completed successfully")
                return json.loads(result.stdout)
            else:
                print(f"❌ JSON enumeration failed: {result.stderr}")
                return None
                
        except json.JSONDecodeError:
            print("❌ Failed to parse JSON output")
            return None
        except subprocess.TimeoutExpired:
            print("❌ JSON enumeration timed out")
            return None
        except Exception as e:
            print(f"❌ Error running JSON enumeration: {e}")
            return None
    
    def analyze_results(self, json_data):
        """Analyze enumeration results and identify potential attack vectors"""
        if not json_data:
            return
        
        print("\n🎯 Analysis Results:")
        print("=" * 50)
        
        # Analyze users
        if 'users' in json_data:
            users = json_data['users']
            print(f"👥 Found {len(users)} users")
            
            # Look for interesting users
            admin_users = [u for u in users if 'admin' in u.get('name', '').lower()]
            service_users = [u for u in users if 'service' in u.get('name', '').lower()]
            
            if admin_users:
                print(f"   🔑 {len(admin_users)} potential admin users")
            if service_users:
                print(f"   🔧 {len(service_users)} potential service users")
        
        # Analyze groups
        if 'groups' in json_data:
            groups = json_data['groups']
            print(f"👥 Found {len(groups)} groups")
            
            # Look for privileged groups
            priv_groups = [g for g in groups if any(keyword in g.get('name', '').lower() 
                          for keyword in ['admin', 'domain', 'enterprise', 'schema'])]
            
            if priv_groups:
                print(f"   🔐 {len(priv_groups)} privileged groups")
        
        # Analyze computers
        if 'computers' in json_data:
            computers = json_data['computers']
            print(f"💻 Found {len(computers)} computers")
            
            # Analyze OS versions
            os_versions = {}
            for comp in computers:
                os = comp.get('os', 'Unknown')
                os_versions[os] = os_versions.get(os, 0) + 1
            
            print("   OS Distribution:")
            for os, count in os_versions.items():
                print(f"     - {os}: {count}")
        
        # Analyze SPNs (potential Kerberoasting targets)
        if 'spns' in json_data:
            spns = json_data['spns']
            print(f"🎫 Found {len(spns)} SPNs")
            
            # Group by service type
            services = {}
            for spn in spns:
                service = spn.get('service', 'Unknown')
                services[service] = services.get(service, 0) + 1
            
            print("   Service Distribution:")
            for service, count in services.items():
                print(f"     - {service}: {count}")
            
            # Highlight potential Kerberoasting targets
            kerberoast_targets = [spn for spn in spns if spn.get('service') in 
                                 ['HTTP', 'MSSQLSvc', 'FTP', 'IMAP', 'POP']]
            if kerberoast_targets:
                print(f"   🎯 {len(kerberoast_targets)} potential Kerberoasting targets")
        
        # Analyze shares
        if 'shares' in json_data:
            shares = json_data['shares']
            interesting_shares = [s for s in shares if s.get('name') not in 
                                 ['ADMIN$', 'C$', 'IPC$', 'NETLOGON', 'SYSVOL']]
            
            print(f"📁 Found {len(shares)} shares")
            if interesting_shares:
                print(f"   📂 {len(interesting_shares)} custom shares")
    
    def generate_recommendations(self, json_data):
        """Generate penetration testing recommendations based on findings"""
        if not json_data:
            return
        
        print("\n💡 PTJunior Recommendations:")
        print("=" * 50)
        
        recommendations = []
        
        # Check for SPNs (Kerberoasting)
        if 'spns' in json_data and json_data['spns']:
            recommendations.append({
                'attack': 'Kerberoasting',
                'description': 'Service accounts with SPNs found',
                'command': 'impacket-GetUserSPNs',
                'priority': 'High'
            })
        
        # Check for admin users
        if 'users' in json_data:
            admin_users = [u for u in json_data['users'] if 'admin' in u.get('name', '').lower()]
            if admin_users:
                recommendations.append({
                    'attack': 'Password Spraying',
                    'description': f'{len(admin_users)} admin users found',
                    'command': 'crackmapexec smb',
                    'priority': 'Medium'
                })
        
        # Check for custom shares
        if 'shares' in json_data:
            custom_shares = [s for s in json_data['shares'] if s.get('name') not in 
                           ['ADMIN$', 'C$', 'IPC$', 'NETLOGON', 'SYSVOL']]
            if custom_shares:
                recommendations.append({
                    'attack': 'Share Enumeration',
                    'description': f'{len(custom_shares)} custom shares found',
                    'command': 'smbclient',
                    'priority': 'Medium'
                })
        
        # Check for old OS versions
        if 'computers' in json_data:
            old_systems = [c for c in json_data['computers'] if 'Windows Server 2008' in c.get('os', '')]
            if old_systems:
                recommendations.append({
                    'attack': 'OS Exploitation',
                    'description': f'{len(old_systems)} legacy systems found',
                    'command': 'searchsploit',
                    'priority': 'High'
                })
        
        # Display recommendations
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec['attack']} ({rec['priority']} Priority)")
            print(f"   Description: {rec['description']}")
            print(f"   Tool: {rec['command']}")
            print()
    
    def save_results(self, json_data, filename=None):
        """Save results to file"""
        if not filename:
            timestamp = int(time.time())
            filename = f"ptjunior_adrecon_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(json_data, f, indent=2)
            print(f"💾 Results saved to: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Error saving results: {e}")
            return None
    
    def run_targeted_enumeration(self, modules):
        """Run enumeration for specific modules only"""
        print(f"🎯 Running targeted enumeration for: {', '.join(modules)}")
        return self.run_json_enumeration(modules)
    
    def run_complete_assessment(self):
        """Run complete AD assessment workflow"""
        print("🚀 Starting PTJunior AD Assessment")
        print("=" * 50)
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Run JSON enumeration for quick analysis
        json_data = self.run_json_enumeration()
        if not json_data:
            print("❌ Failed to get JSON data, trying full enumeration...")
            stdout = self.run_full_enumeration()
            if stdout:
                print("✅ Full enumeration completed, check output directory")
            return False
        
        # Analyze results
        self.analyze_results(json_data)
        
        # Generate recommendations
        self.generate_recommendations(json_data)
        
        # Save results
        filename = self.save_results(json_data)
        
        return True

def main():
    parser = argparse.ArgumentParser(description='PTJunior ADRecon Integration Example')
    parser.add_argument('--target', required=True, help='Domain Controller IP/FQDN')
    parser.add_argument('--domain', required=True, help='Domain name')
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--modules', help='Comma-separated list of modules (optional)')
    parser.add_argument('--json-only', action='store_true', help='Only run JSON enumeration')
    
    args = parser.parse_args()
    
    # Create PTJunior instance
    ptjunior = PTJuniorADRecon(
        target=args.target,
        domain=args.domain,
        username=args.username,
        password=args.password
    )
    
    # Run assessment
    if args.modules:
        modules = args.modules.split(',')
        json_data = ptjunior.run_targeted_enumeration(modules)
        if json_data:
            ptjunior.analyze_results(json_data)
            ptjunior.generate_recommendations(json_data)
            ptjunior.save_results(json_data)
    elif args.json_only:
        json_data = ptjunior.run_json_enumeration()
        if json_data:
            ptjunior.analyze_results(json_data)
            ptjunior.generate_recommendations(json_data)
            ptjunior.save_results(json_data)
    else:
        ptjunior.run_complete_assessment()

if __name__ == '__main__':
    main() 