# Bash-ADRecon

Linux-based Active Directory reconnaissance tool for penetration testing. Provides comprehensive AD enumeration with JSON output optimized for AI analysis.

## Installation (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install ldap-utils smbclient dnsutils
git clone https://github.com/danieltk76/ad-recon-bash.git
cd ad-recon-bash
chmod +x *.sh
```

## Usage

### Quick Start
```bash
./quick-adrecon.sh <domain_controller> <domain> <username> <password>
```

### JSON Output (AI-Optimized)
```bash
./bash-adrecon-json.sh -d <dc> -D <domain> -u <user> -p <pass> > results.json
```

### Full Enumeration
```bash
./bash-adrecon.sh -d <dc> -D <domain> -u <user> -p <pass>
```

## Output Data

JSON format includes:
- `users` - Domain users with attributes
- `groups` - Domain groups and memberships  
- `computers` - Domain computers and OS info
- `spns` - Service Principal Names (Kerberoasting targets)
- `shares` - SMB shares
- `domain` - Domain configuration
- `trusts` - Domain trust relationships

## Files

- `bash-adrecon.sh` - Main tool (CSV output)
- `bash-adrecon-json.sh` - AI-optimized JSON output
- `quick-adrecon.sh` - Simple wrapper
- `ptjunior-adrecon-example.py` - Python integration example

## Example

```bash
# Target: 10.129.28.122, Domain: example.com, User: henry
./bash-adrecon-json.sh -d 10.129.28.122 -D example.com -u henry -p 'password' > ad_data.json
```

Generates structured JSON for automated analysis and attack path identification. 