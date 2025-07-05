#!/bin/bash

# ========================================================================
# Bash-ADRecon: Linux-based Active Directory Reconnaissance Tool
# Author: AI Assistant
# Description: Bash version of ADRecon for Linux-based AD enumeration
# ========================================================================

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
DOMAIN_CONTROLLER=""
DOMAIN=""
USERNAME=""
PASSWORD=""
OUTPUT_DIR=""
COLLECT_ALL=true
VERBOSE=false
LDAP_PORT=389
SMB_PORT=445
DNS_PORT=53

# Available modules
declare -A MODULES=(
    ["domain"]=true
    ["forest"]=true
    ["users"]=true
    ["groups"]=true
    ["computers"]=true
    ["trusts"]=true
    ["gpos"]=true
    ["dns"]=true
    ["shares"]=true
    ["sessions"]=true
    ["spns"]=true
    ["schema"]=true
    ["sites"]=true
    ["subnets"]=true
    ["policies"]=true
)

# Function to display banner
show_banner() {
    echo -e "${BLUE}
    ╔═══════════════════════════════════════════════════════════════╗
    ║                        Bash-ADRecon                           ║
    ║          Linux-based Active Directory Reconnaissance          ║
    ║                     Version 1.0                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    ${NC}"
}

# Function to display usage
show_help() {
    echo -e "${GREEN}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo "Required Parameters:"
    echo "  -d, --domain-controller   Domain Controller IP or FQDN"
    echo "  -D, --domain             Domain name (e.g., example.com)"
    echo "  -u, --username           Username for authentication"
    echo "  -p, --password           Password for authentication"
    echo ""
    echo "Optional Parameters:"
    echo "  -o, --output-dir         Output directory (default: ADRecon-Report-\$(date +%Y%m%d_%H%M%S))"
    echo "  -c, --collect            Comma-separated list of modules to collect"
    echo "  -v, --verbose            Enable verbose output"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Available Modules:"
    echo "  domain, forest, users, groups, computers, trusts, gpos, dns,"
    echo "  shares, sessions, spns, schema, sites, subnets, policies"
    echo ""
    echo "Examples:"
    echo "  $0 -d 192.168.1.10 -D example.com -u admin -p password"
    echo "  $0 -d dc01.example.com -D example.com -u admin -p password -c users,groups"
    echo "  $0 -d 192.168.1.10 -D example.com -u admin -p password -o /tmp/adrecon -v"
}

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[*]${NC} $message" | tee -a "$OUTPUT_DIR/adrecon.log"
            ;;
        "WARN")
            echo -e "${YELLOW}[!]${NC} $message" | tee -a "$OUTPUT_DIR/adrecon.log"
            ;;
        "ERROR")
            echo -e "${RED}[!]${NC} $message" | tee -a "$OUTPUT_DIR/adrecon.log"
            ;;
        "DEBUG")
            if [[ "$VERBOSE" == true ]]; then
                echo -e "${BLUE}[DEBUG]${NC} $message" | tee -a "$OUTPUT_DIR/adrecon.log"
            fi
            ;;
    esac
}

# Function to check required tools
check_dependencies() {
    local required_tools=("ldapsearch" "smbclient" "rpcclient" "dig" "nslookup" "awk" "sed" "grep" "sort" "uniq")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing required tools: ${missing_tools[*]}"
        echo -e "${RED}Please install the missing tools:${NC}"
        echo "  Ubuntu/Debian: sudo apt-get install ldap-utils smbclient dnsutils"
        echo "  CentOS/RHEL: sudo yum install openldap-clients samba-client bind-utils"
        exit 1
    fi
}

# Function to test connectivity
test_connectivity() {
    log_message "INFO" "Testing connectivity to $DOMAIN_CONTROLLER"
    
    # Test LDAP connectivity
    if timeout 5 bash -c "</dev/tcp/$DOMAIN_CONTROLLER/$LDAP_PORT" 2>/dev/null; then
        log_message "INFO" "LDAP port $LDAP_PORT is accessible"
    else
        log_message "WARN" "LDAP port $LDAP_PORT is not accessible"
    fi
    
    # Test SMB connectivity
    if timeout 5 bash -c "</dev/tcp/$DOMAIN_CONTROLLER/$SMB_PORT" 2>/dev/null; then
        log_message "INFO" "SMB port $SMB_PORT is accessible"
    else
        log_message "WARN" "SMB port $SMB_PORT is not accessible"
    fi
    
    # Test DNS connectivity
    if timeout 5 bash -c "</dev/tcp/$DOMAIN_CONTROLLER/$DNS_PORT" 2>/dev/null; then
        log_message "INFO" "DNS port $DNS_PORT is accessible"
    else
        log_message "WARN" "DNS port $DNS_PORT is not accessible"
    fi
}

# Function to get domain information
get_domain_info() {
    if [[ "${MODULES[domain]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting domain information"
    local output_file="$OUTPUT_DIR/domain_info.csv"
    
    # Create CSV header
    echo "Attribute,Value" > "$output_file"
    
    # Get basic domain info via LDAP
    local ldap_result=$(ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s base "(objectClass=*)" \
        dn distinguishedName objectClass whenCreated whenChanged \
        2>/dev/null | grep -v "^#" | grep -v "^$" || true)
    
    if [[ -n "$ldap_result" ]]; then
        echo "Domain Controller,$DOMAIN_CONTROLLER" >> "$output_file"
        echo "Domain Name,$DOMAIN" >> "$output_file"
        echo "Domain DN,DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" >> "$output_file"
        
        # Extract creation time if available
        local creation_time=$(echo "$ldap_result" | grep "whenCreated:" | cut -d' ' -f2- | head -1)
        if [[ -n "$creation_time" ]]; then
            echo "Domain Created,$creation_time" >> "$output_file"
        fi
        
        # Extract last modified time
        local modified_time=$(echo "$ldap_result" | grep "whenChanged:" | cut -d' ' -f2- | head -1)
        if [[ -n "$modified_time" ]]; then
            echo "Domain Modified,$modified_time" >> "$output_file"
        fi
        
        log_message "INFO" "Domain information saved to $output_file"
    else
        log_message "ERROR" "Failed to retrieve domain information"
    fi
}

# Function to get forest information
get_forest_info() {
    if [[ "${MODULES[forest]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting forest information"
    local output_file="$OUTPUT_DIR/forest_info.csv"
    
    echo "Attribute,Value" > "$output_file"
    
    # Get forest root domain
    local forest_root=$(ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "CN=Configuration,DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=crossRef)" \
        dnsRoot | grep "dnsRoot:" | head -1 | cut -d' ' -f2 || true)
    
    if [[ -n "$forest_root" ]]; then
        echo "Forest Root Domain,$forest_root" >> "$output_file"
        log_message "INFO" "Forest information saved to $output_file"
    else
        log_message "WARN" "Could not determine forest root domain"
    fi
}

# Function to get user information
get_users() {
    if [[ "${MODULES[users]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting user information"
    local output_file="$OUTPUT_DIR/users.csv"
    
    echo "Name,SamAccountName,Description,LastLogon,BadPasswordTime,PasswordLastSet,AccountExpires,UserAccountControl,MemberOf" > "$output_file"
    
    # Get all users
    ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=user)" \
        cn sAMAccountName description lastLogon badPasswordTime pwdLastSet accountExpires userAccountControl memberOf \
        2>/dev/null | \
    awk '
    BEGIN { 
        name=""; samname=""; desc=""; lastlogon=""; badpwd=""; pwdlast=""; expires=""; uac=""; memberof=""
    }
    /^dn:/ { 
        if (samname != "") {
            printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", name, samname, desc, lastlogon, badpwd, pwdlast, expires, uac, memberof
        }
        name=""; samname=""; desc=""; lastlogon=""; badpwd=""; pwdlast=""; expires=""; uac=""; memberof=""
    }
    /^cn:/ { name = substr($0, 5) }
    /^sAMAccountName:/ { samname = substr($0, 17) }
    /^description:/ { desc = substr($0, 13) }
    /^lastLogon:/ { lastlogon = substr($0, 11) }
    /^badPasswordTime:/ { badpwd = substr($0, 18) }
    /^pwdLastSet:/ { pwdlast = substr($0, 12) }
    /^accountExpires:/ { expires = substr($0, 16) }
    /^userAccountControl:/ { uac = substr($0, 20) }
    /^memberOf:/ { memberof = memberof substr($0, 10) ";" }
    END { 
        if (samname != "") {
            printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n", name, samname, desc, lastlogon, badpwd, pwdlast, expires, uac, memberof
        }
    }
    ' >> "$output_file"
    
    local user_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((user_count - 1)) users, saved to $output_file"
}

# Function to get group information
get_groups() {
    if [[ "${MODULES[groups]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting group information"
    local output_file="$OUTPUT_DIR/groups.csv"
    
    echo "Name,SamAccountName,Description,GroupType,MemberCount,Members" > "$output_file"
    
    # Get all groups
    ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=group)" \
        cn sAMAccountName description groupType member \
        2>/dev/null | \
    awk '
    BEGIN { 
        name=""; samname=""; desc=""; grouptype=""; members=""
    }
    /^dn:/ { 
        if (samname != "") {
            membercount = gsub(/;/, ";", members)
            printf "%s,%s,%s,%s,%d,%s\n", name, samname, desc, grouptype, membercount, members
        }
        name=""; samname=""; desc=""; grouptype=""; members=""
    }
    /^cn:/ { name = substr($0, 5) }
    /^sAMAccountName:/ { samname = substr($0, 17) }
    /^description:/ { desc = substr($0, 13) }
    /^groupType:/ { grouptype = substr($0, 11) }
    /^member:/ { members = members substr($0, 8) ";" }
    END { 
        if (samname != "") {
            membercount = gsub(/;/, ";", members)
            printf "%s,%s,%s,%s,%d,%s\n", name, samname, desc, grouptype, membercount, members
        }
    }
    ' >> "$output_file"
    
    local group_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((group_count - 1)) groups, saved to $output_file"
}

# Function to get computer information
get_computers() {
    if [[ "${MODULES[computers]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting computer information"
    local output_file="$OUTPUT_DIR/computers.csv"
    
    echo "Name,SamAccountName,OperatingSystem,OperatingSystemVersion,LastLogon,PasswordLastSet,UserAccountControl,ServicePrincipalName" > "$output_file"
    
    # Get all computers
    ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=computer)" \
        cn sAMAccountName operatingSystem operatingSystemVersion lastLogon pwdLastSet userAccountControl servicePrincipalName \
        2>/dev/null | \
    awk '
    BEGIN { 
        name=""; samname=""; os=""; osver=""; lastlogon=""; pwdlast=""; uac=""; spn=""
    }
    /^dn:/ { 
        if (samname != "") {
            printf "%s,%s,%s,%s,%s,%s,%s,%s\n", name, samname, os, osver, lastlogon, pwdlast, uac, spn
        }
        name=""; samname=""; os=""; osver=""; lastlogon=""; pwdlast=""; uac=""; spn=""
    }
    /^cn:/ { name = substr($0, 5) }
    /^sAMAccountName:/ { samname = substr($0, 17) }
    /^operatingSystem:/ { os = substr($0, 17) }
    /^operatingSystemVersion:/ { osver = substr($0, 25) }
    /^lastLogon:/ { lastlogon = substr($0, 11) }
    /^pwdLastSet:/ { pwdlast = substr($0, 12) }
    /^userAccountControl:/ { uac = substr($0, 20) }
    /^servicePrincipalName:/ { spn = spn substr($0, 22) ";" }
    END { 
        if (samname != "") {
            printf "%s,%s,%s,%s,%s,%s,%s,%s\n", name, samname, os, osver, lastlogon, pwdlast, uac, spn
        }
    }
    ' >> "$output_file"
    
    local computer_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((computer_count - 1)) computers, saved to $output_file"
}

# Function to get trust information
get_trusts() {
    if [[ "${MODULES[trusts]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting trust information"
    local output_file="$OUTPUT_DIR/trusts.csv"
    
    echo "TrustPartner,TrustDirection,TrustType,TrustAttributes,WhenCreated,WhenChanged" > "$output_file"
    
    # Get trust relationships
    ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=trustedDomain)" \
        trustPartner trustDirection trustType trustAttributes whenCreated whenChanged \
        2>/dev/null | \
    awk '
    BEGIN { 
        partner=""; direction=""; type=""; attributes=""; created=""; changed=""
    }
    /^dn:/ { 
        if (partner != "") {
            printf "%s,%s,%s,%s,%s,%s\n", partner, direction, type, attributes, created, changed
        }
        partner=""; direction=""; type=""; attributes=""; created=""; changed=""
    }
    /^trustPartner:/ { partner = substr($0, 14) }
    /^trustDirection:/ { direction = substr($0, 16) }
    /^trustType:/ { type = substr($0, 11) }
    /^trustAttributes:/ { attributes = substr($0, 17) }
    /^whenCreated:/ { created = substr($0, 13) }
    /^whenChanged:/ { changed = substr($0, 13) }
    END { 
        if (partner != "") {
            printf "%s,%s,%s,%s,%s,%s\n", partner, direction, type, attributes, created, changed
        }
    }
    ' >> "$output_file"
    
    local trust_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((trust_count - 1)) trusts, saved to $output_file"
}

# Function to get SPNs
get_spns() {
    if [[ "${MODULES[spns]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting Service Principal Names (SPNs)"
    local output_file="$OUTPUT_DIR/spns.csv"
    
    echo "Account,SPN,Service,Host" > "$output_file"
    
    # Get all SPNs
    ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(servicePrincipalName=*)" \
        sAMAccountName servicePrincipalName \
        2>/dev/null | \
    awk '
    BEGIN { account="" }
    /^dn:/ { account="" }
    /^sAMAccountName:/ { account = substr($0, 17) }
    /^servicePrincipalName:/ { 
        spn = substr($0, 22)
        split(spn, parts, "/")
        service = parts[1]
        host = parts[2]
        if (account != "") {
            printf "%s,%s,%s,%s\n", account, spn, service, host
        }
    }
    ' >> "$output_file"
    
    local spn_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((spn_count - 1)) SPNs, saved to $output_file"
}

# Function to get SMB shares
get_shares() {
    if [[ "${MODULES[shares]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting SMB shares"
    local output_file="$OUTPUT_DIR/shares.csv"
    
    echo "ShareName,Type,Comment" > "$output_file"
    
    # Get SMB shares
    smbclient -L "//$DOMAIN_CONTROLLER" -U "$USERNAME%$PASSWORD" 2>/dev/null | \
    grep -E "^\s+[A-Za-z]" | \
    awk '{
        sharename = $1
        type = $2
        comment = ""
        for (i = 3; i <= NF; i++) {
            comment = comment $i " "
        }
        gsub(/^[ \t]+|[ \t]+$/, "", comment)
        printf "%s,%s,%s\n", sharename, type, comment
    }' >> "$output_file"
    
    local share_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((share_count - 1)) shares, saved to $output_file"
}

# Function to get DNS information
get_dns() {
    if [[ "${MODULES[dns]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting DNS information"
    local output_file="$OUTPUT_DIR/dns.csv"
    
    echo "RecordType,Name,Value" > "$output_file"
    
    # Get DNS records
    dig @"$DOMAIN_CONTROLLER" "$DOMAIN" ANY +short 2>/dev/null | while read -r record; do
        if [[ -n "$record" ]]; then
            echo "ANY,$DOMAIN,$record" >> "$output_file"
        fi
    done
    
    # Get SRV records
    dig @"$DOMAIN_CONTROLLER" "_ldap._tcp.$DOMAIN" SRV +short 2>/dev/null | while read -r record; do
        if [[ -n "$record" ]]; then
            echo "SRV,_ldap._tcp.$DOMAIN,$record" >> "$output_file"
        fi
    done
    
    dig @"$DOMAIN_CONTROLLER" "_kerberos._tcp.$DOMAIN" SRV +short 2>/dev/null | while read -r record; do
        if [[ -n "$record" ]]; then
            echo "SRV,_kerberos._tcp.$DOMAIN,$record" >> "$output_file"
        fi
    done
    
    local dns_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((dns_count - 1)) DNS records, saved to $output_file"
}

# Function to get GPO information
get_gpos() {
    if [[ "${MODULES[gpos]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting Group Policy Objects (GPOs)"
    local output_file="$OUTPUT_DIR/gpos.csv"
    
    echo "Name,DisplayName,GUID,WhenCreated,WhenChanged,GPCFileSysPath" > "$output_file"
    
    # Get all GPOs
    ldapsearch -x -h "$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "CN=Policies,CN=System,DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=groupPolicyContainer)" \
        cn displayName objectGUID whenCreated whenChanged gPCFileSysPath \
        2>/dev/null | \
    awk '
    BEGIN { 
        name=""; displayname=""; guid=""; created=""; changed=""; path=""
    }
    /^dn:/ { 
        if (name != "") {
            printf "%s,%s,%s,%s,%s,%s\n", name, displayname, guid, created, changed, path
        }
        name=""; displayname=""; guid=""; created=""; changed=""; path=""
    }
    /^cn:/ { name = substr($0, 5) }
    /^displayName:/ { displayname = substr($0, 13) }
    /^objectGUID:/ { guid = substr($0, 12) }
    /^whenCreated:/ { created = substr($0, 13) }
    /^whenChanged:/ { changed = substr($0, 13) }
    /^gPCFileSysPath:/ { path = substr($0, 16) }
    END { 
        if (name != "") {
            printf "%s,%s,%s,%s,%s,%s\n", name, displayname, guid, created, changed, path
        }
    }
    ' >> "$output_file"
    
    local gpo_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((gpo_count - 1)) GPOs, saved to $output_file"
}

# Function to create summary report
create_summary() {
    log_message "INFO" "Creating summary report"
    local summary_file="$OUTPUT_DIR/summary.txt"
    
    {
        echo "=========================================="
        echo "Bash-ADRecon Summary Report"
        echo "=========================================="
        echo "Target: $DOMAIN_CONTROLLER"
        echo "Domain: $DOMAIN"
        echo "Date: $(date)"
        echo "=========================================="
        echo ""
        
        # Count results from each module
        for module in "${!MODULES[@]}"; do
            if [[ "${MODULES[$module]}" == true ]]; then
                local file_pattern="$OUTPUT_DIR/${module}*.csv"
                for file in $file_pattern; do
                    if [[ -f "$file" ]]; then
                        local count=$(($(wc -l < "$file") - 1))
                        echo "$(basename "$file" .csv): $count entries"
                    fi
                done
            fi
        done
        
        echo ""
        echo "=========================================="
        echo "Output files located in: $OUTPUT_DIR"
        echo "=========================================="
    } > "$summary_file"
    
    log_message "INFO" "Summary report saved to $summary_file"
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain-controller)
                DOMAIN_CONTROLLER="$2"
                shift 2
                ;;
            -D|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -u|--username)
                USERNAME="$2"
                shift 2
                ;;
            -p|--password)
                PASSWORD="$2"
                shift 2
                ;;
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -c|--collect)
                COLLECT_ALL=false
                # Reset all modules to false
                for module in "${!MODULES[@]}"; do
                    MODULES[$module]=false
                done
                # Enable specified modules
                IFS=',' read -ra ADDR <<< "$2"
                for module in "${ADDR[@]}"; do
                    if [[ -n "${MODULES[$module]}" ]]; then
                        MODULES[$module]=true
                    else
                        log_message "WARN" "Unknown module: $module"
                    fi
                done
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Function to validate required parameters
validate_params() {
    local errors=()
    
    if [[ -z "$DOMAIN_CONTROLLER" ]]; then
        errors+=("Domain Controller (-d) is required")
    fi
    
    if [[ -z "$DOMAIN" ]]; then
        errors+=("Domain (-D) is required")
    fi
    
    if [[ -z "$USERNAME" ]]; then
        errors+=("Username (-u) is required")
    fi
    
    if [[ -z "$PASSWORD" ]]; then
        errors+=("Password (-p) is required")
    fi
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        for error in "${errors[@]}"; do
            log_message "ERROR" "$error"
        done
        echo ""
        show_help
        exit 1
    fi
}

# Main execution function
main() {
    show_banner
    
    # Parse command line arguments
    parse_args "$@"
    
    # Validate parameters
    validate_params
    
    # Set default output directory if not specified
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="ADRecon-Report-$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Check dependencies
    check_dependencies
    
    # Test connectivity
    test_connectivity
    
    # Initialize log file
    echo "Bash-ADRecon started at $(date)" > "$OUTPUT_DIR/adrecon.log"
    
    log_message "INFO" "Starting Active Directory enumeration"
    log_message "INFO" "Target: $DOMAIN_CONTROLLER"
    log_message "INFO" "Domain: $DOMAIN"
    log_message "INFO" "Output Directory: $OUTPUT_DIR"
    
    # Execute enabled modules
    get_domain_info
    get_forest_info
    get_users
    get_groups
    get_computers
    get_trusts
    get_spns
    get_shares
    get_dns
    get_gpos
    
    # Create summary report
    create_summary
    
    log_message "INFO" "Enumeration completed successfully"
    log_message "INFO" "Check $OUTPUT_DIR for all output files"
    
    # Display summary
    cat "$OUTPUT_DIR/summary.txt"
}

# Execute main function with all arguments
main "$@" 