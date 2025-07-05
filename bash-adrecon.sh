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
LDAP_PORT=389
SMB_PORT=445
DNS_PORT=53

# Core enumeration modules (all enabled by default)

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
    echo -e "${GREEN}Usage: $0 -d <DOMAIN_CONTROLLER> -D <DOMAIN> -u <USERNAME> -p <PASSWORD>${NC}"
    echo ""
    echo "Parameters:"
    echo "  -d, --domain-controller   Domain Controller IP or FQDN"
    echo "  -D, --domain             Domain name (e.g., example.com)"
    echo "  -u, --username           Username for authentication"
    echo "  -p, --password           Password for authentication"
    echo ""
    echo "Example:"
    echo "  $0 -d 192.168.1.10 -D example.com -u admin -p password"
    echo ""
    echo "Enumerates everything: users, groups, shares, permissions, relationships, etc."
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
            echo -e "${BLUE}[DEBUG]${NC} $message" | tee -a "$OUTPUT_DIR/adrecon.log"
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
    log_message "INFO" "Collecting domain information"
    local output_file="$OUTPUT_DIR/domain_info.csv"
    
    # Create CSV header
    echo "Attribute,Value" > "$output_file"
    
    # Get basic domain info via LDAP
    local ldap_result=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
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
    log_message "INFO" "Collecting forest information"
    local output_file="$OUTPUT_DIR/forest_info.csv"
    
    echo "Attribute,Value" > "$output_file"
    
    # Get forest root domain
    local forest_root=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
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
    log_message "INFO" "Collecting user information"
    local output_file="$OUTPUT_DIR/users.csv"
    
    echo "Name,SamAccountName,Description,LastLogon,BadPasswordTime,PasswordLastSet,AccountExpires,UserAccountControl,MemberOf,RID" > "$output_file"
    
    # Try LDAP first
    local ldap_result=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=user)" \
        cn sAMAccountName description lastLogon badPasswordTime pwdLastSet accountExpires userAccountControl memberOf \
        2>/dev/null | head -20)
    
    if [[ "$ldap_result" == *"search:"* ]] && [[ "$ldap_result" != *"Referral"* ]]; then
        # LDAP is working, use it
        log_message "INFO" "Using LDAP for user enumeration"
        ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
            -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
            -s sub "(objectClass=user)" \
            cn sAMAccountName description lastLogon badPasswordTime pwdLastSet accountExpires userAccountControl memberOf \
            2>/dev/null | \
        awk '
        BEGIN { 
            name=""; samname=""; desc=""; lastlogon=""; badpwd=""; pwdlast=""; expires=""; uac=""; memberof=""; rid=""
        }
        /^dn:/ { 
            if (samname != "") {
                printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", name, samname, desc, lastlogon, badpwd, pwdlast, expires, uac, memberof, rid
            }
            name=""; samname=""; desc=""; lastlogon=""; badpwd=""; pwdlast=""; expires=""; uac=""; memberof=""; rid=""
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
                printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", name, samname, desc, lastlogon, badpwd, pwdlast, expires, uac, memberof, rid
            }
        }
        ' >> "$output_file"
    else
        # LDAP failed, use RPC
        log_message "INFO" "LDAP failed, using RPC for user enumeration"
        
        # Get users via RPC
        rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "enumdomusers" 2>/dev/null | \
        while IFS= read -r line; do
            if [[ "$line" =~ user:\[([^\]]+)\].*rid:\[([^\]]+)\] ]]; then
                username="${BASH_REMATCH[1]}"
                rid="${BASH_REMATCH[2]}"
                
                # Get additional user info via RPC
                user_info=$(rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "queryuser $rid" 2>/dev/null || echo "")
                
                # Parse user info
                full_name=$(echo "$user_info" | grep "Full Name" | cut -d: -f2- | sed 's/^ *//' || echo "")
                description=$(echo "$user_info" | grep "Description" | cut -d: -f2- | sed 's/^ *//' || echo "")
                
                # Output user data
                echo "$full_name,$username,$description,,,,,,$rid" >> "$output_file"
            fi
        done
    fi
    
    local user_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((user_count - 1)) users, saved to $output_file"
}

# Function to get group information
get_groups() {
    log_message "INFO" "Collecting group information"
    local output_file="$OUTPUT_DIR/groups.csv"
    
    echo "Name,SamAccountName,Description,GroupType,MemberCount,Members,RID" > "$output_file"
    
    # Try LDAP first
    local ldap_result=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=group)" \
        cn sAMAccountName description groupType member \
        2>/dev/null | head -20)
    
    if [[ "$ldap_result" == *"search:"* ]] && [[ "$ldap_result" != *"Referral"* ]]; then
        # LDAP is working, use it
        log_message "INFO" "Using LDAP for group enumeration"
        ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
            -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
            -s sub "(objectClass=group)" \
            cn sAMAccountName description groupType member \
            2>/dev/null | \
        awk '
        BEGIN { 
            name=""; samname=""; desc=""; grouptype=""; members=""; rid=""
        }
        /^dn:/ { 
            if (samname != "") {
                membercount = gsub(/;/, ";", members)
                printf "%s,%s,%s,%s,%d,%s,%s\n", name, samname, desc, grouptype, membercount, members, rid
            }
            name=""; samname=""; desc=""; grouptype=""; members=""; rid=""
        }
        /^cn:/ { name = substr($0, 5) }
        /^sAMAccountName:/ { samname = substr($0, 17) }
        /^description:/ { desc = substr($0, 13) }
        /^groupType:/ { grouptype = substr($0, 11) }
        /^member:/ { members = members substr($0, 8) ";" }
        END { 
            if (samname != "") {
                membercount = gsub(/;/, ";", members)
                printf "%s,%s,%s,%s,%d,%s,%s\n", name, samname, desc, grouptype, membercount, members, rid
            }
        }
        ' >> "$output_file"
    else
        # LDAP failed, use RPC
        log_message "INFO" "LDAP failed, using RPC for group enumeration"
        
        # Get groups via RPC (simplified to avoid hanging)
        rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "enumdomgroups" 2>/dev/null | \
        while IFS= read -r line; do
            if [[ "$line" =~ group:\[([^\]]+)\].*rid:\[([^\]]+)\] ]]; then
                groupname="${BASH_REMATCH[1]}"
                rid="${BASH_REMATCH[2]}"
                
                # Output basic group data (avoid hanging on additional queries)
                echo "$groupname,$groupname,,,$rid,,$rid" >> "$output_file"
            fi
        done
    fi
    
    local group_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((group_count - 1)) groups, saved to $output_file"
}

# Function to get computer information
get_computers() {
    log_message "INFO" "Collecting computer information"
    local output_file="$OUTPUT_DIR/computers.csv"
    
    echo "Name,SamAccountName,OperatingSystem,OperatingSystemVersion,LastLogon,PasswordLastSet,UserAccountControl,ServicePrincipalName" > "$output_file"
    
    # Try LDAP first, fall back to RPC if it fails
    ldap_result=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=computer)" \
        cn sAMAccountName operatingSystem operatingSystemVersion lastLogon pwdLastSet userAccountControl servicePrincipalName \
        2>/dev/null | head -20)

    if [[ -n "$ldap_result" && "$ldap_result" != *"referral"* ]]; then
        # LDAP worked, parse the full result
        ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
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
    else
        # LDAP failed, use RPC fallback
        log_message "INFO" "LDAP failed, using RPC for computer enumeration"
        
        # Get basic computer list via RPC
        rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "enumdomusers" 2>/dev/null | \
        grep -E "\$" | \
        while read -r line; do
            if [[ "$line" =~ \[([^\]]+)\] ]]; then
                computer_name="${BASH_REMATCH[1]}"
                echo "$computer_name,$computer_name,Unknown,Unknown,Unknown,Unknown,Unknown,Unknown" >> "$output_file"
            fi
        done
    fi
    
    local computer_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((computer_count - 1)) computers, saved to $output_file"
}

# Function to get trust information
get_trusts() {
    log_message "INFO" "Collecting trust information"
    local output_file="$OUTPUT_DIR/trusts.csv"
    
    echo "TrustPartner,TrustDirection,TrustType,TrustAttributes,WhenCreated,WhenChanged" > "$output_file"
    
    # Get trust relationships with timeout
    timeout 30 ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
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
    log_message "INFO" "Collecting Service Principal Names (SPNs)"
    local output_file="$OUTPUT_DIR/spns.csv"
    
    echo "Account,SPN,Service,Host" > "$output_file"
    
    # Get all SPNs with timeout
    timeout 30 ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
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
    log_message "INFO" "Collecting Group Policy Objects (GPOs)"
    local output_file="$OUTPUT_DIR/gpos.csv"
    
    echo "Name,DisplayName,GUID,WhenCreated,WhenChanged,GPCFileSysPath" > "$output_file"
    
    # Get all GPOs with timeout
    timeout 30 ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
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

# Function to get additional RPC information
get_rpc_info() {
    log_message "INFO" "Collecting additional RPC information"
    local output_file="$OUTPUT_DIR/rpc_info.csv"
    
    echo "Type,Name,Description,Additional_Info" > "$output_file"
    
    # Get domain info via RPC (simplified to avoid hanging)
    local domain_info=$(rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "lsaquery" 2>/dev/null | head -10 || echo "")
    if [[ -n "$domain_info" ]]; then
        domain_name=$(echo "$domain_info" | grep "Domain Name:" | cut -d: -f2- | sed 's/^ *//' | head -1)
        domain_sid=$(echo "$domain_info" | grep "Domain Sid:" | cut -d: -f2- | sed 's/^ *//' | head -1)
        echo "Domain,$domain_name,Domain SID,$domain_sid" >> "$output_file"
    fi
    
    log_message "INFO" "Additional RPC information saved to $output_file"
}

# Function to get detailed group memberships and relationships
get_group_relationships() {
    log_message "INFO" "Collecting group membership relationships"
    local output_file="$OUTPUT_DIR/group_relationships.csv"
    
    echo "User,Group_Name,Group_RID,Relationship_Type" > "$output_file"
    
    # Dynamically discover all user-group relationships
    if [[ -f "$OUTPUT_DIR/users.csv" && -f "$OUTPUT_DIR/groups.csv" ]]; then
        # For each user, get their group memberships
        while IFS=',' read -r full_name sam_account desc rest; do
            if [[ "$sam_account" != "SamAccountName" && -n "$sam_account" ]]; then
                # Get user RID from the users.csv (last column)
                user_rid=$(echo "$rest" | rev | cut -d',' -f1 | rev)
                
                # Get groups for this user via RPC - avoid subshell issues
                local temp_groups=$(rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "queryusergroups $user_rid" 2>/dev/null | \
                grep "group rid" | awk '{print $2}' | cut -d':' -f2 | tr -d '[]')
                
                # Process each group RID
                for group_rid in $temp_groups; do
                    # Find group name from groups.csv (RID is in last column)
                    group_name=$(awk -F',' -v rid="$group_rid" '$NF == rid {print $1}' "$OUTPUT_DIR/groups.csv" 2>/dev/null | head -1)
                    if [[ -n "$group_name" ]]; then
                        echo "$sam_account,$group_name,$group_rid,MEMBER_OF" >> "$output_file"
                    fi
                done
            fi
        done < "$OUTPUT_DIR/users.csv"
    fi
    
    log_message "INFO" "Group relationships saved to $output_file"
}

# Function to get comprehensive permissions like BloodHound
get_permissions() {
    log_message "INFO" "Collecting comprehensive permissions (BloodHound-style)"
    local output_file="$OUTPUT_DIR/permissions.csv"
    
    echo "Principal,Target_Object,Permission_Type,Access_Rights,Inherited,Description" > "$output_file"
    
    # 1. ANALYZE GROUP MEMBERSHIPS FOR PRIVILEGE ESCALATION
    log_message "INFO" "Analyzing group memberships for privilege escalation"
    if [[ -f "$OUTPUT_DIR/group_relationships.csv" ]]; then
        while IFS=',' read -r username group_name group_rid relationship; do
            if [[ "$username" != "Username" && -n "$username" ]]; then
                case "$group_name" in
                    "Domain Admins")
                        echo "$username,DOMAIN,GROUP_MEMBERSHIP,DOMAIN_ADMIN,false,Full domain administrative privileges" >> "$output_file"
                        echo "$username,ALL_COMPUTERS,LOCAL_ADMIN,FULL_CONTROL,false,Local admin on all domain computers" >> "$output_file"
                        echo "$username,DOMAIN,DCSYNC,REPLICATION_RIGHTS,false,Can perform DCSync attack" >> "$output_file"
                        ;;
                    "Enterprise Admins")
                        echo "$username,FOREST,GROUP_MEMBERSHIP,ENTERPRISE_ADMIN,false,Full forest administrative privileges" >> "$output_file"
                        echo "$username,ALL_DOMAINS,CROSS_DOMAIN_ADMIN,FULL_CONTROL,false,Admin across all forest domains" >> "$output_file"
                        ;;
                    "Schema Admins")
                        echo "$username,SCHEMA,GROUP_MEMBERSHIP,SCHEMA_ADMIN,false,Can modify AD schema" >> "$output_file"
                        echo "$username,DOMAIN,SCHEMA_PERSISTENCE,MODIFY_SCHEMA,false,Can create persistent backdoors via schema" >> "$output_file"
                        ;;
                    "Backup Operators")
                        echo "$username,DOMAIN_CONTROLLERS,BACKUP_RIGHTS,BACKUP_RESTORE,false,Can backup/restore domain controllers" >> "$output_file"
                        echo "$username,NTDS.DIT,FILE_ACCESS,READ_WRITE,false,Can access NTDS.DIT file" >> "$output_file"
                        ;;
                    "Account Operators")
                        echo "$username,DOMAIN_USERS,USER_MANAGEMENT,CREATE_DELETE_MODIFY,false,Can create/delete/modify user accounts" >> "$output_file"
                        echo "$username,DOMAIN_GROUPS,GROUP_MANAGEMENT,MODIFY_MEMBERSHIP,false,Can modify group memberships" >> "$output_file"
                        ;;
                    "Print Operators")
                        echo "$username,DOMAIN_CONTROLLERS,LOGON_RIGHTS,LOGON_LOCALLY,false,Can logon locally to domain controllers" >> "$output_file"
                        ;;
                    "Server Operators")
                        echo "$username,DOMAIN_CONTROLLERS,SERVICE_CONTROL,START_STOP_SERVICES,false,Can control services on domain controllers" >> "$output_file"
                        echo "$username,DOMAIN_CONTROLLERS,LOGON_RIGHTS,LOGON_LOCALLY,false,Can logon locally to domain controllers" >> "$output_file"
                        ;;
                    "Group Policy Creator Owners")
                        echo "$username,GROUP_POLICY,GPO_MANAGEMENT,CREATE_MODIFY_DELETE,false,Can create/modify Group Policy Objects" >> "$output_file"
                        echo "$username,ALL_COMPUTERS,GPO_CONTROL,COMPUTER_CONFIGURATION,false,Can push malicious GPOs to all computers" >> "$output_file"
                        ;;
                    "DNSAdmins")
                        echo "$username,DNS_SERVICE,DNS_MANAGEMENT,FULL_CONTROL,false,Can manipulate DNS records" >> "$output_file"
                        echo "$username,DOMAIN_CONTROLLERS,DLL_INJECTION,LOAD_LIBRARY,false,Can achieve code execution via DNS service" >> "$output_file"
                        ;;
                    "Service Account Managers")
                        echo "$username,SERVICE_ACCOUNTS,ACCOUNT_MANAGEMENT,MANAGE_SERVICE_ACCOUNTS,false,Can manage service accounts" >> "$output_file"
                        ;;
                    "Service Accounts")
                        echo "$username,SERVICE_PRINCIPALS,KERBEROS_AUTH,SERVICE_TICKETS,false,Service account vulnerable to Kerberoasting" >> "$output_file"
                        ;;
                    "Remote Desktop Users")
                        echo "$username,DOMAIN_CONTROLLERS,REMOTE_ACCESS,RDP_LOGON,false,Can RDP to domain controllers" >> "$output_file"
                        ;;
                    "Administrators")
                        echo "$username,LOCAL_SYSTEM,LOCAL_ADMIN,FULL_CONTROL,false,Local administrator privileges" >> "$output_file"
                        ;;
                esac
            fi
        done < "$OUTPUT_DIR/group_relationships.csv"
    fi
    
    # 2. ANALYZE SERVICE ACCOUNTS FOR KERBEROASTING
    log_message "INFO" "Analyzing service accounts for Kerberoasting"
    if [[ -f "$OUTPUT_DIR/users.csv" ]]; then
        while IFS=',' read -r name sam_account desc rest; do
            if [[ "$sam_account" != "SamAccountName" && "$sam_account" =~ svc|service ]]; then
                echo "$sam_account,KERBEROS_SERVICE,SERVICE_TICKET,KERBEROASTING_TARGET,false,Service account vulnerable to Kerberoasting attack" >> "$output_file"
                echo "$sam_account,DOMAIN,LATERAL_MOVEMENT,SERVICE_IMPERSONATION,false,Can be used for lateral movement if compromised" >> "$output_file"
            fi
        done < "$OUTPUT_DIR/users.csv"
    fi
    
    # 3. ANALYZE DELEGATION RIGHTS
    log_message "INFO" "Analyzing delegation rights"
    # Check for unconstrained delegation (high risk)
    ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        sAMAccountName 2>/dev/null | grep "sAMAccountName:" | while read -r line; do
        computer_name=$(echo "$line" | cut -d' ' -f2)
        echo "$computer_name,DOMAIN,UNCONSTRAINED_DELEGATION,FULL_DELEGATION,false,Computer has unconstrained delegation - can impersonate any user" >> "$output_file"
        echo "$computer_name,ALL_USERS,IMPERSONATION,STEAL_TOKENS,false,Can steal and reuse authentication tokens" >> "$output_file"
    done
    
    # Check for constrained delegation
    ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(&(objectClass=computer)(msDS-AllowedToDelegateTo=*))" \
        sAMAccountName msDS-AllowedToDelegateTo 2>/dev/null | \
    awk '/^sAMAccountName:/ {comp=$2} /^msDS-AllowedToDelegateTo:/ {print comp","$2}' | \
    while IFS=',' read -r computer_name target_service; do
        if [[ -n "$computer_name" && -n "$target_service" ]]; then
            echo "$computer_name,$target_service,CONSTRAINED_DELEGATION,SERVICE_DELEGATION,false,Can delegate to specific service: $target_service" >> "$output_file"
        fi
    done
    
    # 4. ANALYZE SHARE PERMISSIONS
    log_message "INFO" "Analyzing share permissions"
    if [[ -f "$OUTPUT_DIR/shares.csv" ]]; then
        while IFS=',' read -r share_name type comment; do
            if [[ "$share_name" != "ShareName" && "$share_name" != "Sharename" ]]; then
                case "$share_name" in
                    "ADMIN$")
                        echo "$USERNAME,$share_name,ADMIN_SHARE,FULL_CONTROL,false,Access to administrative share" >> "$output_file"
                        ;;
                    "C$"|"D$"|"E$")
                        echo "$USERNAME,$share_name,DRIVE_SHARE,FULL_CONTROL,false,Access to system drive share" >> "$output_file"
                        ;;
                    "SYSVOL")
                        echo "$USERNAME,$share_name,SYSVOL_ACCESS,READ_WRITE,false,Access to SYSVOL - can read/modify GPOs" >> "$output_file"
                        ;;
                    "NETLOGON")
                        echo "$USERNAME,$share_name,NETLOGON_ACCESS,READ_WRITE,false,Access to NETLOGON - can modify logon scripts" >> "$output_file"
                        ;;
                    *)
                        # Test access to custom shares
                        if timeout 5 smbclient "//$DOMAIN_CONTROLLER/$share_name" -U "$USERNAME%$PASSWORD" -c "exit" 2>/dev/null; then
                            echo "$USERNAME,$share_name,CUSTOM_SHARE,READ_ACCESS,false,Access to custom share" >> "$output_file"
                        fi
                        ;;
                esac
            fi
        done < "$OUTPUT_DIR/shares.csv"
    fi
    
    # 5. ANALYZE PASSWORDS AND AUTHENTICATION
    log_message "INFO" "Analyzing password and authentication settings"
    if [[ -f "$OUTPUT_DIR/users.csv" ]]; then
        while IFS=',' read -r name sam_account desc rest; do
            if [[ "$sam_account" != "SamAccountName" ]]; then
                # Check for accounts that might have passwords that don't expire
                user_account_control=$(echo "$rest" | cut -d',' -f7)
                if [[ "$user_account_control" == *"65536"* ]]; then
                    echo "$sam_account,PASSWORD_POLICY,NEVER_EXPIRES,WEAK_PASSWORD_POLICY,false,Password never expires" >> "$output_file"
                fi
                
                # Check for disabled accounts (might be service accounts)
                if [[ "$user_account_control" == *"514"* ]]; then
                    echo "$sam_account,ACCOUNT_STATUS,DISABLED,ACCOUNT_DISABLED,false,Account is disabled but might be reactivated" >> "$output_file"
                fi
            fi
        done < "$OUTPUT_DIR/users.csv"
    fi
    
    # 6. ANALYZE COMPUTER ACCOUNTS FOR VULNERABILITIES
    log_message "INFO" "Analyzing computer accounts"
    if [[ -f "$OUTPUT_DIR/computers.csv" ]]; then
        while IFS=',' read -r computer_name sam_account os version rest; do
            if [[ "$computer_name" != "Name" && -n "$computer_name" ]]; then
                # Check for potential vulnerabilities based on OS version
                case "$os" in
                    *"Windows Server 2003"*|*"Windows Server 2008"*|*"Windows XP"*|*"Windows 7"*)
                        echo "$computer_name,OPERATING_SYSTEM,OUTDATED_OS,VULNERABLE_SYSTEM,false,Outdated operating system with known vulnerabilities" >> "$output_file"
                        ;;
                    *"Windows Server 2012"*|*"Windows 8"*)
                        echo "$computer_name,OPERATING_SYSTEM,LEGACY_OS,POTENTIALLY_VULNERABLE,false,Legacy operating system that may have vulnerabilities" >> "$output_file"
                        ;;
                esac
            fi
        done < "$OUTPUT_DIR/computers.csv"
    fi
    
    # 7. ANALYZE TRUST RELATIONSHIPS
    log_message "INFO" "Analyzing trust relationships"
    # Get domain trusts
    rpcclient -U "$USERNAME%$PASSWORD" "$DOMAIN_CONTROLLER" -c "enumtrust" 2>/dev/null | \
    while IFS= read -r line; do
        if [[ "$line" =~ Domain.*:.*\[([^\]]+)\] ]]; then
            trusted_domain="${BASH_REMATCH[1]}"
            echo "$DOMAIN,$trusted_domain,DOMAIN_TRUST,BIDIRECTIONAL_TRUST,false,Trust relationship allows cross-domain attacks" >> "$output_file"
        fi
    done
    
    # 8. ANALYZE LAPS (Local Admin Password Solution) PERMISSIONS
    log_message "INFO" "Analyzing LAPS permissions"
    # Check who can read LAPS passwords
    ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=computer)" \
        ms-Mcs-AdmPwd 2>/dev/null | grep "ms-Mcs-AdmPwd:" | while read -r line; do
        echo "$USERNAME,LAPS_PASSWORDS,READ_PERMISSION,LOCAL_ADMIN_PASSWORDS,false,Can read LAPS local admin passwords" >> "$output_file"
        break  # Only need to report once if any LAPS passwords are readable
    done
    
    local perm_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((perm_count - 1)) detailed permissions, saved to $output_file"
}

# Function to analyze attack paths like BloodHound
analyze_attack_paths() {
    log_message "INFO" "Analyzing attack paths (BloodHound-style)"
    local output_file="$OUTPUT_DIR/attack_paths.csv"
    
    echo "Attack_Path_ID,Source_Principal,Target_Principal,Attack_Method,Privileges_Required,Risk_Level,Description,Mitigation" > "$output_file"
    
    # 1. SERVICE ACCOUNT ATTACKS
    log_message "INFO" "Analyzing service account attack paths"
    if [[ -f "$OUTPUT_DIR/users.csv" ]]; then
        # Kerberoasting attack paths
        grep -i "svc\|service" "$OUTPUT_DIR/users.csv" | while IFS=',' read -r name sam_account rest; do
            if [[ "$sam_account" != "SamAccountName" ]]; then
                echo "KERBEROAST_001,$USERNAME,$sam_account,KERBEROASTING,DOMAIN_USER,HIGH,Request TGS for service account and crack offline,Use strong passwords for service accounts" >> "$output_file"
            fi
        done
        
        # ASREPRoasting attack paths (accounts with pre-auth disabled)
        echo "ASREPROAST_001,$USERNAME,PREAUTH_DISABLED_USERS,ASREPROASTING,DOMAIN_USER,MEDIUM,Request AS-REP for accounts without pre-auth,Enable Kerberos pre-authentication" >> "$output_file"
    fi
    
    # 2. PRIVILEGE ESCALATION PATHS
    log_message "INFO" "Analyzing privilege escalation paths"
    if [[ -f "$OUTPUT_DIR/group_relationships.csv" ]]; then
        # Service account to domain admin
        grep -i "service.*account.*manager" "$OUTPUT_DIR/group_relationships.csv" | while IFS=',' read -r user group rest; do
            echo "PRIVESC_001,$user,DOMAIN_ADMINS,SERVICE_ACCOUNT_ABUSE,SERVICE_ACCOUNT_MANAGER,HIGH,Abuse service account management rights to escalate,Limit service account management permissions" >> "$output_file"
        done
        
        # Backup operators to domain admin
        grep -i "backup.*operator" "$OUTPUT_DIR/group_relationships.csv" | while IFS=',' read -r user group rest; do
            echo "PRIVESC_002,$user,DOMAIN_ADMINS,BACKUP_ABUSE,BACKUP_OPERATORS,CRITICAL,Use backup privileges to access NTDS.DIT,Restrict backup operator membership" >> "$output_file"
        done
        
        # Account operators to domain admin
        grep -i "account.*operator" "$OUTPUT_DIR/group_relationships.csv" | while IFS=',' read -r user group rest; do
            echo "PRIVESC_003,$user,DOMAIN_ADMINS,ACCOUNT_MANIPULATION,ACCOUNT_OPERATORS,HIGH,Create new admin accounts or modify existing ones,Limit account operator privileges" >> "$output_file"
        done
    fi
    
    # 3. LATERAL MOVEMENT PATHS
    log_message "INFO" "Analyzing lateral movement paths"
    # Domain admin to all computers
    grep -i "domain.*admin" "$OUTPUT_DIR/group_relationships.csv" 2>/dev/null | while IFS=',' read -r user group rest; do
        echo "LATERAL_001,$user,ALL_COMPUTERS,ADMIN_SHARES,DOMAIN_ADMIN,CRITICAL,Use admin shares to move laterally,Disable unnecessary admin shares" >> "$output_file"
        echo "LATERAL_002,$user,ALL_COMPUTERS,PSEXEC,DOMAIN_ADMIN,CRITICAL,Use PsExec or similar tools for remote execution,Monitor for unusual process creation" >> "$output_file"
        echo "LATERAL_003,$user,ALL_COMPUTERS,WMI,DOMAIN_ADMIN,CRITICAL,Use WMI for remote command execution,Monitor WMI activity" >> "$output_file"
        echo "LATERAL_004,$user,ALL_COMPUTERS,RDP,DOMAIN_ADMIN,HIGH,Use RDP for remote desktop access,Enable NLA and monitor RDP connections" >> "$output_file"
    done
    
    # 4. PERSISTENCE PATHS
    log_message "INFO" "Analyzing persistence paths"
    # Golden ticket attack path
    grep -i "domain.*admin\|krbtgt" "$OUTPUT_DIR/group_relationships.csv" 2>/dev/null | while IFS=',' read -r user group rest; do
        echo "PERSIST_001,$user,KRBTGT,GOLDEN_TICKET,DOMAIN_ADMIN,CRITICAL,Create golden tickets for long-term persistence,Regularly rotate krbtgt password" >> "$output_file"
        break
    done
    
    # Silver ticket attack path
    grep -i "svc\|service" "$OUTPUT_DIR/users.csv" 2>/dev/null | while IFS=',' read -r name sam_account rest; do
        if [[ "$sam_account" != "SamAccountName" ]]; then
            echo "PERSIST_002,$USERNAME,$sam_account,SILVER_TICKET,SERVICE_ACCOUNT_HASH,HIGH,Create silver tickets for specific services,Monitor for unusual service ticket usage" >> "$output_file"
        fi
    done
    
    # 5. CREDENTIAL THEFT PATHS
    log_message "INFO" "Analyzing credential theft paths"
    # DCSync attack path
    grep -i "domain.*admin\|enterprise.*admin" "$OUTPUT_DIR/group_relationships.csv" 2>/dev/null | while IFS=',' read -r user group rest; do
        echo "CREDTHEFT_001,$user,DOMAIN_CONTROLLER,DCSYNC,DOMAIN_ADMIN,CRITICAL,Use DCSync to dump all domain credentials,Monitor for unusual replication requests" >> "$output_file"
    done
    
    # NTDS.DIT access path
    grep -i "backup.*operator" "$OUTPUT_DIR/group_relationships.csv" 2>/dev/null | while IFS=',' read -r user group rest; do
        echo "CREDTHEFT_002,$user,NTDS.DIT,BACKUP_ABUSE,BACKUP_OPERATORS,CRITICAL,Access NTDS.DIT file to extract credentials,Monitor file access to NTDS.DIT" >> "$output_file"
    done
    
    # 6. GPO ABUSE PATHS
    log_message "INFO" "Analyzing GPO abuse paths"
    grep -i "group.*policy.*creator" "$OUTPUT_DIR/group_relationships.csv" 2>/dev/null | while IFS=',' read -r user group rest; do
        echo "GPO_001,$user,ALL_COMPUTERS,GPO_ABUSE,GROUP_POLICY_CREATOR,HIGH,Create malicious GPOs to compromise all computers,Monitor GPO modifications" >> "$output_file"
        echo "GPO_002,$user,ALL_USERS,GPO_ABUSE,GROUP_POLICY_CREATOR,HIGH,Create malicious GPOs to compromise all users,Monitor GPO modifications" >> "$output_file"
    done
    
    local path_count=$(wc -l < "$output_file")
    log_message "INFO" "Found $((path_count - 1)) attack paths, saved to $output_file"
}

# Function to create BloodHound-style relationship analysis
create_bloodhound_analysis() {
    log_message "INFO" "Creating BloodHound-style relationship analysis"
    local output_file="$OUTPUT_DIR/bloodhound_analysis.json"
    
    cat > "$output_file" << EOF
{
  "meta": {
    "type": "bloodhound_analysis",
    "version": "1.0",
    "domain": "$DOMAIN",
    "domain_controller": "$DOMAIN_CONTROLLER",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "nodes": {
    "users": [
EOF

    # Add users with their properties
    if [[ -f "$OUTPUT_DIR/users.csv" ]]; then
        while IFS=',' read -r name sam_account desc rest; do
            if [[ "$sam_account" != "SamAccountName" ]]; then
                user_rid=$(echo "$rest" | rev | cut -d',' -f1 | rev)
                cat >> "$output_file" << EOF
      {
        "name": "$sam_account",
        "display_name": "$name",
        "description": "$desc",
        "rid": "$user_rid",
        "enabled": true,
        "properties": {
          "is_service_account": $(if [[ "$sam_account" =~ svc|service ]]; then echo "true"; else echo "false"; fi),
          "is_admin": $(if grep -q "$sam_account.*Domain Admins" "$OUTPUT_DIR/group_relationships.csv" 2>/dev/null; then echo "true"; else echo "false"; fi),
          "password_never_expires": false,
          "kerberoastable": $(if [[ "$sam_account" =~ svc|service ]]; then echo "true"; else echo "false"; fi)
        }
      },
EOF
            fi
        done < "$OUTPUT_DIR/users.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
    ],
    "groups": [
EOF

    # Add groups with their properties
    if [[ -f "$OUTPUT_DIR/groups.csv" ]]; then
        while IFS=',' read -r name sam_account desc type count members rid; do
            if [[ "$sam_account" != "SamAccountName" ]]; then
                cat >> "$output_file" << EOF
      {
        "name": "$name",
        "description": "$desc",
        "rid": "$rid",
        "properties": {
          "is_privileged": $(if [[ "$name" =~ Admin|Enterprise|Schema|Backup|Account.*Operator ]]; then echo "true"; else echo "false"; fi),
          "member_count": "$count"
        }
      },
EOF
            fi
        done < "$OUTPUT_DIR/groups.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
    ],
    "computers": [
EOF

    # Add computers if available
    if [[ -f "$OUTPUT_DIR/computers.csv" ]]; then
        while IFS=',' read -r name sam_account os version rest; do
            if [[ "$name" != "Name" && -n "$name" ]]; then
                cat >> "$output_file" << EOF
      {
        "name": "$name",
        "operating_system": "$os",
        "os_version": "$version",
        "properties": {
          "is_domain_controller": $(if [[ "$name" =~ DC|domain.*controller ]]; then echo "true"; else echo "false"; fi),
          "unconstrained_delegation": false,
          "allows_delegation": false
        }
      },
EOF
            fi
        done < "$OUTPUT_DIR/computers.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
    ]
  },
  "edges": [
EOF

    # Add relationships (edges)
    if [[ -f "$OUTPUT_DIR/group_relationships.csv" ]]; then
        while IFS=',' read -r username group_name group_rid relationship; do
            if [[ "$username" != "Username" && -n "$username" ]]; then
                cat >> "$output_file" << EOF
    {
      "source": "$username",
      "target": "$group_name",
      "relationship": "MemberOf",
      "properties": {
        "is_primary": false,
        "is_inherited": false
      }
    },
EOF
            fi
        done < "$OUTPUT_DIR/group_relationships.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
  ],
  "attack_paths": [
EOF

    # Add attack paths from analysis
    if [[ -f "$OUTPUT_DIR/attack_paths.csv" ]]; then
        while IFS=',' read -r path_id source target method privs risk desc mitigation; do
            if [[ "$path_id" != "Attack_Path_ID" ]]; then
                cat >> "$output_file" << EOF
    {
      "id": "$path_id",
      "source": "$source",
      "target": "$target",
      "method": "$method",
      "required_privileges": "$privs",
      "risk_level": "$risk",
      "description": "$desc",
      "mitigation": "$mitigation"
    },
EOF
            fi
        done < "$OUTPUT_DIR/attack_paths.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
  ]
}
EOF

    log_message "INFO" "BloodHound-style analysis saved to $output_file"
}

# Function to create LLM-optimized JSON output
create_llm_output() {
    log_message "INFO" "Creating LLM-optimized JSON analysis"
    local output_file="$OUTPUT_DIR/llm_analysis.json"
    
    # Get dynamic domain info from our CSV files
    local domain_name="$DOMAIN"
    local domain_controller="$DOMAIN_CONTROLLER"
    local domain_sid=$(grep "Domain SID" "$OUTPUT_DIR/rpc_info.csv" 2>/dev/null | cut -d',' -f4 | head -1 || echo "Unknown")
    
    cat > "$output_file" << EOF
{
  "domain_intelligence": {
    "domain_name": "$domain_name",
    "domain_controller": "$domain_controller", 
    "domain_sid": "$domain_sid",
    "analysis_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "users": [
EOF

    # Add users with factual information only
    while IFS=',' read -r name sam_account desc rest; do
        if [[ "$sam_account" != "SamAccountName" ]]; then
            # Extract RID from rest of the line
            user_rid=$(echo "$rest" | rev | cut -d',' -f1 | rev)
            cat >> "$output_file" << EOF
    {
      "username": "$sam_account",
      "full_name": "$name",
      "description": "$desc",
      "rid": "$user_rid"
    },
EOF
        fi
    done < "$OUTPUT_DIR/users.csv"
    
    # Remove last comma and close array
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
  ],
  "groups": [
EOF

    # Add groups with factual information only
    while IFS=',' read -r name sam_account desc type count members rid; do
        if [[ "$sam_account" != "SamAccountName" ]]; then
            cat >> "$output_file" << EOF
    {
      "group_name": "$name",
      "rid": "$rid",
      "description": "$desc",
      "member_count": "$count"
    },
EOF
        fi
    done < "$OUTPUT_DIR/groups.csv"
    
    # Remove last comma and close array
    sed -i '$ s/,$//' "$output_file"
    
    cat >> "$output_file" << 'EOF'
  ],
  "shares": [
EOF

    # Add shares with factual information only
    while IFS=',' read -r share_name type comment; do
        if [[ "$share_name" != "ShareName" && "$share_name" != "Sharename" ]]; then
            cat >> "$output_file" << EOF
    {
      "share_name": "$share_name",
      "type": "$type",
      "comment": "$comment"
    },
EOF
        fi
    done < "$OUTPUT_DIR/shares.csv"
    
    # Remove last comma and close array
    sed -i '$ s/,$//' "$output_file"
    
    # Add group relationships for context
    cat >> "$output_file" << 'EOF'
  ],
  "group_relationships": [
EOF

    # Add group relationships factually
    if [[ -f "$OUTPUT_DIR/group_relationships.csv" ]]; then
        while IFS=',' read -r username group_name group_rid relationship; do
            if [[ "$username" != "User" && -n "$username" ]]; then
                cat >> "$output_file" << EOF
    {
      "username": "$username",
      "group_name": "$group_name",
      "group_rid": "$group_rid",
      "relationship": "$relationship"
    },
EOF
            fi
        done < "$OUTPUT_DIR/group_relationships.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file" 2>/dev/null || true
    
    # Add permissions data
    cat >> "$output_file" << 'EOF'
  ],
  "permissions": [
EOF

    # Add permissions factually
    if [[ -f "$OUTPUT_DIR/permissions.csv" ]]; then
        while IFS=',' read -r principal target_object permission_type access_rights inherited description; do
            if [[ "$principal" != "Principal" && -n "$principal" ]]; then
                cat >> "$output_file" << EOF
    {
      "principal": "$principal",
      "target_object": "$target_object",
      "permission_type": "$permission_type",
      "access_rights": "$access_rights",
      "inherited": "$inherited",
      "description": "$description"
    },
EOF
            fi
        done < "$OUTPUT_DIR/permissions.csv"
    fi
    
    # Remove trailing comma
    sed -i '$ s/,$//' "$output_file" 2>/dev/null || true
    
    cat >> "$output_file" << 'EOF'
  ]
}
EOF

    log_message "INFO" "LLM-optimized analysis saved to $output_file"
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
        
        # Count results from each output file
        for file in "$OUTPUT_DIR"/*.csv; do
            if [[ -f "$file" ]]; then
                local count=$(($(wc -l < "$file") - 1))
                echo "$(basename "$file" .csv): $count entries"
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
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                echo ""
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
    
    # Execute enabled modules - IMPORTANT ONES FIRST
    get_domain_info
    get_users
    get_groups
    get_shares
    get_rpc_info
    get_group_relationships
    create_llm_output
    
    # Secondary modules (can hang, but won't block important analysis)
    get_permissions
    analyze_attack_paths
    create_bloodhound_analysis
    get_forest_info
    get_computers
    get_trusts
    get_spns
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