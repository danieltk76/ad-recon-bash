#!/bin/bash

# ========================================================================
# Bash-ADRecon JSON: JSON Output Version for AI Agents
# Author: AI Assistant
# Description: JSON-optimized version of bash-adrecon for PTJunior AI
# ========================================================================

set -euo pipefail

# Global variables
DOMAIN_CONTROLLER=""
DOMAIN=""
USERNAME=""
PASSWORD=""
OUTPUT_FILE=""
COLLECT_ALL=true
VERBOSE=false

# Available modules
declare -A MODULES=(
    ["domain"]=true
    ["users"]=true
    ["groups"]=true
    ["computers"]=true
    ["spns"]=true
    ["trusts"]=true
    ["shares"]=true
    ["dns"]=true
)

# Function to log messages (only if verbose)
log_message() {
    local level=$1
    local message=$2
    
    if [[ "$VERBOSE" == true ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $level: $message" >&2
    fi
}

# Function to escape JSON strings
escape_json() {
    local string="$1"
    # Escape backslashes, quotes, and control characters
    echo "$string" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed 's/\t/\\t/g' | sed 's/\n/\\n/g' | sed 's/\r/\\r/g'
}

# Function to create JSON array from CSV-like data
create_json_array() {
    local header_line="$1"
    local data_lines="$2"
    
    # Parse header
    IFS=',' read -ra headers <<< "$header_line"
    
    echo "["
    local first=true
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            if [[ "$first" != true ]]; then
                echo ","
            fi
            first=false
            
            echo -n "{"
            IFS=',' read -ra values <<< "$line"
            
            local first_field=true
            for i in "${!headers[@]}"; do
                if [[ "$first_field" != true ]]; then
                    echo -n ","
                fi
                first_field=false
                
                local header=$(escape_json "${headers[$i]}")
                local value=$(escape_json "${values[$i]:-}")
                echo -n "\"$header\":\"$value\""
            done
            echo -n "}"
        fi
    done <<< "$data_lines"
    echo -e "\n]"
}

# Function to get domain information
get_domain_info() {
    if [[ "${MODULES[domain]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting domain information"
    
    local ldap_result=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s base "(objectClass=*)" \
        dn distinguishedName whenCreated whenChanged \
        2>/dev/null | grep -E "^(dn|distinguishedName|whenCreated|whenChanged):" || true)
    
    local domain_controller=$(escape_json "$DOMAIN_CONTROLLER")
    local domain_name=$(escape_json "$DOMAIN")
    local domain_dn=$(escape_json "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')")
    
    local creation_time=$(echo "$ldap_result" | grep "whenCreated:" | cut -d' ' -f2- | head -1)
    local modified_time=$(echo "$ldap_result" | grep "whenChanged:" | cut -d' ' -f2- | head -1)
    
    creation_time=$(escape_json "$creation_time")
    modified_time=$(escape_json "$modified_time")
    
    cat << EOF
"domain": {
    "controller": "$domain_controller",
    "name": "$domain_name",
    "distinguished_name": "$domain_dn",
    "created": "$creation_time",
    "modified": "$modified_time"
}
EOF
}

# Function to get users
get_users() {
    if [[ "${MODULES[users]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting users"
    
    local users_data=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=user)" \
        cn sAMAccountName description userAccountControl memberOf \
        2>/dev/null | \
    awk '
    BEGIN { users=""; count=0 }
    /^dn:/ { 
        if (samname != "") {
            if (count > 0) users = users ","
            users = users sprintf("{\"name\":\"%s\",\"samaccountname\":\"%s\",\"description\":\"%s\",\"useraccountcontrol\":\"%s\",\"memberof\":\"%s\"}", 
                                 gensub(/["\\]/, "\\\\&", "g", name), 
                                 gensub(/["\\]/, "\\\\&", "g", samname), 
                                 gensub(/["\\]/, "\\\\&", "g", desc), 
                                 gensub(/["\\]/, "\\\\&", "g", uac), 
                                 gensub(/["\\]/, "\\\\&", "g", memberof))
            count++
        }
        name=""; samname=""; desc=""; uac=""; memberof=""
    }
    /^cn:/ { name = substr($0, 5) }
    /^sAMAccountName:/ { samname = substr($0, 17) }
    /^description:/ { desc = substr($0, 13) }
    /^userAccountControl:/ { uac = substr($0, 20) }
    /^memberOf:/ { memberof = memberof substr($0, 10) ";" }
    END { 
        if (samname != "") {
            if (count > 0) users = users ","
            users = users sprintf("{\"name\":\"%s\",\"samaccountname\":\"%s\",\"description\":\"%s\",\"useraccountcontrol\":\"%s\",\"memberof\":\"%s\"}", 
                                 gensub(/["\\]/, "\\\\&", "g", name), 
                                 gensub(/["\\]/, "\\\\&", "g", samname), 
                                 gensub(/["\\]/, "\\\\&", "g", desc), 
                                 gensub(/["\\]/, "\\\\&", "g", uac), 
                                 gensub(/["\\]/, "\\\\&", "g", memberof))
        }
        print "[" users "]"
    }
    ')
    
    echo "\"users\": $users_data"
}

# Function to get groups
get_groups() {
    if [[ "${MODULES[groups]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting groups"
    
    local groups_data=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=group)" \
        cn sAMAccountName description groupType member \
        2>/dev/null | \
    awk '
    BEGIN { groups=""; count=0 }
    /^dn:/ { 
        if (samname != "") {
            if (count > 0) groups = groups ","
            membercount = gsub(/;/, ";", members)
            groups = groups sprintf("{\"name\":\"%s\",\"samaccountname\":\"%s\",\"description\":\"%s\",\"grouptype\":\"%s\",\"membercount\":%d,\"members\":\"%s\"}", 
                                   gensub(/["\\]/, "\\\\&", "g", name), 
                                   gensub(/["\\]/, "\\\\&", "g", samname), 
                                   gensub(/["\\]/, "\\\\&", "g", desc), 
                                   gensub(/["\\]/, "\\\\&", "g", grouptype), 
                                   membercount, 
                                   gensub(/["\\]/, "\\\\&", "g", members))
            count++
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
            if (count > 0) groups = groups ","
            membercount = gsub(/;/, ";", members)
            groups = groups sprintf("{\"name\":\"%s\",\"samaccountname\":\"%s\",\"description\":\"%s\",\"grouptype\":\"%s\",\"membercount\":%d,\"members\":\"%s\"}", 
                                   gensub(/["\\]/, "\\\\&", "g", name), 
                                   gensub(/["\\]/, "\\\\&", "g", samname), 
                                   gensub(/["\\]/, "\\\\&", "g", desc), 
                                   gensub(/["\\]/, "\\\\&", "g", grouptype), 
                                   membercount, 
                                   gensub(/["\\]/, "\\\\&", "g", members))
        }
        print "[" groups "]"
    }
    ')
    
    echo "\"groups\": $groups_data"
}

# Function to get computers
get_computers() {
    if [[ "${MODULES[computers]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting computers"
    
    local computers_data=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(objectClass=computer)" \
        cn sAMAccountName operatingSystem operatingSystemVersion lastLogon \
        2>/dev/null | \
    awk '
    BEGIN { computers=""; count=0 }
    /^dn:/ { 
        if (samname != "") {
            if (count > 0) computers = computers ","
            computers = computers sprintf("{\"name\":\"%s\",\"samaccountname\":\"%s\",\"os\":\"%s\",\"osversion\":\"%s\",\"lastlogon\":\"%s\"}", 
                                         gensub(/["\\]/, "\\\\&", "g", name), 
                                         gensub(/["\\]/, "\\\\&", "g", samname), 
                                         gensub(/["\\]/, "\\\\&", "g", os), 
                                         gensub(/["\\]/, "\\\\&", "g", osver), 
                                         gensub(/["\\]/, "\\\\&", "g", lastlogon))
            count++
        }
        name=""; samname=""; os=""; osver=""; lastlogon=""
    }
    /^cn:/ { name = substr($0, 5) }
    /^sAMAccountName:/ { samname = substr($0, 17) }
    /^operatingSystem:/ { os = substr($0, 17) }
    /^operatingSystemVersion:/ { osver = substr($0, 25) }
    /^lastLogon:/ { lastlogon = substr($0, 11) }
    END { 
        if (samname != "") {
            if (count > 0) computers = computers ","
            computers = computers sprintf("{\"name\":\"%s\",\"samaccountname\":\"%s\",\"os\":\"%s\",\"osversion\":\"%s\",\"lastlogon\":\"%s\"}", 
                                         gensub(/["\\]/, "\\\\&", "g", name), 
                                         gensub(/["\\]/, "\\\\&", "g", samname), 
                                         gensub(/["\\]/, "\\\\&", "g", os), 
                                         gensub(/["\\]/, "\\\\&", "g", osver), 
                                         gensub(/["\\]/, "\\\\&", "g", lastlogon))
        }
        print "[" computers "]"
    }
    ')
    
    echo "\"computers\": $computers_data"
}

# Function to get SPNs
get_spns() {
    if [[ "${MODULES[spns]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting SPNs"
    
    local spns_data=$(ldapsearch -x -H "ldap://$DOMAIN_CONTROLLER" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
        -b "DC=$(echo $DOMAIN | sed 's/\./,DC=/g')" \
        -s sub "(servicePrincipalName=*)" \
        sAMAccountName servicePrincipalName \
        2>/dev/null | \
    awk '
    BEGIN { spns=""; count=0 }
    /^dn:/ { account="" }
    /^sAMAccountName:/ { account = substr($0, 17) }
    /^servicePrincipalName:/ { 
        spn = substr($0, 22)
        split(spn, parts, "/")
        service = parts[1]
        host = parts[2]
        if (account != "") {
            if (count > 0) spns = spns ","
            spns = spns sprintf("{\"account\":\"%s\",\"spn\":\"%s\",\"service\":\"%s\",\"host\":\"%s\"}", 
                               gensub(/["\\]/, "\\\\&", "g", account), 
                               gensub(/["\\]/, "\\\\&", "g", spn), 
                               gensub(/["\\]/, "\\\\&", "g", service), 
                               gensub(/["\\]/, "\\\\&", "g", host))
            count++
        }
    }
    END { print "[" spns "]" }
    ')
    
    echo "\"spns\": $spns_data"
}

# Function to get SMB shares
get_shares() {
    if [[ "${MODULES[shares]}" != true ]]; then return; fi
    
    log_message "INFO" "Collecting SMB shares"
    
    local shares_data=$(smbclient -L "//$DOMAIN_CONTROLLER" -U "$USERNAME%$PASSWORD" 2>/dev/null | \
    grep -E "^\s+[A-Za-z]" | \
    awk '
    BEGIN { shares=""; count=0 }
    {
        sharename = $1
        type = $2
        comment = ""
        for (i = 3; i <= NF; i++) {
            comment = comment $i " "
        }
        gsub(/^[ \t]+|[ \t]+$/, "", comment)
        gsub(/["\\]/, "\\\\&", sharename)
        gsub(/["\\]/, "\\\\&", type)
        gsub(/["\\]/, "\\\\&", comment)
        
        if (count > 0) shares = shares ","
        shares = shares sprintf("{\"name\":\"%s\",\"type\":\"%s\",\"comment\":\"%s\"}", sharename, type, comment)
        count++
    }
    END { print "[" shares "]" }
    ')
    
    echo "\"shares\": $shares_data"
}

# Function to create final JSON output
create_json_output() {
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local target=$(escape_json "$DOMAIN_CONTROLLER")
    local domain=$(escape_json "$DOMAIN")
    
    echo "{"
    echo "  \"metadata\": {"
    echo "    \"tool\": \"bash-adrecon-json\","
    echo "    \"version\": \"1.0\","
    echo "    \"timestamp\": \"$timestamp\","
    echo "    \"target\": \"$target\","
    echo "    \"domain\": \"$domain\""
    echo "  },"
    
    # Collect all enabled module outputs
    local outputs=()
    
    if [[ "${MODULES[domain]}" == true ]]; then
        outputs+=($(get_domain_info))
    fi
    
    if [[ "${MODULES[users]}" == true ]]; then
        outputs+=($(get_users))
    fi
    
    if [[ "${MODULES[groups]}" == true ]]; then
        outputs+=($(get_groups))
    fi
    
    if [[ "${MODULES[computers]}" == true ]]; then
        outputs+=($(get_computers))
    fi
    
    if [[ "${MODULES[spns]}" == true ]]; then
        outputs+=($(get_spns))
    fi
    
    if [[ "${MODULES[shares]}" == true ]]; then
        outputs+=($(get_shares))
    fi
    
    # Join outputs with commas
    local first=true
    for output in "${outputs[@]}"; do
        if [[ "$first" != true ]]; then
            echo ","
        fi
        first=false
        echo "  $output"
    done
    
    echo "}"
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
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -c|--collect)
                COLLECT_ALL=false
                for module in "${!MODULES[@]}"; do
                    MODULES[$module]=false
                done
                IFS=',' read -ra ADDR <<< "$2"
                for module in "${ADDR[@]}"; do
                    if [[ -n "${MODULES[$module]}" ]]; then
                        MODULES[$module]=true
                    fi
                done
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 -d <dc> -D <domain> -u <user> -p <pass> [options]"
                echo "Options:"
                echo "  -o, --output     Output file (default: stdout)"
                echo "  -c, --collect    Modules to collect (comma-separated)"
                echo "  -v, --verbose    Enable verbose logging"
                echo "Available modules: domain,users,groups,computers,spns,shares"
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    parse_args "$@"
    
    # Validate required parameters
    if [[ -z "$DOMAIN_CONTROLLER" || -z "$DOMAIN" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
        echo "Error: Required parameters missing" >&2
        echo "Usage: $0 -d <dc> -D <domain> -u <user> -p <pass>" >&2
        exit 1
    fi
    
    # Generate JSON output
    if [[ -n "$OUTPUT_FILE" ]]; then
        create_json_output > "$OUTPUT_FILE"
        if [[ "$VERBOSE" == true ]]; then
            echo "JSON output saved to: $OUTPUT_FILE" >&2
        fi
    else
        create_json_output
    fi
}

# Run main function
main "$@" 