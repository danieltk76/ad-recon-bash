#!/bin/bash

# Quick ADRecon Wrapper Script
# Makes it easier to run bash-adrecon.sh with minimal arguments

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to display usage
show_usage() {
    echo -e "${GREEN}Quick ADRecon Wrapper${NC}"
    echo "Usage: $0 <domain_controller> <domain> <username> <password> [modules]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.10 example.com administrator password"
    echo "  $0 dc01.example.com example.com admin P@ssw0rd users,groups"
    echo ""
    echo "Available modules: domain,forest,users,groups,computers,trusts,gpos,dns,shares,sessions,spns,schema,sites,subnets,policies"
    echo "If no modules specified, all modules will be executed."
}

# Check if bash-adrecon.sh exists
if [[ ! -f "./bash-adrecon.sh" ]]; then
    echo -e "${RED}Error: bash-adrecon.sh not found in current directory${NC}"
    exit 1
fi

# Check arguments
if [[ $# -lt 4 ]]; then
    show_usage
    exit 1
fi

# Parse arguments
DOMAIN_CONTROLLER="$1"
DOMAIN="$2"
USERNAME="$3"
PASSWORD="$4"
MODULES="${5:-}"

# Build command
CMD="./bash-adrecon.sh -d \"$DOMAIN_CONTROLLER\" -D \"$DOMAIN\" -u \"$USERNAME\" -p \"$PASSWORD\" -v"

# Add modules if specified
if [[ -n "$MODULES" ]]; then
    CMD="$CMD -c \"$MODULES\""
fi

# Display what we're about to run
echo -e "${YELLOW}Running ADRecon with:${NC}"
echo "  Domain Controller: $DOMAIN_CONTROLLER"
echo "  Domain: $DOMAIN"
echo "  Username: $USERNAME"
echo "  Password: [HIDDEN]"
if [[ -n "$MODULES" ]]; then
    echo "  Modules: $MODULES"
else
    echo "  Modules: ALL"
fi
echo ""

# Make sure bash-adrecon.sh is executable
chmod +x ./bash-adrecon.sh

# Execute the command
echo -e "${GREEN}Starting enumeration...${NC}"
eval "$CMD" 