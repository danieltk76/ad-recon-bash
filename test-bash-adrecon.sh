#!/bin/bash

# Test script for bash-adrecon tools
# This script helps verify that all components work correctly

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test parameters (change these for your environment)
TEST_DC="${TEST_DC:-}"
TEST_DOMAIN="${TEST_DOMAIN:-}"
TEST_USERNAME="${TEST_USERNAME:-}"
TEST_PASSWORD="${TEST_PASSWORD:-}"

# Function to print test results
print_test_result() {
    local test_name="$1"
    local result="$2"
    local details="${3:-}"
    
    if [[ "$result" == "PASS" ]]; then
        echo -e "${GREEN}✅ $test_name: PASS${NC}"
    elif [[ "$result" == "FAIL" ]]; then
        echo -e "${RED}❌ $test_name: FAIL${NC}"
        if [[ -n "$details" ]]; then
            echo -e "${RED}   Details: $details${NC}"
        fi
    elif [[ "$result" == "SKIP" ]]; then
        echo -e "${YELLOW}⚠️  $test_name: SKIP${NC}"
        if [[ -n "$details" ]]; then
            echo -e "${YELLOW}   Details: $details${NC}"
        fi
    fi
}

# Function to test script existence
test_script_exists() {
    local script_name="$1"
    
    if [[ -f "$script_name" ]]; then
        if [[ -x "$script_name" ]]; then
            print_test_result "Script exists and is executable: $script_name" "PASS"
            return 0
        else
            print_test_result "Script exists but not executable: $script_name" "FAIL" "Run chmod +x $script_name"
            return 1
        fi
    else
        print_test_result "Script exists: $script_name" "FAIL" "File not found"
        return 1
    fi
}

# Function to test dependencies
test_dependencies() {
    local required_tools=("ldapsearch" "smbclient" "dig" "awk" "sed" "grep")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_test_result "Dependency: $tool" "PASS"
        else
            print_test_result "Dependency: $tool" "FAIL" "Tool not found in PATH"
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        return 0
    else
        echo -e "${RED}Missing dependencies: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}Install with: sudo apt-get install ldap-utils smbclient dnsutils${NC}"
        return 1
    fi
}

# Function to test script syntax
test_script_syntax() {
    local script_name="$1"
    
    if bash -n "$script_name" 2>/dev/null; then
        print_test_result "Script syntax: $script_name" "PASS"
        return 0
    else
        print_test_result "Script syntax: $script_name" "FAIL" "Syntax error detected"
        return 1
    fi
}

# Function to test help functionality
test_help_functionality() {
    local script_name="$1"
    
    if ./"$script_name" --help &>/dev/null; then
        print_test_result "Help functionality: $script_name" "PASS"
        return 0
    else
        print_test_result "Help functionality: $script_name" "FAIL" "Help option not working"
        return 1
    fi
}

# Function to test with live AD (if credentials provided)
test_live_ad() {
    if [[ -z "$TEST_DC" || -z "$TEST_DOMAIN" || -z "$TEST_USERNAME" || -z "$TEST_PASSWORD" ]]; then
        print_test_result "Live AD test" "SKIP" "No test credentials provided"
        return 0
    fi
    
    echo -e "${BLUE}Testing with live AD environment...${NC}"
    
    # Test basic connectivity
    if timeout 5 bash -c "</dev/tcp/$TEST_DC/389" 2>/dev/null; then
        print_test_result "AD connectivity (LDAP port 389)" "PASS"
    else
        print_test_result "AD connectivity (LDAP port 389)" "FAIL" "Cannot connect to $TEST_DC:389"
        return 1
    fi
    
    # Test basic LDAP authentication
    if ldapsearch -x -h "$TEST_DC" -D "$TEST_USERNAME@$TEST_DOMAIN" -w "$TEST_PASSWORD" -b "DC=$(echo $TEST_DOMAIN | sed 's/\./,DC=/g')" -s base "(objectClass=*)" dn &>/dev/null; then
        print_test_result "AD authentication" "PASS"
    else
        print_test_result "AD authentication" "FAIL" "Cannot authenticate with provided credentials"
        return 1
    fi
    
    # Test JSON script with minimal modules
    echo -e "${BLUE}Testing JSON enumeration...${NC}"
    if timeout 60 ./bash-adrecon-json.sh -d "$TEST_DC" -D "$TEST_DOMAIN" -u "$TEST_USERNAME" -p "$TEST_PASSWORD" -c domain &>/dev/null; then
        print_test_result "JSON enumeration test" "PASS"
    else
        print_test_result "JSON enumeration test" "FAIL" "JSON enumeration failed"
        return 1
    fi
    
    return 0
}

# Function to show usage
show_usage() {
    echo -e "${BLUE}Bash-ADRecon Test Script${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help"
    echo "  --live-test             Run live AD tests (requires environment variables)"
    echo "  --install-deps          Install missing dependencies"
    echo ""
    echo "Environment Variables for Live Testing:"
    echo "  TEST_DC                 Domain Controller IP/FQDN"
    echo "  TEST_DOMAIN             Domain name"
    echo "  TEST_USERNAME           Username for authentication"
    echo "  TEST_PASSWORD           Password for authentication"
    echo ""
    echo "Examples:"
    echo "  $0                      # Run basic tests"
    echo "  $0 --live-test          # Run tests including live AD"
    echo "  $0 --install-deps       # Install missing dependencies"
    echo ""
    echo "  # Live test with environment variables:"
    echo "  TEST_DC=192.168.1.10 TEST_DOMAIN=example.com TEST_USERNAME=admin TEST_PASSWORD=password $0 --live-test"
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    
    if [[ -f "./install-dependencies.sh" ]]; then
        ./install-dependencies.sh
    else
        echo -e "${YELLOW}install-dependencies.sh not found, trying manual install...${NC}"
        
        # Detect OS and install
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y ldap-utils smbclient dnsutils
        elif command -v yum &> /dev/null; then
            sudo yum install -y openldap-clients samba-client bind-utils
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y openldap-clients samba-client bind-utils
        else
            echo -e "${RED}Cannot determine package manager. Please install manually.${NC}"
            return 1
        fi
    fi
}

# Main function
main() {
    local run_live_test=false
    local install_deps=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            --live-test)
                run_live_test=true
                shift
                ;;
            --install-deps)
                install_deps=true
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    echo -e "${BLUE}
    ╔══════════════════════════════════════════════════════════════╗
    ║                  Bash-ADRecon Test Suite                    ║
    ╚══════════════════════════════════════════════════════════════╝
    ${NC}"
    
    # Install dependencies if requested
    if [[ "$install_deps" == true ]]; then
        install_dependencies
        echo ""
    fi
    
    # Test 1: Check if scripts exist
    echo -e "${BLUE}Testing script files...${NC}"
    test_script_exists "bash-adrecon.sh"
    test_script_exists "bash-adrecon-json.sh"
    test_script_exists "quick-adrecon.sh"
    test_script_exists "install-dependencies.sh"
    echo ""
    
    # Test 2: Check dependencies
    echo -e "${BLUE}Testing dependencies...${NC}"
    test_dependencies
    echo ""
    
    # Test 3: Check script syntax
    echo -e "${BLUE}Testing script syntax...${NC}"
    test_script_syntax "bash-adrecon.sh"
    test_script_syntax "bash-adrecon-json.sh"
    test_script_syntax "quick-adrecon.sh"
    echo ""
    
    # Test 4: Check help functionality
    echo -e "${BLUE}Testing help functionality...${NC}"
    test_help_functionality "bash-adrecon.sh"
    test_help_functionality "bash-adrecon-json.sh"
    echo ""
    
    # Test 5: Live AD test (if requested and credentials provided)
    if [[ "$run_live_test" == true ]]; then
        echo -e "${BLUE}Testing live AD functionality...${NC}"
        test_live_ad
        echo ""
    fi
    
    # Summary
    echo -e "${GREEN}Test suite completed!${NC}"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "- Basic functionality tests completed"
    echo "- For live AD testing, set environment variables and use --live-test"
    echo "- Check README-bash-adrecon.md for full usage instructions"
}

# Run main function
main "$@" 