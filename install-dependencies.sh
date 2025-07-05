#!/bin/bash

# Dependency Installation Script for Bash-ADRecon
# Automatically installs required tools on different Linux distributions

set -euo pipefail

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo $ID
    elif type lsb_release >/dev/null 2>&1; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        echo $DISTRIB_ID | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    local distro=$(detect_distro)
    
    echo -e "${BLUE}Detected Linux distribution: $distro${NC}"
    
    case $distro in
        ubuntu|debian|kali|parrot)
            echo -e "${GREEN}Installing dependencies for Debian/Ubuntu-based systems...${NC}"
            sudo apt-get update
            sudo apt-get install -y ldap-utils smbclient dnsutils netcat-traditional curl wget
            ;;
        centos|rhel|fedora)
            echo -e "${GREEN}Installing dependencies for RedHat-based systems...${NC}"
            if command -v dnf &> /dev/null; then
                sudo dnf install -y openldap-clients samba-client bind-utils nc curl wget
            else
                sudo yum install -y openldap-clients samba-client bind-utils nc curl wget
            fi
            ;;
        arch|manjaro)
            echo -e "${GREEN}Installing dependencies for Arch-based systems...${NC}"
            sudo pacman -Sy --needed openldap smbclient dnsutils gnu-netcat curl wget
            ;;
        opensuse|sles)
            echo -e "${GREEN}Installing dependencies for openSUSE/SLES systems...${NC}"
            sudo zypper install -y openldap2-client samba-client bind-utils netcat-openbsd curl wget
            ;;
        alpine)
            echo -e "${GREEN}Installing dependencies for Alpine Linux...${NC}"
            sudo apk add --no-cache openldap-clients samba-client bind-tools netcat-openbsd curl wget
            ;;
        *)
            echo -e "${YELLOW}Unknown distribution: $distro${NC}"
            echo -e "${YELLOW}Please install the following packages manually:${NC}"
            echo "- ldap-utils or openldap-clients"
            echo "- smbclient"
            echo "- dnsutils or bind-utils"
            echo "- netcat"
            echo "- curl and wget"
            exit 1
            ;;
    esac
}

# Function to verify installation
verify_installation() {
    local required_tools=("ldapsearch" "smbclient" "dig" "nc" "curl" "wget")
    local missing_tools=()
    
    echo -e "${BLUE}Verifying installation...${NC}"
    
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}✓${NC} $tool is installed"
        else
            echo -e "${RED}✗${NC} $tool is missing"
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        echo -e "${GREEN}All dependencies are installed successfully!${NC}"
        return 0
    else
        echo -e "${RED}Missing tools: ${missing_tools[*]}${NC}"
        return 1
    fi
}

# Function to show help
show_help() {
    echo -e "${BLUE}Bash-ADRecon Dependency Installer${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --verify   Only verify if dependencies are installed"
    echo "  -f, --force    Force installation even if tools are present"
    echo ""
    echo "This script will automatically detect your Linux distribution"
    echo "and install the required tools for bash-adrecon.sh"
}

# Main function
main() {
    local verify_only=false
    local force_install=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verify)
                verify_only=true
                shift
                ;;
            -f|--force)
                force_install=true
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
    
    echo -e "${BLUE}
    ╔══════════════════════════════════════════════════════════════╗
    ║              Bash-ADRecon Dependency Installer              ║
    ╚══════════════════════════════════════════════════════════════╝
    ${NC}"
    
    # Check if we're running as root for package installation
    if [[ $EUID -eq 0 ]] && [[ $verify_only != true ]]; then
        echo -e "${YELLOW}Warning: Running as root. This is not recommended.${NC}"
        echo -e "${YELLOW}Please run as a regular user with sudo privileges.${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Verify current installation
    if verify_installation; then
        if [[ $verify_only == true ]]; then
            echo -e "${GREEN}Verification complete. All tools are available.${NC}"
            exit 0
        elif [[ $force_install != true ]]; then
            echo -e "${GREEN}All dependencies are already installed.${NC}"
            echo -e "${YELLOW}Use --force to reinstall anyway.${NC}"
            exit 0
        fi
    fi
    
    if [[ $verify_only != true ]]; then
        echo -e "${YELLOW}Installing missing dependencies...${NC}"
        install_dependencies
        
        echo -e "${BLUE}Installation complete. Verifying...${NC}"
        if verify_installation; then
            echo -e "${GREEN}✓ All dependencies installed successfully!${NC}"
            echo -e "${GREEN}You can now run bash-adrecon.sh${NC}"
        else
            echo -e "${RED}✗ Some dependencies failed to install${NC}"
            exit 1
        fi
    fi
}

# Run main function
main "$@" 