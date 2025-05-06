#!/bin/bash

# stall_nosudo_v2.sh: Installs reconnaissance tools locally without sudo.

# --- Configuration ---
USER_HOME=$HOME
TOOLS_DIR="$USER_HOME/tools"
TOOLS_BIN_DIR="$TOOLS_DIR/bin"
TOOLS_SRC_DIR="$TOOLS_DIR/src"
GO_INSTALL_PATH="$TOOLS_DIR/go"
GO_VERSION="1.22.4" # Specify a recent Go version (>=1.22.2 for katana)
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://golang.org/dl/${GO_TAR}"
GO_PATH="$USER_HOME/go_projects" # Separate from Go installation path
GO_BIN_PATH="$GO_PATH/bin"
WORDLIST_PATH="$USER_HOME/wordlists"
SECLISTS_PATH="$WORDLIST_PATH/SecLists"
USER_RC_FILE="$USER_HOME/.bashrc" # Or .zshrc, .profile etc.

# Color definitions
GREEN=\'\033[1;32m\'
RED=\'\033[1;31m\'
YELLOW=\'\033[1;33m\'
NC=\'\033[0m\' # No Color

# Logging functions
log() { echo -e "${GREEN}[*] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] Warning: $1${NC}"; }
error() { echo -e "${RED}[!] Error: $1${NC}" >&2; exit 1; }

# Function to add paths to RC file if not already present
add_to_rc() {
    local line_to_add=$1
    local file=$2
    if ! grep -qF -- "$line_to_add" "$file"; then
        log "Adding to $file: $line_to_add"
        echo "" >> "$file"
        echo "# Added by stall_nosudo_v2.sh" >> "$file"
        echo "$line_to_add" >> "$file"
        export RC_UPDATED=true
    fi
}

# --- Setup Directories and PATH ---
setup_environment() {
    log "Setting up local directories in $TOOLS_DIR..."
    mkdir -p "$TOOLS_BIN_DIR"
    mkdir -p "$TOOLS_SRC_DIR"
    mkdir -p "$GO_PATH"
    mkdir -p "$GO_BIN_PATH"
    mkdir -p "$WORDLIST_PATH"

    log "Ensuring local bin directories are in PATH for this session and future sessions..."
    # Add to current session PATH
    export PATH="$TOOLS_BIN_DIR:$GO_INSTALL_PATH/bin:$GO_BIN_PATH:$PATH"

    # Add to RC file for persistence
    export RC_UPDATED=false
    add_to_rc "export PATH=\"$TOOLS_BIN_DIR:\$PATH\"" "$USER_RC_FILE"
    add_to_rc "export PATH=\"$GO_INSTALL_PATH/bin:\$PATH\"" "$USER_RC_FILE"
    add_to_rc "export GOPATH=\"$GO_PATH\"" "$USER_RC_FILE"
    add_to_rc "export PATH=\"\$PATH:\$GOPATH/bin\"" "$USER_RC_FILE"

    if [ "$RC_UPDATED" = true ]; then
        warn "Your $USER_RC_FILE has been updated. Please run 'source $USER_RC_FILE' or restart your shell after this script finishes."
    fi
}

# --- Install Go Locally ---
install_go() {
    log "Checking for local Go installation..."
    if command -v go &>/dev/null && [[ "$(go version)" == *"$GO_VERSION"* ]]; then
        log "Go version $GO_VERSION already installed."
        return 0
    fi

    if [ -d "$GO_INSTALL_PATH" ]; then
        log "Removing previous local Go installation at $GO_INSTALL_PATH..."
        rm -rf "$GO_INSTALL_PATH"
    fi

    log "Downloading Go $GO_VERSION..."
    curl -L "$GO_URL" -o "/tmp/$GO_TAR"
    if [[ $? -ne 0 ]]; then error "Failed to download Go tarball."; fi

    log "Installing Go to $GO_INSTALL_PATH..."
    tar -C "$TOOLS_DIR" -xzf "/tmp/$GO_TAR"
    if [[ $? -ne 0 ]]; then error "Failed to extract Go tarball."; fi
    rm "/tmp/$GO_TAR"

    # Verify installation
    if ! command -v go &>/dev/null; then
        error "Go installation failed. 'go' command not found in PATH."
    fi
    log "Go $(go version) installed successfully locally."
}

# --- Install Go-based Tools Locally ---
install_go_tool() {
    local tool_name=$1
    local install_cmd=$2
    local check_path="$GO_BIN_PATH/$tool_name"

    log "Checking for Go tool: $tool_name..."
    if ! command -v "$check_path" &>/dev/null; then
        log "Installing $tool_name to $GO_BIN_PATH..."
        eval "$install_cmd"
        if [[ $? -ne 0 ]]; then
            warn "Failed to install $tool_name using: $install_cmd. Trying without -v flag..."
            local cmd_no_v=$(echo "$install_cmd" | sed 's/ -v//')
            eval "$cmd_no_v"
            if [[ $? -ne 0 ]]; then
                 error "Failed to install $tool_name even without -v flag."
            else
                 log "$tool_name installed successfully (without -v)."
            fi
        else
            log "$tool_name installed successfully."
        fi
    else
        log "$tool_name already found at $check_path. Attempting update..."
        # Go install usually handles updates gracefully
        eval "$install_cmd" > /dev/null 2>&1
        log "$tool_name update attempt finished."
    fi
}

install_go_tools() {
    log "Installing Go-based security tools to $GO_BIN_PATH..."
    # Ensure Go env vars are set
    export GOPATH="$GO_PATH"
    export PATH="$PATH:$GO_BIN_PATH"

    declare -A go_tools=(
        ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["assetfinder"]="go install -v github.com/tomnomnom/assetfinder@latest"
        # ["amass"]="go install -v github.com/OWASP/Amass/v4/cmd/amass@latest" # REMOVED (module path conflict)
        ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        # ["katana"]="go install -v github.com/projectdiscovery/katana/cmd/katana@latest" # REMOVED (build issues with tree-sitter)
        ["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
        ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        # ["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" # Nmap alternative - REMOVED (requires libpcap-dev)
        ["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
        ["gobuster"]="go install -v github.com/OJ/gobuster/v3@latest"
    )

    for tool in "${!go_tools[@]}"; do
        install_go_tool "$tool" "${go_tools[$tool]}"
    done

    # Update Nuclei Templates
    log "Updating Nuclei templates (in $HOME/nuclei-templates)..."
    if command -v "$GO_BIN_PATH/nuclei" &>/dev/null; then
       "$GO_BIN_PATH/nuclei" -update-templates || warn "Nuclei template update failed. Check manually."
    else
        warn "Nuclei command not found in $GO_BIN_PATH, cannot update templates."
    fi
}

# --- Install Other Tools Locally ---

# Install jq (binary download)
install_jq() {
    log "Checking for local jq installation..."
    if command -v "$TOOLS_BIN_DIR/jq" &>/dev/null; then
        log "jq already found in $TOOLS_BIN_DIR."
        return 0
    fi
    log "Installing jq locally..."
    curl -L https://github.com/jqlang/jq/releases/latest/download/jq-linux-amd64 -o "$TOOLS_BIN_DIR/jq"
    if [[ $? -ne 0 ]]; then error "Failed to download jq."; fi
    chmod +x "$TOOLS_BIN_DIR/jq"
    log "jq installed successfully to $TOOLS_BIN_DIR."
}

# Install sqlmap (git clone)
install_sqlmap() {
    local sqlmap_dir="$TOOLS_SRC_DIR/sqlmap"
    log "Checking for local sqlmap installation..."
    if [ -f "$sqlmap_dir/sqlmap.py" ]; then
        log "sqlmap found in $sqlmap_dir. Updating..."
        (cd "$sqlmap_dir" && git pull) || warn "Failed to update sqlmap."
        return 0
    fi
    log "Installing sqlmap locally via git clone..."
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$sqlmap_dir"
    if [[ $? -ne 0 ]]; then error "Failed to clone sqlmap."; fi
    # Create a wrapper script in bin
    echo "#!/bin/bash" > "$TOOLS_BIN_DIR/sqlmap"
    echo "python3 $sqlmap_dir/sqlmap.py \"\$@\"" >> "$TOOLS_BIN_DIR/sqlmap"
    chmod +x "$TOOLS_BIN_DIR/sqlmap"
    log "sqlmap installed successfully. Wrapper script created in $TOOLS_BIN_DIR."
    # Note: sqlmap might have Python dependencies. User might need to install them manually if issues arise.
    # Consider adding: pip3 install -r $sqlmap_dir/requirements.txt --user
}

# Install Nikto (git clone)
install_nikto() {
    local nikto_dir="$TOOLS_SRC_DIR/nikto"
    log "Checking for local Nikto installation..."
    if [ -f "$nikto_dir/program/nikto.pl" ]; then
        log "Nikto found in $nikto_dir. Updating..."
        (cd "$nikto_dir" && git pull) || warn "Failed to update Nikto."
        return 0
    fi
    log "Installing Nikto locally via git clone..."
    git clone --depth 1 https://github.com/sullo/nikto.git "$nikto_dir"
    if [[ $? -ne 0 ]]; then error "Failed to clone Nikto."; fi
    # Create a wrapper script in bin
    echo "#!/bin/bash" > "$TOOLS_BIN_DIR/nikto"
    # Need to execute perl script from its directory
    echo "(cd $nikto_dir/program && perl nikto.pl -Version > /dev/null 2>&1 && perl nikto.pl \"\$@\")" >> "$TOOLS_BIN_DIR/nikto"
    chmod +x "$TOOLS_BIN_DIR/nikto"
    log "Nikto installed successfully. Wrapper script created in $TOOLS_BIN_DIR."
    # Note: Nikto might have Perl dependencies. User might need to install them manually if issues arise.
}

# Install SecLists (git clone)
install_seclists() {
    log "Checking for SecLists..."
    if [ -d "$SECLISTS_PATH" ]; then
        log "SecLists found in $SECLISTS_PATH. Updating..."
        (cd "$SECLISTS_PATH" && git pull) || warn "Failed to update SecLists."
        return 0
    fi
    log "Installing SecLists from GitHub to $SECLISTS_PATH..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_PATH"
    if [[ $? -ne 0 ]]; then error "Failed to clone SecLists."; fi
    log "SecLists installed successfully."
}

# --- Verification ---
verify_installations() {
    log "Verifying tool installations..."
    local tools_to_verify=(
        "$GO_INSTALL_PATH/bin/go"
        "$GO_BIN_PATH/subfinder"
        "$GO_BIN_PATH/assetfinder"
        # "$GO_BIN_PATH/amass" # REMOVED
        "$GO_BIN_PATH/nuclei"
        # "$GO_BIN_PATH/katana" # REMOVED
        "$GO_BIN_PATH/gau"
        "$GO_BIN_PATH/httpx"
        # "$GO_BIN_PATH/naabu" # REMOVED
        "$GO_BIN_PATH/waybackurls"
        "$GO_BIN_PATH/gobuster"
        "$TOOLS_BIN_DIR/jq"
        "$TOOLS_BIN_DIR/sqlmap"
        "$TOOLS_BIN_DIR/nikto"
    )
    local failed_tools=()

    for tool_path in "${tools_to_verify[@]}"; do
        if command -v "$tool_path" &>/dev/null || [ -f "$tool_path" ]; then
            log "Verified: $tool_path"
        else
            warn "Verification failed for: $tool_path"
            failed_tools+=("$(basename $tool_path)")
        fi
    done

    # Verify SecLists Directory
    if [ -d "$SECLISTS_PATH" ]; then
        log "Verified: SecLists directory ($SECLISTS_PATH)"
    else
        warn "SecLists directory verification failed ($SECLISTS_PATH)."
        failed_tools+=("SecLists")
    fi

    if [ ${#failed_tools[@]} -ne 0 ]; then
        error "Setup process completed, but verification failed for: ${failed_tools[*]}. Please check the logs."
    else
        log "All required tools and SecLists verified successfully!"
    fi
}

# --- Main Execution Flow ---
main() {
    log "Starting local tool installation and setup process (v2) for user: $(whoami)"
    log "Installation base directory: $TOOLS_DIR"

    # Check basic dependencies needed by this script
    if ! command -v curl &>/dev/null; then error "'curl' is required but not found. Please install it manually."; fi
    if ! command -v git &>/dev/null; then error "'git' is required but not found. Please install it manually."; fi
    if ! command -v tar &>/dev/null; then error "'tar' is required but not found. Please install it manually."; fi
    if ! command -v python3 &>/dev/null; then error "'python3' is required for sqlmap but not found. Please install it manually."; fi
    if ! command -v perl &>/dev/null; then error "'perl' is required for nikto but not found. Please install it manually."; fi

    setup_environment
    install_go
    install_go_tools
    install_jq
    install_sqlmap
    install_nikto
    install_seclists
    verify_installations

    log "Setup script finished."
    echo -e "${GREEN}-----------------------------------------------------${NC}"
    echo -e "${GREEN}Local setup complete. All tools installed under $TOOLS_DIR and $GO_PATH."
    if [ "$RC_UPDATED" = true ]; then
        echo -e "${YELLOW}IMPORTANT: Your $USER_RC_FILE was updated. Run 'source $USER_RC_FILE' or restart your shell.${NC}"
    fi
    echo -e "${GREEN}You can now run the updated recon script: ./propylea_nosudo_v2.sh <domain>${NC}"
    echo -e "${GREEN}-----------------------------------------------------${NC}"
}

# Trap Ctrl+C
trap 'echo -e "\n${RED}[!] Script interrupted by user.${NC}"; exit 1' INT

# Execute main
main

