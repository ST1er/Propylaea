#!/bin/bash

# propylea_nosudo_v2.sh: Runs reconnaissance using locally installed tools.

# --- Configuration (Must match stall_nosudo_v2.sh) ---
BASE_OUTPUT_DIR="Recon_v2"
USER_HOME=$HOME
TOOLS_DIR="$USER_HOME/tools"
TOOLS_BIN_DIR="$TOOLS_DIR/bin"
TOOLS_SRC_DIR="$TOOLS_DIR/src"
GO_INSTALL_PATH="$TOOLS_DIR/go"
GO_PATH="$USER_HOME/go_projects"
GO_BIN_PATH="$GO_PATH/bin"
WORDLIST_PATH="$USER_HOME/wordlists"
SECLISTS_PATH="$WORDLIST_PATH/SecLists"
DEFAULT_WORDLIST="$SECLISTS_PATH/Discovery/Web-Content/directory-list-2.3-medium.txt"

# Color definitions
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
# --- Environment Setup ---
# Ensure local bin directories are in PATH
export PATH="$TOOLS_BIN_DIR:$GO_INSTALL_PATH/bin:$GO_BIN_PATH:$PATH"

# --- Logging Functions ---
banner() { echo -e "\n${BLUE}===== [ $1 ] =====${NC}"; }
log() { echo -e "${GREEN}[*] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[!] ERROR: $1${NC}" >&2; exit 1; }

# --- Tool Verification ---
check_tools() {
    banner "Checking for required tools (Locally Installed)"
    local tools_to_check=(
        # Go tools (should be in $GO_BIN_PATH)
        # "$GO_BIN_PATH/amass" # REMOVED
        "$GO_BIN_PATH/subfinder"
        "$GO_BIN_PATH/assetfinder"
        "$GO_BIN_PATH/gau"
        "$GO_BIN_PATH/httpx"
        "$GO_BIN_PATH/waybackurls"
        # "$GO_BIN_PATH/katana" # REMOVED
        "$GO_BIN_PATH/gobuster"
        "$GO_BIN_PATH/nuclei"
        # "$GO_BIN_PATH/naabu" # Nmap alternative - REMOVED
        # Other tools (should be in $TOOLS_BIN_DIR)
        "$TOOLS_BIN_DIR/jq"
        "$TOOLS_BIN_DIR/sqlmap" # Wrapper script
        "$TOOLS_BIN_DIR/nikto"  # Wrapper script
    )
    local missing_tools=()
    for tool_path in "${tools_to_check[@]}"; do
        if ! command -v "$tool_path" &>/dev/null && ! [ -x "$tool_path" ]; then
            missing_tools+=("$(basename "$tool_path")")
        fi
    done

    # Check basic system tools needed by the script itself
    local basic_tools=(curl git python3 perl)
     for tool in "${basic_tools[@]}"; do
         if ! command -v "$tool" &>/dev/null; then
             missing_tools+=("$tool (system)")
         fi
     done

    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}. Please run stall_nosudo_v2.sh or install them manually."
    else
        log "All required tools seem to be available."
    fi

    # Check specifically for wordlist needed by Gobuster
    if [ ! -f "$DEFAULT_WORDLIST" ]; then
         warn "Could not find Gobuster wordlist ($DEFAULT_WORDLIST). Gobuster scan might fail or be skipped. Ensure SecLists was installed correctly by stall_nosudo_v2.sh."
    fi
}

# --- Command Execution ---
run_cmd() {
    local cmd_string="$1"
    local output_file="$2"
    local full_cmd="$cmd_string"
    local exit_code
    local stderr_output
    local cmd_output

    # Ensure PATH includes local bins for the command execution context
    # This might be redundant if the parent shell already has it, but ensures safety.
    local current_path="$TOOLS_BIN_DIR:$GO_INSTALL_PATH/bin:$GO_BIN_PATH:$PATH"

    # log "Executing: PATH=$current_path $cmd_string" # Verbose logging if needed

    if [ -n "$output_file" ]; then
         # Use env to ensure the PATH is set for the command
         env PATH="$current_path" bash -c "$cmd_string" > "$output_file" 2> "${output_file}.stderr"
         exit_code=$?
         stderr_output=$(<"${output_file}.stderr")
         rm -f "${output_file}.stderr"
    else
        # Use env to ensure the PATH is set for the command
        cmd_output=$(env PATH="$current_path" bash -c "$cmd_string" 2>&1)
        exit_code=$?
    fi

    if [ $exit_code -ne 0 ]; then
        warn "Command failed (Exit Code: $exit_code): $cmd_string"
        if [ -n "$stderr_output" ]; then warn "Stderr Output: $stderr_output"; fi
        if [ -n "$cmd_output" ]; then warn "Stdout/Stderr Output: $cmd_output"; fi
        return 1 # Indicate failure
    fi
    return 0 # Indicate success
}

# --- Directory Setup ---
setup_output_dir() {
    local domain="$1"
    local safe_domain=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    OUTPUT_DIR="${BASE_OUTPUT_DIR}/recon-${safe_domain}"
    log "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR" || error "Failed to create output directory: $OUTPUT_DIR"
    log "Results will be saved in $OUTPUT_DIR"

    # Define file paths
    SUBDOMAINS_RAW="$OUTPUT_DIR/subdomains_raw.txt"
    SUBDOMAINS_FINAL="$OUTPUT_DIR/subdomains_final.txt"
    LIVE_SUBDOMAINS_HTTPX="$OUTPUT_DIR/live_subdomains_httpx.txt" # URLs from httpx
    LIVE_SUBDOMAINS_HOSTS="$OUTPUT_DIR/live_subdomains_hosts.txt" # Hosts only for naabu
    URLS_GAU="$OUTPUT_DIR/urls_gau.txt"
    URLS_WAYBACK="$OUTPUT_DIR/urls_wayback.txt"
    # URLS_KATANA="$OUTPUT_DIR/urls_katana.txt" # REMOVED
    URLS_GOBUSTER="$OUTPUT_DIR/urls_gobuster.txt"
    ALL_URLS="$OUTPUT_DIR/urls_all_unique.txt"
    # NAABU_RESULTS="$OUTPUT_DIR/naabu_portscan_results.txt" # REMOVED
    HTTPX_TECH_RESULTS="$OUTPUT_DIR/httpx_tech_results.txt"
    NIKTO_RESULTS="$OUTPUT_DIR/nikto_scan_results.txt"
    NUCLEI_SUBDOMAIN_RESULTS="$OUTPUT_DIR/nuclei_subdomain_results.txt"
    NUCLEI_URL_RESULTS="$OUTPUT_DIR/nuclei_url_results.txt"
    SQLMAP_RESULTS_DIR="$OUTPUT_DIR/sqlmap_logs"
    SQLMAP_VULN_FILE="$OUTPUT_DIR/sqlmap_vulnerable_urls.txt"
    SUMMARY_REPORT="$OUTPUT_DIR/summary_report.txt"
}

# --- Phase 1: Passive Subdomain Enumeration ---
passive_recon() {
    local domain="$1"
    banner "Phase 1: Passive Subdomain Enumeration for $domain"
    > "$SUBDOMAINS_RAW"
    # run_cmd "amass enum -passive -d $domain -o $OUTPUT_DIR/amass_tmp.txt" # REMOVED
    # cat "$OUTPUT_DIR/amass_tmp.txt" >> "$SUBDOMAINS_RAW" 2>/dev/null; rm -f "$OUTPUT_DIR/amass_tmp.txt"
    log "Running Subfinder..."
    run_cmd "subfinder -d $domain -all -silent -o $OUTPUT_DIR/subfinder_tmp.txt"
    cat "$OUTPUT_DIR/subfinder_tmp.txt" >> "$SUBDOMAINS_RAW" 2>/dev/null; rm -f "$OUTPUT_DIR/subfinder_tmp.txt"
    log "Running Assetfinder..."
    run_cmd "assetfinder --subs-only $domain" > "$OUTPUT_DIR/assetfinder_tmp.txt"
    cat "$OUTPUT_DIR/assetfinder_tmp.txt" >> "$SUBDOMAINS_RAW" 2>/dev/null; rm -f "$OUTPUT_DIR/assetfinder_tmp.txt"
    log "Querying crt.sh..."
    # Use jq installed locally
    run_cmd "curl -s 'https://crt.sh/?q=%25.$domain&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u" > "$OUTPUT_DIR/crtsh_tmp.txt"
    cat "$OUTPUT_DIR/crtsh_tmp.txt" >> "$SUBDOMAINS_RAW" 2>/dev/null; rm -f "$OUTPUT_DIR/crtsh_tmp.txt"
    log "Running GAU (passive URL discovery)..."
    run_cmd "gau --subs $domain" "$URLS_GAU"
    log "Processing discovered subdomains..."
    if [ ! -s "$SUBDOMAINS_RAW" ]; then warn "No subdomains found during passive enumeration phase."; fi
    # Filter for valid hostnames and sort uniquely
    cat "$SUBDOMAINS_RAW" | grep -E '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' | sort -u > "$SUBDOMAINS_FINAL"
    local final_count=$(wc -l < "$SUBDOMAINS_FINAL" 2>/dev/null || echo 0)
    log "Passive recon completed. Found $final_count unique potential subdomains in $SUBDOMAINS_FINAL."
    rm -f "$SUBDOMAINS_RAW"
}

# --- Phase 2: Active Reconnaissance & Probing ---
active_recon() {
    local domain="$1"
    banner "Phase 2: Active Reconnaissance on $domain"
    if [ ! -s "$SUBDOMAINS_FINAL" ]; then warn "Subdomain file '$SUBDOMAINS_FINAL' is empty. Skipping active recon."; return; fi

    log "Probing subdomains with httpx..."
    # -silent: Show only live hosts, -H: Add User-Agent, -sc: Show status code, -td: Tech detect (for later)
    run_cmd "httpx -l $SUBDOMAINS_FINAL -silent -H 'User-Agent: Mozilla/5.0' -sc -td" "$LIVE_SUBDOMAINS_HTTPX"
    if [ ! -s "$LIVE_SUBDOMAINS_HTTPX" ]; then warn "httpx found no live subdomains. Skipping further active steps."; return; fi

    # Extract just the URLs for further processing
    grep -oE 'https?://[^ ]+' "$LIVE_SUBDOMAINS_HTTPX" > "$OUTPUT_DIR/live_urls.tmp"
    # Extract just the hostnames for port scanning
    sed 's~https*://~~' "$OUTPUT_DIR/live_urls.tmp" | cut -d'[' -f1 | sort -u > "$LIVE_SUBDOMAINS_HOSTS"
    local live_count=$(wc -l < "$LIVE_SUBDOMAINS_HOSTS" 2>/dev/null || echo 0)
    log "Found $live_count live hosts saved in $LIVE_SUBDOMAINS_HOSTS (URLs in $LIVE_SUBDOMAINS_HTTPX)."

    # --- Port Scanning (Naabu - Nmap alternative) --- # REMOVED
    # log "Running Naabu port scan on live hosts (Top 100 ports)..."
    # # -silent: Show only ports, -top-ports 100: Scan top 100 ports, -l: Input list
    # run_cmd "naabu -l $LIVE_SUBDOMAINS_HOSTS -top-ports 100 -silent" "$NAABU_RESULTS"
    # log "Naabu port scan completed. Results in $NAABU_RESULTS."

    # --- Active URL Discovery ---
    log "Running Waybackurls and GAU on live URLs..."
    > "$URLS_WAYBACK"; # > "$URLS_KATANA"
    while IFS= read -r live_url; do
        if [ -n "$live_url" ]; then
             local target_host=$(echo "$live_url" | sed 's~https*://~~')
             run_cmd "waybackurls $target_host" >> "$URLS_WAYBACK"
             # run_cmd "katana -u $live_url -silent -d 5 -H 'User-Agent: Mozilla/5.0'" >> "$URLS_KATANA" # -d 5 for crawl depth - REMOVED
        fi
    done < "$OUTPUT_DIR/live_urls.tmp"; log "Waybackurls/GAU completed."

    # --- Directory Brute-forcing (Gobuster) ---
    log "Running Gobuster..."
    if [ ! -f "$DEFAULT_WORDLIST" ]; then warn "Gobuster wordlist ($DEFAULT_WORDLIST) not found. Skipping scan."; else
        > "$URLS_GOBUSTER"
        while IFS= read -r live_url; do
            if [ -n "$live_url" ]; then
                # -q: quiet, -t 50: threads, - H: User-Agent, -k: skip SSL verify, -f: append slash
                run_cmd "timeout 1800 gobuster dir -u $live_url -w $DEFAULT_WORDLIST -q -t 10 -k -f -H \'User-Agent: Mozilla/5.0\' --no-error" >> "$URLS_GOBUSTER"
            fi
        done < "$OUTPUT_DIR/live_urls.tmp"; log "Gobuster scans completed."
    fi

    # --- Consolidate All URLs ---
    log "Consolidating discovered URLs..."
    cat "$URLS_GAU" "$URLS_WAYBACK" "$URLS_GOBUSTER" 2>/dev/null | grep -Eo "(http|https)://[a-zA-Z0-9./?=_%:-]*" | grep "\.$domain" | sort -u > "$ALL_URLS"
    local url_count=$(wc -l < "$ALL_URLS" 2>/dev/null || echo 0)
    log "Found $url_count unique URLs saved in $ALL_URLS."

    rm -f "$OUTPUT_DIR/live_urls.tmp"
}

# --- Phase 3: Fingerprinting (HTTPX - WhatWeb alternative) ---
fingerprint() {
    banner "Phase 3: Technology Fingerprinting (using httpx)"
    if [ ! -s "$LIVE_SUBDOMAINS_HTTPX" ]; then warn "Live subdomain file from httpx missing. Skipping fingerprinting."; return; fi
    log "Extracting technology data from initial httpx scan results..."
    # The tech data was already gathered during the httpx probe in Phase 2
    cp "$LIVE_SUBDOMAINS_HTTPX" "$HTTPX_TECH_RESULTS"
    log "Technology fingerprinting data saved in $HTTPX_TECH_RESULTS."
}

# --- Phase 4: Vulnerability Scanning ---
vulnerability_scan() {
    banner "Phase 4: Vulnerability Scanning"
    local nuclei_templates_dir="$HOME/nuclei-templates" # User templates dir

    # --- Nikto Scan ---
    if command -v nikto &>/dev/null || [ -x "$TOOLS_BIN_DIR/nikto" ]; then
        if [ ! -s "$LIVE_SUBDOMAINS_HOSTS" ]; then warn "Live host file missing. Skipping Nikto."; else
            log "Running Nikto scans..."; > "$NIKTO_RESULTS"
             while IFS= read -r live_host; do if [ -n "$live_host" ]; then
                 # Use the wrapper script, which handles calling perl correctly
                 # Need to determine if http or https is available. Check httpx results.
                 local live_url=$(grep "$live_host" "$LIVE_SUBDOMAINS_HTTPX" | head -n 1 | grep -oE 'https?://[^ ]+')
                 if [ -n "$live_url" ]; then
                     log "Nikto scanning: $live_url"
                     # -Tuning 4: Less common checks, -ask no: Non-interactive, -no404: Ignore 404s
                     run_cmd "nikto -h $live_url -Tuning 4 -ask no -no404 -UserAgent 'Mozilla/5.0'" >> "$NIKTO_RESULTS"
                 else
                     warn "Could not determine URL for host $live_host from httpx results. Skipping Nikto for this host."
                 fi
             fi; done < "$LIVE_SUBDOMAINS_HOSTS"; log "Nikto scans completed."
        fi
    else warn "Nikto command/wrapper not found. Skipping."; fi

    # --- Nuclei Scan (Subdomains & URLs) ---
    if command -v nuclei &>/dev/null || [ -x "$GO_BIN_PATH/nuclei" ]; then
        # Ensure templates are updated (stall script should have done this, but check again)
        if [ ! -d "$nuclei_templates_dir" ] || [ -z "$(ls -A $nuclei_templates_dir)" ]; then
            log "Updating Nuclei templates again..."
            run_cmd "nuclei -update-templates" || warn "Nuclei template update failed."
        fi

        # Scan Live URLs from httpx results
        if [ ! -s "$LIVE_SUBDOMAINS_HTTPX" ]; then warn "Live subdomain file (httpx) missing. Skipping Nuclei subdomain scan."; else
            log "Running Nuclei on live URLs..."; > "$NUCLEI_SUBDOMAIN_RESULTS"
            # Extract URLs from httpx output for nuclei
            grep -oE 'https?://[^ ]+' "$LIVE_SUBDOMAINS_HTTPX" > "$OUTPUT_DIR/nuclei_targets.tmp"
            run_cmd "nuclei -l $OUTPUT_DIR/nuclei_targets.tmp -H 'User-Agent: Mozilla/5.0' -stats -o $NUCLEI_SUBDOMAIN_RESULTS"; log "Nuclei live URL scans completed."
            rm -f "$OUTPUT_DIR/nuclei_targets.tmp"
        fi

        # Scan All Collected URLs
        if [ ! -s "$ALL_URLS" ]; then warn "All URLs file missing. Skipping Nuclei URL scan."; else
            log "Running Nuclei on all collected URLs..."; > "$NUCLEI_URL_RESULTS"
            run_cmd "nuclei -l $ALL_URLS -H 'User-Agent: Mozilla/5.0' -stats -o $NUCLEI_URL_RESULTS"; log "Nuclei all URL scans completed."
        fi
    else warn "Nuclei command not found. Skipping."; fi
}

# --- Phase 5: Targeted Exploitation (SQLmap) ---
exploit() {
    banner "Phase 5: Attempting Basic Exploitation (SQL Injection)"
    if ! command -v sqlmap &>/dev/null && ! [ -x "$TOOLS_BIN_DIR/sqlmap" ]; then warn "sqlmap command/wrapper not found. Skipping."; return; fi
    if [ ! -s "$ALL_URLS" ]; then warn "URL file missing. Skipping SQLmap."; return; fi

    local potential_sqli_urls="$OUTPUT_DIR/potential_sqli_urls.tmp"
    log "Identifying URLs with parameters for SQLmap..."
    grep '[?].*=' "$ALL_URLS" > "$potential_sqli_urls"
    if [ ! -s "$potential_sqli_urls" ]; then log "No URLs with parameters found. Skipping SQLmap."; rm -f "$potential_sqli_urls"; return; fi

    local sqli_count=$(wc -l < "$potential_sqli_urls" 2>/dev/null || echo 0)
    log "Found $sqli_count URLs with parameters. Testing with SQLmap (batch mode, level 1, risk 1)..."
    mkdir -p "$SQLMAP_RESULTS_DIR"
    > "$SQLMAP_VULN_FILE"

    # Run sqlmap on the list of URLs with parameters
    # --batch: Non-interactive, --level=1, --risk=1: Basic tests
    # --output-dir: Store logs, --results-file: Not reliable for batch, parse output instead
    # Use the wrapper script
    sqlmap_cmd="sqlmap -m $potential_sqli_urls --batch --level=1 --risk=1 --user-agent='Mozilla/5.0' --output-dir='$SQLMAP_RESULTS_DIR'"
    log "Executing: $sqlmap_cmd"
    sqlmap_output_log="$OUTPUT_DIR/sqlmap_batch_output.log"
    run_cmd "$sqlmap_cmd" "$sqlmap_output_log"

    log "Parsing SQLmap output for vulnerabilities..."
    # Check the log file for indicators of success
    if grep -q -E 'Parameter.*is vulnerable|might be injectable' "$sqlmap_output_log"; then
        warn "SQLmap indicates potential SQL injection found! Check logs in $SQLMAP_RESULTS_DIR and $sqlmap_output_log"
        # Try to extract vulnerable URLs from log (might be imperfect)
        grep -oE 'URL: https?://[^ ]+' "$sqlmap_output_log" | sed 's/URL: //' | sort -u >> "$SQLMAP_VULN_FILE"
    fi

    rm -f "$potential_sqli_urls"
    if [ -s "$SQLMAP_VULN_FILE" ]; then log "SQLmap testing completed. Potentially vulnerable URLs saved in $SQLMAP_VULN_FILE."; else log "SQLmap testing completed. No vulnerabilities confirmed in batch mode."; fi
}

# --- Phase 6: Summarize Findings ---
summarize() {
    local domain="$1"; banner "Phase 6: Summarizing Findings for $domain"; > "$SUMMARY_REPORT"
    echo "###############################################" >> "$SUMMARY_REPORT"; echo "# Reconnaissance Summary Report for: $domain (Non-Sudo Mode v2)" >> "$SUMMARY_REPORT"
    echo "# Report generated on: $(date)" >> "$SUMMARY_REPORT"; echo "# Results stored in: $OUTPUT_DIR" >> "$SUMMARY_REPORT"; echo "###############################################" >> "$SUMMARY_REPORT"; echo "" >> "$SUMMARY_REPORT"
    echo "--- Counts ---" >> "$SUMMARY_REPORT"
    local final_sub_count=$( [ -f "$SUBDOMAINS_FINAL" ] && wc -l < "$SUBDOMAINS_FINAL" 2>/dev/null || echo 0 )
    local live_host_count=$( [ -f "$LIVE_SUBDOMAINS_HOSTS" ] && wc -l < "$LIVE_SUBDOMAINS_HOSTS" 2>/dev/null || echo 0 )
    local url_count=$( [ -f "$ALL_URLS" ] && wc -l < "$ALL_URLS" 2>/dev/null || echo 0 )
    local nuclei_sub_vulns=$( [ -f "$NUCLEI_SUBDOMAIN_RESULTS" ] && grep -cE '\[(critical|high|medium)\]' "$NUCLEI_SUBDOMAIN_RESULTS" 2>/dev/null || echo 0 )
    local nuclei_url_vulns=$( [ -f "$NUCLEI_URL_RESULTS" ] && grep -cE '\[(critical|high|medium)\]' "$NUCLEI_URL_RESULTS" 2>/dev/null || echo 0 )
    local sqlmap_vulns=$( [ -f "$SQLMAP_VULN_FILE" ] && wc -l < "$SQLMAP_VULN_FILE" 2>/dev/null || echo 0 )
    echo "Potential Subdomains Found: $final_sub_count ($SUBDOMAINS_FINAL)" >> "$SUMMARY_REPORT"
    echo "Live Hosts Found (httpx): $live_host_count ($LIVE_SUBDOMAINS_HOSTS)" >> "$SUMMARY_REPORT"
    echo "Unique URLs Collected: $url_count ($ALL_URLS)" >> "$SUMMARY_REPORT"
    echo "Open Ports Found (Naabu Top 100): $( [ -f "$NAABU_RESULTS" ] && wc -l < "$NAABU_RESULTS" 2>/dev/null || echo 0 ) ($NAABU_RESULTS)" >> "$SUMMARY_REPORT"
    echo "Potential Vulns (Nuclei Live URLs): $nuclei_sub_vulns ($NUCLEI_SUBDOMAIN_RESULTS)" >> "$SUMMARY_REPORT"
    echo "Potential Vulns (Nuclei All URLs): $nuclei_url_vulns ($NUCLEI_URL_RESULTS)" >> "$SUMMARY_REPORT"
    echo "Potentially SQL Injectable URLs: $sqlmap_vulns ($SQLMAP_VULN_FILE)" >> "$SUMMARY_REPORT"; echo "" >> "$SUMMARY_REPORT"
    echo "--- Key Files ---" >> "$SUMMARY_REPORT"
    [ -f "$SUBDOMAINS_FINAL" ] && echo "Final Subdomains: $SUBDOMAINS_FINAL" >> "$SUMMARY_REPORT"
    [ -f "$LIVE_SUBDOMAINS_HTTPX" ] && echo "Live URLs & Tech (httpx): $LIVE_SUBDOMAINS_HTTPX" >> "$SUMMARY_REPORT"
    [ -f "$NAABU_RESULTS" ] && echo "Port Scan (Naabu): $NAABU_RESULTS" >> "$SUMMARY_REPORT"
    [ -f "$ALL_URLS" ] && echo "All Unique URLs: $ALL_URLS" >> "$SUMMARY_REPORT"
    [ -f "$HTTPX_TECH_RESULTS" ] && echo "Tech Detection (httpx): $HTTPX_TECH_RESULTS" >> "$SUMMARY_REPORT"
    [ -f "$NUCLEI_SUBDOMAIN_RESULTS" ] && echo "Nuclei Live URL Scan: $NUCLEI_SUBDOMAIN_RESULTS" >> "$SUMMARY_REPORT"
    [ -f "$NUCLEI_URL_RESULTS" ] && echo "Nuclei All URL Scan: $NUCLEI_URL_RESULTS" >> "$SUMMARY_REPORT"
    [ -f "$NIKTO_RESULTS" ] && echo "Nikto Scan Results: $NIKTO_RESULTS" >> "$SUMMARY_REPORT"
    [ -f "$SQLMAP_VULN_FILE" ] && echo "SQLmap Vulnerable URLs: $SQLMAP_VULN_FILE" >> "$SUMMARY_REPORT"
    [ -d "$SQLMAP_RESULTS_DIR" ] && echo "SQLmap Logs: $SQLMAP_RESULTS_DIR/" >> "$SUMMARY_REPORT"
    echo "" >> "$SUMMARY_REPORT"
    echo "###############################################" >> "$SUMMARY_REPORT"; log "Summary report written to $SUMMARY_REPORT"; echo -e "${GREEN}-------------------- Summary --------------------${NC}"; cat "$SUMMARY_REPORT"; echo -e "${GREEN}-------------------------------------------------${NC}"
}

# --- Main Execution ---
main() {
    if [ "$#" -ne 1 ]; then error "Usage: $0 <domain.tld>"; fi
    local domain="$1"

    banner "Starting Propylon Reconnaissance v2 for $domain (Non-Sudo Mode)"
    setup_output_dir "$domain"
    check_tools

    passive_recon "$domain"
    active_recon "$domain"
    fingerprint
    vulnerability_scan
    exploit
    summarize "$domain"

    banner "Propylon Reconnaissance v2 Completed for $domain (Non-Sudo Mode)"
    log "All results are stored in: $OUTPUT_DIR/"
}

# Trap Ctrl+C
trap 'echo -e "\n${RED}[!] Script interrupted by user. Exiting.${NC}"; exit 1' INT

# Run main
main "$@"

