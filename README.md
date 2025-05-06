Works best on Linux 22 and up, Launch the stall.sh to download or maintain tech stack
The gate is all yours (its not perfect yet but its honnest work from a pentesting amateur)




next up: 
UPGRADES:

Tools like gobuster and nmap can be noisy: options for stealth could avoid detection.

New tools:

The focus on SQL injection is narrow; adding tests for XSS, CSRF, or authentication bypasses would make it more complete.

OWASP ZAP / Burp Suite
to deepen webapp scanning

# dnsx (go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest)
Validate subdomains and check DNS misconfigurations (e.g., dangling CNAMEs for subdomain takeovers).
Add to passive_recon()
log "Running dnsx for DNS validation..."
run_cmd "dnsx -l $SUBDOMAINS_FINAL -silent -resp" > "$OUTPUT_DIR/dnsx_tmp.txt"
cat "$OUTPUT_DIR/dnsx_tmp.txt" >> "$SUBDOMAINS_RAW" 2>/dev/null; rm -f "$OUTPUT_DIR/dnsx_tmp.txt"

# dalfox (go install -v github.com/hahwul/dalfox/v2/cmd/dalfox@latest)
Scan for XSS vulnerabilities in URLs.
Add to vulnerability_scan()
log "Running dalfox for XSS scanning..."
run_cmd "dalfox file $ALL_URLS --output $OUTPUT_DIR/dalfox_results.txt" || warn "dalfox scan failed."

# Arjun (pip3 install arjun --user)
Discover hidden parameters for sqlmap.
Add to exploit()
log "Running Arjun for parameter discovery..."
run_cmd "arjun -u $ALL_URLS -oT $OUTPUT_DIR/arjun_params.txt" || warn "Arjun failed."

# JSA (pip3 install -r requirements.txt --user)
Parse JavaScript files for sensitive data.
Add to active_recon()
log "Running JSA for JS analysis..."
run_cmd "jsa -u $ALL_URLS -o $OUTPUT_DIR/jsa_results.txt" || warn "JSA failed."

Cloud Recon:
Use cloud_enum to check for misconfigured cloud assets (e.g., S3 buckets, Azure blobs).
Add to passive_recon()
log "Running cloud_enum for cloud assets..."
run_cmd "cloud_enum -k $domain -o $OUTPUT_DIR/cloud_enum_results.txt" || warn "cloud_enum failed."

Custom Wordlists: Use target-specific wordlists for gobuster (e.g., generate them based on the target’s tech stack using cewl or scrape their JS files).

Couple integrations from ReconFTW or/and LazyRecon instead of parts of my own code could simplify the job
