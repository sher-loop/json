#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MALICIOUS_PACKAGES=("axios@0.30.4" "axios@1.14.1" "plain-crypto-js@4.2.0" "plain-crypto-js@4.2.1" "@shadanai/openclaw" "@qqbrowser/openclaw-qbot")

MALICIOUS_FILES=("/Library/Caches/com.apple.act.mond" "/tmp/ld.py" "$TMPDIR/6202033")

C2_DOMAIN="sfrclak"
C2_IP="142.11.206.73"

# Save reports to Desktop
DESKTOP_DIR="$HOME/Desktop"
if [ ! -d "$DESKTOP_DIR" ]; then
    DESKTOP_DIR=$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")
fi
if [ ! -d "$DESKTOP_DIR" ]; then
    DESKTOP_DIR="$HOME"
fi

HOSTNAME_VAL=$(hostname)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$DESKTOP_DIR/scan_report_${HOSTNAME_VAL}_${TIMESTAMP}.txt"
HTML_REPORT="$DESKTOP_DIR/scan_report_${HOSTNAME_VAL}_${TIMESTAMP}.html"
found_count=0
FINDINGS=""

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

log_found() {
    local msg="$1"
    local detail="$2"
    FINDINGS="${FINDINGS}<tr><td style='color:#dc3545;font-weight:bold'>${msg}</td><td>${detail}</td></tr>"
    found_count=$((found_count + 1))
}

echo -e "${YELLOW}=========================================="
echo "  IOC Detection Script (Linux/macOS)"
echo "==========================================${NC}"
echo ""

log "=========================================="
log "  IOC Detection Script (Linux/macOS)"
log "  Hostname : $HOSTNAME_VAL"
log "  User     : $(whoami)"
log "  Date     : $(date)"
log "  OS       : $(uname -a)"
log "  Reports  : $DESKTOP_DIR"
log "=========================================="
log ""

# [1] Checking npm Global Packages
echo -e "${YELLOW}[1] Checking npm Global Packages${NC}"
echo "------------------------------------------"
log "${YELLOW}[1] Checking npm Global Packages${NC}"
log "------------------------------------------"

if command -v npm &>/dev/null; then
    global_pkgs=$(npm list -g --depth=0 --json 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | grep -E "axios|plain-crypto|openclaw" || true)
    if [ -n "$global_pkgs" ]; then
        echo -e "${RED}[!] MALICIOUS PACKAGES FOUND IN GLOBAL:${NC}"
        log "${RED}[!] MALICIOUS PACKAGES FOUND IN GLOBAL:${NC}"
        npm list -g --depth=0 2>/dev/null | grep -iE "axios|plain-crypto|openclaw" | while read -r line; do
            echo -e "    $line"
            log "    $line"
        done
        log_found "Malicious packages in global npm" "$global_pkgs"
    else
        echo -e "${GREEN}[OK] No malicious packages in global${NC}"
        log "${GREEN}[OK] No malicious packages in global${NC}"
    fi
else
    echo "[!] npm not found"
    log "[!] npm not found"
fi

echo ""
log ""

# [2] Checking All Installed Versions of Malicious Packages
echo -e "${YELLOW}[2] Checking All Installed Versions of Malicious Packages${NC}"
echo "------------------------------------------"
log "${YELLOW}[2] Checking All Installed Versions of Malicious Packages${NC}"
log "------------------------------------------"

for pkg in "${MALICIOUS_PACKAGES[@]}"; do
    pkg_name=$(echo "$pkg" | cut -d'@' -f1)
    result=$(npm list -g "$pkg_name" 2>/dev/null || true)
    if echo "$result" | grep -q "$pkg_name"; then
        echo -e "${RED}[!] FOUND: $pkg${NC}"
        echo "    Location: Global npm"
        log "${RED}[!] FOUND: $pkg${NC}"
        log "    Location: Global npm"
        log_found "$pkg" "Location: Global npm"
    fi
done

echo ""
log ""

# [3] Scanning All Project Folders for Malicious Packages
echo -e "${YELLOW}[3] Scanning All Project Folders for Malicious Packages${NC}"
echo "------------------------------------------"
echo "[*] Searching in common locations..."
log "${YELLOW}[3] Scanning All Project Folders for Malicious Packages${NC}"
log "------------------------------------------"
log "[*] Searching in common locations..."

SEARCH_DIRS=("$HOME" "/var/www" "/opt" "/home" "/tmp" "$PWD")

for dir in "${SEARCH_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        while IFS= read -r -d '' node_modules; do
            pkg_json_dir=$(dirname "$node_modules")
            if [ -f "$pkg_json_dir/package.json" ]; then
                for pkg in "${MALICIOUS_PACKAGES[@]}"; do
                    pkg_name=$(echo "$pkg" | cut -d'@' -f1)
                    if grep -q "\"$pkg_name\"" "$pkg_json_dir/package.json" 2>/dev/null; then
                        echo -e "${RED}[!] FOUND: $pkg${NC}"
                        echo "    Project: $pkg_json_dir"
                        echo "    File: $pkg_json_dir/package.json"
                        log "${RED}[!] FOUND: $pkg${NC}"
                        log "    Project: $pkg_json_dir"
                        log "    File: $pkg_json_dir/package.json"
                        log_found "$pkg" "Project: $pkg_json_dir"
                    fi
                done
            fi
        done < <(find "$dir" -name "node_modules" -type d -print0 2>/dev/null)
    fi
done

echo ""
log ""

# [4] Checking Suspicious Files
echo -e "${YELLOW}[4] Checking Suspicious Files${NC}"
echo "------------------------------------------"
log "${YELLOW}[4] Checking Suspicious Files${NC}"
log "------------------------------------------"

for f in "${MALICIOUS_FILES[@]}"; do
    if [ -e "$f" ]; then
        echo -e "${RED}[!] FOUND: $f${NC}"
        ls -la "$f" 2>/dev/null
        log "${RED}[!] FOUND: $f${NC}"
        log "$(ls -la "$f" 2>/dev/null)"
        log_found "Malware artifact: $f" "$(ls -la "$f" 2>/dev/null)"
    fi
done

if [ ! -e "/tmp/ld.py" ] && [ ! -e "$TMPDIR/6202033" ] && [ ! -e "/Library/Caches/com.apple.act.mond" ]; then
    echo -e "${GREEN}[OK] No suspicious files found${NC}"
    log "${GREEN}[OK] No suspicious files found${NC}"
fi

echo ""
log ""

# [5] Checking Network Indicators
echo -e "${YELLOW}[5] Checking Network Indicators${NC}"
echo "------------------------------------------"
echo "[*] C2 Domain: $C2_DOMAIN"
echo "[*] C2 IP: $C2_IP"
log "${YELLOW}[5] Checking Network Indicators${NC}"
log "------------------------------------------"
log "[*] C2 Domain: $C2_DOMAIN"
log "[*] C2 IP: $C2_IP"

if [ -f /etc/hosts ]; then
    if grep -q "$C2_DOMAIN" /etc/hosts 2>/dev/null; then
        echo -e "${RED}[!] MALICIOUS DOMAIN FOUND IN /etc/hosts${NC}"
        grep "$C2_DOMAIN" /etc/hosts
        log "${RED}[!] MALICIOUS DOMAIN FOUND IN /etc/hosts${NC}"
        log "$(grep "$C2_DOMAIN" /etc/hosts)"
        log_found "C2 domain in /etc/hosts" "$(grep "$C2_DOMAIN" /etc/hosts)"
    fi
fi

echo ""
echo "[*] Checking active network connections..."
log ""
log "[*] Checking active network connections..."

if command -v netstat &>/dev/null; then
    if netstat -an 2>/dev/null | grep -q "$C2_IP"; then
        echo -e "${RED}[!] ACTIVE CONNECTION TO C2 IP FOUND${NC}"
        netstat -an | grep "$C2_IP"
        log "${RED}[!] ACTIVE CONNECTION TO C2 IP FOUND${NC}"
        log "$(netstat -an | grep "$C2_IP")"
        log_found "Active connection to C2 IP $C2_IP" "$(netstat -an | grep "$C2_IP")"
    else
        echo -e "${GREEN}[OK] No connection to C2 IP${NC}"
        log "${GREEN}[OK] No connection to C2 IP${NC}"
    fi
elif command -v ss &>/dev/null; then
    if ss -tan 2>/dev/null | grep -q "$C2_IP"; then
        echo -e "${RED}[!] ACTIVE CONNECTION TO C2 IP FOUND${NC}"
        ss -tan | grep "$C2_IP"
        log "${RED}[!] ACTIVE CONNECTION TO C2 IP FOUND${NC}"
        log "$(ss -tan | grep "$C2_IP")"
        log_found "Active connection to C2 IP $C2_IP" "$(ss -tan | grep "$C2_IP")"
    else
        echo -e "${GREEN}[OK] No connection to C2 IP${NC}"
        log "${GREEN}[OK] No connection to C2 IP${NC}"
    fi
fi

echo ""
log ""

# [6] Checking Running Processes
echo -e "${YELLOW}[6] Checking Running Processes${NC}"
echo "------------------------------------------"
echo "[*] Suspicious process names: ld.py, 6202033, act.mond"
log "${YELLOW}[6] Checking Running Processes${NC}"
log "------------------------------------------"
log "[*] Suspicious process names: ld.py, 6202033, act.mond"

suspicious_procs=$(ps aux 2>/dev/null | grep -iE "ld\.py|6202033|act\.mond" | grep -v grep || true)

if [ -n "$suspicious_procs" ]; then
    echo -e "${RED}[!] SUSPICIOUS PROCESSES FOUND:${NC}"
    echo "$suspicious_procs"
    log "${RED}[!] SUSPICIOUS PROCESSES FOUND:${NC}"
    log "$suspicious_procs"
    log_found "Suspicious processes running" "$suspicious_procs"
else
    echo -e "${GREEN}[OK] No suspicious processes${NC}"
    log "${GREEN}[OK] No suspicious processes${NC}"
fi

echo ""
log ""

# [7] Checking Cron Jobs for Persistence
echo -e "${YELLOW}[7] Checking Cron Jobs for Persistence${NC}"
echo "------------------------------------------"
log "${YELLOW}[7] Checking Cron Jobs for Persistence${NC}"
log "------------------------------------------"

cron_found=0

if [ -f /etc/crontab ]; then
    if grep -qE "ld\.py|6202033|sfrclak" /etc/crontab 2>/dev/null; then
        echo -e "${RED}[!] SUSPICIOUS CRON ENTRIES FOUND${NC}"
        grep -E "ld\.py|6202033|sfrclak" /etc/crontab
        log "${RED}[!] SUSPICIOUS CRON ENTRIES FOUND${NC}"
        log "$(grep -E "ld\.py|6202033|sfrclak" /etc/crontab)"
        log_found "Suspicious cron entry in /etc/crontab" "$(grep -E 'ld\.py|6202033|sfrclak' /etc/crontab)"
        cron_found=1
    fi
fi

for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    user_cron=$(crontab -l -u "$user" 2>/dev/null || true)
    if echo "$user_cron" | grep -qE "ld\.py|6202033|sfrclak" 2>/dev/null; then
        echo -e "${RED}[!] Found in crontab for $user${NC}"
        log "${RED}[!] Found in crontab for $user${NC}"
        log_found "Suspicious cron job for user $user" "$(echo "$user_cron" | grep -E 'ld\.py|6202033|sfrclak')"
        cron_found=1
    fi
done

if [ -d /etc/cron.d ]; then
    for cronfile in /etc/cron.d/*; do
        if grep -qE "ld\.py|6202033|sfrclak" "$cronfile" 2>/dev/null; then
            echo -e "${RED}[!] Suspicious entry in $cronfile${NC}"
            log "${RED}[!] Suspicious entry in $cronfile${NC}"
            log_found "Suspicious entry in $cronfile" "$(grep -E 'ld\.py|6202033|sfrclak' "$cronfile")"
            cron_found=1
        fi
    done
fi

[ $cron_found -eq 0 ] && echo -e "${GREEN}[OK] No suspicious cron entries${NC}" && log "${GREEN}[OK] No suspicious cron entries${NC}"

echo ""
log ""

# [8] Checking Startup Items (macOS/Linux)
echo -e "${YELLOW}[8] Checking Startup Items (macOS/Linux)${NC}"
echo "------------------------------------------"
log "${YELLOW}[8] Checking Startup Items (macOS/Linux)${NC}"
log "------------------------------------------"

startup_found=0

# macOS LaunchAgents
if [ -d "$HOME/Library/LaunchAgents" ]; then
    if ls -la "$HOME/Library/LaunchAgents" 2>/dev/null | grep -qE "6202033|act"; then
        echo -e "${RED}[!] SUSPICIOUS LAUNCH AGENT FOUND${NC}"
        ls -la "$HOME/Library/LaunchAgents" | grep -E "6202033|act"
        log "${RED}[!] SUSPICIOUS LAUNCH AGENT FOUND${NC}"
        log "$(ls -la "$HOME/Library/LaunchAgents" | grep -E "6202033|act")"
        log_found "Suspicious macOS LaunchAgent" "$(ls -la "$HOME/Library/LaunchAgents" | grep -E "6202033|act")"
        startup_found=1
    fi
fi

# Linux init.d
if [ -d "/etc/init.d" ]; then
    if ls -la "/etc/init.d" 2>/dev/null | grep -qE "6202033|ld"; then
        echo -e "${RED}[!] SUSPICIOUS INIT SCRIPT FOUND${NC}"
        ls -la "/etc/init.d" | grep -E "6202033|ld"
        log "${RED}[!] SUSPICIOUS INIT SCRIPT FOUND${NC}"
        log "$(ls -la "/etc/init.d" | grep -E "6202033|ld")"
        log_found "Suspicious init.d script" "$(ls -la "/etc/init.d" | grep -E "6202033|ld")"
        startup_found=1
    fi
fi

# systemd services
if [ -d "/etc/systemd/system" ]; then
    if ls -la "/etc/systemd/system" 2>/dev/null | grep -qiE "6202033|sfrclak|ld\.py"; then
        echo -e "${RED}[!] SUSPICIOUS SYSTEMD SERVICE FOUND${NC}"
        ls -la "/etc/systemd/system" | grep -iE "6202033|sfrclak|ld\.py"
        log "${RED}[!] SUSPICIOUS SYSTEMD SERVICE FOUND${NC}"
        log_found "Suspicious systemd service" "$(ls -la "/etc/systemd/system" | grep -iE "6202033|sfrclak|ld\.py")"
        startup_found=1
    fi
fi

# Shell rc files
for rcfile in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zshrc"; do
    if [ -f "$rcfile" ]; then
        if grep -qE "ld\.py|6202033|sfrclak|plain-crypto" "$rcfile" 2>/dev/null; then
            echo -e "${RED}[!] Suspicious entry in $rcfile${NC}"
            log "${RED}[!] Suspicious entry in $rcfile${NC}"
            log_found "Suspicious entry in $rcfile" "$(grep -E 'ld\.py|6202033|sfrclak|plain-crypto' "$rcfile")"
            startup_found=1
        fi
    fi
done

[ $startup_found -eq 0 ] && echo -e "${GREEN}[OK] No suspicious startup items${NC}" && log "${GREEN}[OK] No suspicious startup items${NC}"

echo ""
log ""

# =============================================================================
# Scan Summary
# =============================================================================
echo "=========================================="
echo -e "${YELLOW}  SCAN SUMMARY${NC}"
echo "=========================================="
log "=========================================="
log "  SCAN SUMMARY"
log "=========================================="

if [ $found_count -gt 0 ]; then
    echo -e "${RED}[!] THREATS DETECTED: $found_count${NC}"
    log "${RED}[!] THREATS DETECTED: $found_count${NC}"
    echo ""
    echo -e "${YELLOW}  RECOMMENDED ACTIONS:${NC}"
    echo "    1. Remove affected packages: npm uninstall <package>"
    echo "    2. Delete malware artifacts found above"
    echo "    3. Clear npm cache: npm cache clean --force"
    echo "    4. Run full antivirus/EDR scan"
    echo "    5. Check firewall logs for C2: $C2_DOMAIN / $C2_IP"
    echo "    6. Rotate any exposed credentials"
    echo "    7. Notify security team immediately"
    log "  RECOMMENDED ACTIONS:"
    log "    1. Remove affected packages: npm uninstall <package>"
    log "    2. Delete malware artifacts found above"
    log "    3. Clear npm cache: npm cache clean --force"
    log "    4. Run full antivirus/EDR scan"
    log "    5. Check firewall logs for C2: $C2_DOMAIN / $C2_IP"
    log "    6. Rotate any exposed credentials"
    log "    7. Notify security team immediately"
else
    echo -e "${GREEN}[OK] No threats detected${NC}"
    log "${GREEN}[OK] No threats detected${NC}"
fi

# =============================================================================
# Generate HTML Report on Desktop
# =============================================================================

if [ $found_count -gt 0 ]; then
    STATUS_COLOR="#dc3545"
    STATUS_TEXT="$found_count THREAT(S) DETECTED"
else
    STATUS_COLOR="#28a745"
    STATUS_TEXT="NO THREATS DETECTED"
fi

if [ -n "$FINDINGS" ]; then
    FINDINGS_HTML="<h2>Findings</h2><table><tr><th>Issue</th><th>Details</th></tr>$FINDINGS</table>"
else
    FINDINGS_HTML=""
fi

FULL_LOG=$(sed 's/\x1b\[[0-9;]*m//g' "$REPORT_FILE" 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g')

cat > "$HTML_REPORT" <<HTMLEOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IOC Scan Report - $HOSTNAME_VAL</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .status { padding: 15px; border-radius: 5px; color: white; font-size: 18px; font-weight: bold; text-align: center; background: $STATUS_COLOR; }
        .info { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 20px 0; }
        .info div { background: #f8f9fa; padding: 8px 12px; border-radius: 4px; }
        .info label { font-weight: bold; color: #555; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; font-weight: bold; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 13px; line-height: 1.5; }
        .footer { margin-top: 30px; text-align: center; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IOC & Malicious Package Scan Report</h1>
        <div class="status">$STATUS_TEXT</div>
        <div class="info">
            <div><label>Hostname:</label> $HOSTNAME_VAL</div>
            <div><label>OS:</label> $(uname -sr)</div>
            <div><label>User:</label> $(whoami)</div>
            <div><label>Scan Date:</label> $(date)</div>
        </div>
        <h2>C2 Indicators</h2>
        <table>
            <tr><th>Type</th><th>Value</th></tr>
            <tr><td>Domain</td><td>$C2_DOMAIN</td></tr>
            <tr><td>IP Address</td><td>$C2_IP</td></tr>
            <tr><td>URL</td><td>http://sfrclak.com:8000/6202033</td></tr>
        </table>
        <h2>Malicious Packages Scanned</h2>
        <table>
            <tr><th>Package</th><th>Version</th></tr>
            <tr><td>axios</td><td>0.30.4, 1.14.1</td></tr>
            <tr><td>plain-crypto-js</td><td>4.2.0, 4.2.1</td></tr>
            <tr><td>@shadanai/openclaw</td><td>2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2</td></tr>
            <tr><td>@qqbrowser/openclaw-qbot</td><td>0.0.130</td></tr>
        </table>
        $FINDINGS_HTML
        <h2>Full Scan Log</h2>
        <pre>$FULL_LOG</pre>
        <div class="footer">Generated by Malicious Package & IOC Scanner v1.0</div>
    </div>
</body>
</html>
HTMLEOF

echo ""
echo "=========================================="
echo -e "${CYAN}  Reports saved to Desktop:${NC}"
echo -e "${CYAN}    TXT  : $REPORT_FILE${NC}"
echo -e "${CYAN}    HTML : $HTML_REPORT${NC}"
echo "=========================================="
log ""
log "Reports saved to Desktop:"
log "  TXT  : $REPORT_FILE"
log "  HTML : $HTML_REPORT"
