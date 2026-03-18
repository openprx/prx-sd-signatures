#!/usr/bin/env bash
#
# PRX-SD Signatures Sync
#
# Downloads and organizes threat intelligence from all free sources
# into a unified format for the PRX-SD antivirus engine.
#
# Usage:
#   ./sync.sh                        # Sync everything
#   ./sync.sh --category hashes      # Only hashes
#   ./sync.sh --category yara        # Only YARA rules
#   ./sync.sh --category clamav      # Only ClamAV
#   ./sync.sh --category ioc         # Only IOC feeds
#   ./sync.sh --stats                # Show current database stats
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF="$SCRIPT_DIR/sync.conf"
CATEGORY="all"
STATS_ONLY=false
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DATE_SHORT=$(date -u +"%Y-%m-%d")

# ─── Parse args ──────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --category) CATEGORY="$2"; shift 2 ;;
        --stats)    STATS_ONLY=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--category all|hashes|yara|clamav|ioc] [--stats]"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ─── Load config ─────────────────────────────────────
[[ -f "$CONF" ]] && source "$CONF"
DOWNLOAD_TIMEOUT=${DOWNLOAD_TIMEOUT:-120}
GIT_DEPTH=${GIT_DEPTH:-1}

# ─── Helpers ─────────────────────────────────────────
R='\033[1;31m' G='\033[1;32m' B='\033[1;34m' C='\033[1;36m' Y='\033[1;33m' N='\033[0m'
log()  { echo -e "${B}[SYNC]${N} $*"; }
ok()   { echo -e "${G}[ OK ]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
err()  { echo -e "${R}[ERR ]${N} $*"; }
stat() { echo -e "${C}[STAT]${N} $*"; }

header() {
    local w=56
    echo ""
    echo -e "${B}╔$(printf '═%.0s' $(seq 1 $w))╗${N}"
    printf "${B}║${N}  %-$((w-2))s${B}║${N}\n" "$1"
    echo -e "${B}╚$(printf '═%.0s' $(seq 1 $w))╝${N}"
    echo ""
}

write_header() {
    local file="$1" source="$2" count="$3"
    {
        echo "# Source: $source"
        echo "# Updated: $TIMESTAMP"
        echo "# Count: $count"
    } > "$file.hdr"
    cat "$file.hdr" "$file.tmp" > "$file" 2>/dev/null || true
    rm -f "$file.hdr" "$file.tmp"
}

# ─── Stats ───────────────────────────────────────────
show_stats() {
    header "PRX-SD Signatures Database Stats"

    local sha_count md5_count yara_files yara_rules ioc_ips ioc_domains ioc_urls

    sha_count=$(cat "$SCRIPT_DIR"/hashes/sha256/*.txt 2>/dev/null | grep -cv '^#\|^$' || echo 0)
    md5_count=$(cat "$SCRIPT_DIR"/hashes/md5/*.txt 2>/dev/null | grep -cv '^#\|^$' || echo 0)
    yara_files=$(find "$SCRIPT_DIR/yara" -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)
    yara_rules=$(grep -r "^rule " "$SCRIPT_DIR/yara" --include="*.yar" --include="*.yara" 2>/dev/null | wc -l)
    ioc_ips=$(wc -l < "$SCRIPT_DIR/ioc/ip-blocklist.txt" 2>/dev/null || echo 0)
    ioc_domains=$(wc -l < "$SCRIPT_DIR/ioc/domain-blocklist.txt" 2>/dev/null || echo 0)
    ioc_urls=$(wc -l < "$SCRIPT_DIR/ioc/url-blocklist.txt" 2>/dev/null || echo 0)

    local clamav_size="0"
    if [[ -f "$SCRIPT_DIR/clamav/main.cvd" ]]; then
        clamav_size=$(du -sh "$SCRIPT_DIR/clamav/" 2>/dev/null | awk '{print $1}')
    fi

    stat "SHA-256 hashes:  $sha_count"
    stat "MD5 hashes:      $md5_count"
    stat "YARA files:      $yara_files"
    stat "YARA rules:      $yara_rules"
    stat "ClamAV DB size:  $clamav_size"
    stat "Blocklist IPs:   $ioc_ips"
    stat "Blocklist domains: $ioc_domains"
    stat "Blocklist URLs:  $ioc_urls"
    stat "Last sync:       $TIMESTAMP"

    local total_size
    total_size=$(du -sh "$SCRIPT_DIR" 2>/dev/null | awk '{print $1}')
    stat "Total size:      $total_size"
}

if [[ "$STATS_ONLY" == "true" ]]; then
    show_stats
    exit 0
fi

# ═══════════════════════════════════════════════════════
#  HASHES
# ═══════════════════════════════════════════════════════

sync_hashes() {
    header "Syncing Hash Signatures"

    local total=0

    # --- MalwareBazaar ---
    if [[ "${MALWAREBAZAAR_ENABLED:-true}" == "true" ]]; then
        log "MalwareBazaar (SHA-256, last 48h)..."
        local out="$SCRIPT_DIR/hashes/sha256/malwarebazaar.txt"
        if curl -sS --max-time "$DOWNLOAD_TIMEOUT" "https://bazaar.abuse.ch/export/txt/sha256/recent/" 2>/dev/null \
            | grep -v '^#\|^$' | while read -r hash; do echo "$hash MalwareBazaar.Recent"; done > "$out.tmp"; then
            local c; c=$(wc -l < "$out.tmp")
            write_header "$out" "abuse.ch MalwareBazaar" "$c"
            total=$((total + c))
            ok "MalwareBazaar: $c hashes"
        else
            warn "MalwareBazaar: download failed"
        fi
    fi

    # --- URLhaus payloads ---
    if [[ "${URLHAUS_ENABLED:-true}" == "true" ]]; then
        log "URLhaus payload hashes..."
        local out="$SCRIPT_DIR/hashes/sha256/urlhaus.txt"
        if curl -sS --max-time "$DOWNLOAD_TIMEOUT" "https://urlhaus.abuse.ch/downloads/payloads/" 2>/dev/null \
            | grep -oP '"[a-f0-9]{64}"' | tr -d '"' | sort -u \
            | while read -r hash; do echo "$hash URLhaus.Payload"; done > "$out.tmp"; then
            local c; c=$(wc -l < "$out.tmp")
            write_header "$out" "abuse.ch URLhaus" "$c"
            total=$((total + c))
            ok "URLhaus: $c hashes"
        else
            warn "URLhaus: download failed"
        fi
    fi

    # --- Feodo Tracker ---
    if [[ "${FEODO_ENABLED:-true}" == "true" ]]; then
        log "Feodo Tracker (banking trojans)..."
        local out="$SCRIPT_DIR/hashes/sha256/feodo.txt"
        if curl -sS --max-time "$DOWNLOAD_TIMEOUT" "https://feodotracker.abuse.ch/downloads/malware_hashes.csv" 2>/dev/null \
            | grep -oP '[a-f0-9]{64}' | sort -u \
            | while read -r hash; do echo "$hash Feodo.BankTrojan"; done > "$out.tmp"; then
            local c; c=$(wc -l < "$out.tmp")
            write_header "$out" "abuse.ch Feodo Tracker" "$c"
            total=$((total + c))
            ok "Feodo: $c hashes"
        else
            warn "Feodo: download failed"
        fi
    fi

    # --- ThreatFox ---
    if [[ "${THREATFOX_ENABLED:-true}" == "true" ]]; then
        log "ThreatFox IOC hashes..."
        local out="$SCRIPT_DIR/hashes/sha256/threatfox.txt"
        if curl -sS --max-time "$DOWNLOAD_TIMEOUT" "https://threatfox.abuse.ch/export/json/md5/recent/" 2>/dev/null \
            | grep -oP '"sha256_hash"\s*:\s*"([a-fA-F0-9]{64})"' | grep -oP '[a-fA-F0-9]{64}' | sort -u \
            | while read -r hash; do echo "$hash ThreatFox.IOC"; done > "$out.tmp"; then
            local c; c=$(wc -l < "$out.tmp")
            write_header "$out" "abuse.ch ThreatFox" "$c"
            total=$((total + c))
            ok "ThreatFox: $c hashes"
        else
            warn "ThreatFox: download failed"
        fi
    fi

    # --- SSL Blacklist ---
    if [[ "${SSLBL_ENABLED:-true}" == "true" ]]; then
        log "SSL Blacklist..."
        local out="$SCRIPT_DIR/hashes/sha256/sslbl.txt"
        if curl -sS --max-time "$DOWNLOAD_TIMEOUT" "https://sslbl.abuse.ch/blacklist/sslblacklist.csv" 2>/dev/null \
            | grep -oP '[a-f0-9]{64}' | sort -u \
            | while read -r hash; do echo "$hash SSLBL.MaliciousCert"; done > "$out.tmp"; then
            local c; c=$(wc -l < "$out.tmp")
            write_header "$out" "abuse.ch SSL Blacklist" "$c"
            total=$((total + c))
            ok "SSL Blacklist: $c hashes"
        else
            warn "SSL Blacklist: download failed"
        fi
    fi

    # --- VirusShare (optional, large) ---
    if [[ "${VIRUSSHARE_ENABLED:-false}" == "true" ]]; then
        log "VirusShare MD5 lists (large download)..."
        local out="$SCRIPT_DIR/hashes/md5/virusshare.txt"
        local vs_total=0
        for i in $(seq "${VIRUSSHARE_LIST_START:-495}" "${VIRUSSHARE_LIST_END:-499}"); do
            local url="https://virusshare.com/hashfiles/VirusShare_$(printf '%05d' "$i").md5"
            if curl -sS --max-time "$DOWNLOAD_TIMEOUT" "$url" 2>/dev/null \
                | grep -v '^#' | grep -v '^$' >> "$out.tmp" 2>/dev/null; then
                vs_total=$((vs_total + 1))
            fi
        done
        if [[ -f "$out.tmp" ]]; then
            local c; c=$(wc -l < "$out.tmp")
            # Convert to our format
            awk '{print $1" VirusShare.MD5"}' "$out.tmp" > "$out.tmp2"
            mv "$out.tmp2" "$out.tmp"
            write_header "$out" "VirusShare" "$c"
            total=$((total + c))
            ok "VirusShare: $c MD5 hashes ($vs_total lists)"
        fi
    fi

    # --- Built-in ---
    local builtin="$SCRIPT_DIR/hashes/sha256/builtin.txt"
    local prx_hashes="/opt/worker/task/prx-sd/signatures-db/hashes/sha256_blocklist.txt"
    if [[ -f "$prx_hashes" ]]; then
        cp "$prx_hashes" "$builtin"
        local c; c=$(grep -cv '^#\|^$' "$builtin" 2>/dev/null || echo 0)
        total=$((total + c))
        ok "Built-in: $c hashes"
    fi

    stat "Total hash entries: $total"
}

# ═══════════════════════════════════════════════════════
#  YARA RULES
# ═══════════════════════════════════════════════════════

sync_git_repo() {
    local name="$1" url="$2" target="$3" filter="${4:-}"

    log "Syncing $name..."
    local tmp_dir="/tmp/prx-sd-sync-$$-$name"
    rm -rf "$tmp_dir"

    if git clone --depth "$GIT_DEPTH" --single-branch -q "$url" "$tmp_dir" 2>/dev/null; then
        mkdir -p "$target"
        # Copy only .yar/.yara files
        if [[ -n "$filter" ]]; then
            find "$tmp_dir/$filter" \( -name "*.yar" -o -name "*.yara" \) -exec cp {} "$target/" \; 2>/dev/null
        else
            find "$tmp_dir" \( -name "*.yar" -o -name "*.yara" \) -exec cp {} "$target/" \; 2>/dev/null
        fi
        local count
        count=$(find "$target" \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | wc -l)
        rm -rf "$tmp_dir"
        ok "$name: $count rule files"
    else
        warn "$name: git clone failed"
        rm -rf "$tmp_dir"
    fi
}

sync_yara() {
    header "Syncing YARA Rules"

    # --- Built-in rules ---
    local prx_yara="/opt/worker/task/prx-sd/signatures-db/yara"
    if [[ -d "$prx_yara" ]]; then
        log "Copying built-in PRX-SD rules..."
        cp "$prx_yara"/malware/linux_*.yar "$SCRIPT_DIR/yara/builtin/linux/" 2>/dev/null || true
        cp "$prx_yara"/malware/macos_*.yar "$SCRIPT_DIR/yara/builtin/macos/" 2>/dev/null || true
        cp "$prx_yara"/malware/trojan.yar "$prx_yara"/malware/backdoor.yar "$prx_yara"/malware/ransomware.yar "$prx_yara"/malware/worm.yar "$SCRIPT_DIR/yara/builtin/windows/" 2>/dev/null || true
        cp "$prx_yara"/malware/cross_platform.yar "$SCRIPT_DIR/yara/builtin/cross-platform/" 2>/dev/null || true
        cp "$prx_yara"/packer/*.yar "$prx_yara"/pua/*.yar "$prx_yara"/test/*.yar "$SCRIPT_DIR/yara/builtin/" 2>/dev/null || true
        local c; c=$(find "$SCRIPT_DIR/yara/builtin" \( -name "*.yar" -o -name "*.yara" \) | wc -l)
        ok "Built-in: $c rule files"
    fi

    # --- Git-based YARA sources ---
    [[ "${ICEWATER_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "Icewater" "${ICEWATER_REPO}" "$SCRIPT_DIR/yara/icewater"

    [[ "${SIGNATURE_BASE_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "signature-base" "${SIGNATURE_BASE_REPO}" "$SCRIPT_DIR/yara/signature-base" "yara"

    [[ "${YARA_RULES_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "Yara-Rules" "${YARA_RULES_REPO}" "$SCRIPT_DIR/yara/yara-rules"

    [[ "${ELASTIC_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "Elastic" "${ELASTIC_REPO}" "$SCRIPT_DIR/yara/elastic" "yara"

    [[ "${GCTI_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "Google GCTI" "${GCTI_REPO}" "$SCRIPT_DIR/yara/gcti"

    [[ "${REVERSINGLABS_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "ReversingLabs" "${REVERSINGLABS_REPO}" "$SCRIPT_DIR/yara/reversinglabs"

    [[ "${ESET_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "ESET" "${ESET_REPO}" "$SCRIPT_DIR/yara/eset"

    [[ "${INQUEST_ENABLED:-true}" == "true" ]] && \
        sync_git_repo "InQuest" "${INQUEST_REPO}" "$SCRIPT_DIR/yara/inquest"

    # --- Stats ---
    local total_files total_rules
    total_files=$(find "$SCRIPT_DIR/yara" \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | wc -l)
    total_rules=$(grep -r "^rule " "$SCRIPT_DIR/yara" --include="*.yar" --include="*.yara" 2>/dev/null | wc -l)
    stat "Total YARA: $total_files files, ~$total_rules rules"
}

# ═══════════════════════════════════════════════════════
#  ClamAV
# ═══════════════════════════════════════════════════════

sync_clamav() {
    header "Syncing ClamAV Official Database"

    if [[ "${CLAMAV_ENABLED:-true}" != "true" ]]; then
        log "ClamAV: disabled in config"
        return
    fi

    local clamav_dir="$SCRIPT_DIR/clamav"
    local mirror="${CLAMAV_MIRROR:-https://database.clamav.net}"

    for db in main.cvd daily.cvd bytecode.cvd; do
        log "Downloading $db..."
        if curl -sS --max-time 300 -o "$clamav_dir/$db.tmp" "$mirror/$db" 2>/dev/null; then
            # Verify it's a valid CVD (starts with ClamAV-)
            if head -c 7 "$clamav_dir/$db.tmp" 2>/dev/null | grep -q "ClamAV"; then
                mv "$clamav_dir/$db.tmp" "$clamav_dir/$db"
                local size
                size=$(du -h "$clamav_dir/$db" | awk '{print $1}')
                ok "$db: $size"
            else
                rm -f "$clamav_dir/$db.tmp"
                warn "$db: invalid file (not a ClamAV database)"
            fi
        else
            rm -f "$clamav_dir/$db.tmp"
            warn "$db: download failed"
        fi
    done

    if [[ -f "$clamav_dir/main.cvd" ]]; then
        local total_size
        total_size=$(du -sh "$clamav_dir" | awk '{print $1}')
        stat "ClamAV total: $total_size"
    fi
}

# ═══════════════════════════════════════════════════════
#  IOC FEEDS
# ═══════════════════════════════════════════════════════

sync_ioc() {
    header "Syncing IOC Feeds (IP/Domain/URL)"

    local ioc_dir="$SCRIPT_DIR/ioc"

    # --- IP Blocklists ---
    log "Aggregating IP blocklists..."
    > "$ioc_dir/ip-blocklist.txt.tmp"

    if [[ "${IPSUM_ENABLED:-true}" == "true" ]]; then
        log "  IPsum (30+ aggregated sources)..."
        curl -sS --max-time "$DOWNLOAD_TIMEOUT" \
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" 2>/dev/null \
            | grep -v '^#' | awk '{print $1}' >> "$ioc_dir/ip-blocklist.txt.tmp" || true
    fi

    if [[ "${FIREHOL_ENABLED:-true}" == "true" ]]; then
        log "  FireHOL level1..."
        curl -sS --max-time "$DOWNLOAD_TIMEOUT" \
            "https://iplists.firehol.org/files/firehol_level1.netset" 2>/dev/null \
            | grep -v '^#' >> "$ioc_dir/ip-blocklist.txt.tmp" || true
    fi

    if [[ "${ET_COMPROMISED_ENABLED:-true}" == "true" ]]; then
        log "  Emerging Threats compromised IPs..."
        curl -sS --max-time "$DOWNLOAD_TIMEOUT" \
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" 2>/dev/null \
            | grep -v '^#' >> "$ioc_dir/ip-blocklist.txt.tmp" || true
    fi

    # Deduplicate and sort
    sort -u "$ioc_dir/ip-blocklist.txt.tmp" | grep -v '^$' > "$ioc_dir/ip-blocklist.txt"
    rm -f "$ioc_dir/ip-blocklist.txt.tmp"
    local ip_count
    ip_count=$(wc -l < "$ioc_dir/ip-blocklist.txt")
    ok "IP blocklist: $ip_count unique IPs"

    # --- Domain Blocklists ---
    log "Aggregating domain blocklists..."
    > "$ioc_dir/domain-blocklist.txt.tmp"

    if [[ "${SANS_ENABLED:-true}" == "true" ]]; then
        log "  SANS suspicious domains..."
        curl -sS --max-time "$DOWNLOAD_TIMEOUT" \
            "https://isc.sans.edu/feeds/suspiciousdomains_High.txt" 2>/dev/null \
            | grep -v '^#\|^$\|Site' >> "$ioc_dir/domain-blocklist.txt.tmp" || true
    fi

    sort -u "$ioc_dir/domain-blocklist.txt.tmp" | grep -v '^$' > "$ioc_dir/domain-blocklist.txt"
    rm -f "$ioc_dir/domain-blocklist.txt.tmp"
    local domain_count
    domain_count=$(wc -l < "$ioc_dir/domain-blocklist.txt")
    ok "Domain blocklist: $domain_count unique domains"

    # --- URL Blocklists ---
    log "Aggregating URL blocklists..."
    > "$ioc_dir/url-blocklist.txt.tmp"

    if [[ "${URLHAUS_URLS_ENABLED:-true}" == "true" ]]; then
        log "  URLhaus malicious URLs..."
        curl -sS --max-time "$DOWNLOAD_TIMEOUT" \
            "https://urlhaus.abuse.ch/downloads/text_recent/" 2>/dev/null \
            | grep -v '^#\|^$' >> "$ioc_dir/url-blocklist.txt.tmp" || true
    fi

    sort -u "$ioc_dir/url-blocklist.txt.tmp" | grep -v '^$' > "$ioc_dir/url-blocklist.txt"
    rm -f "$ioc_dir/url-blocklist.txt.tmp"
    local url_count
    url_count=$(wc -l < "$ioc_dir/url-blocklist.txt")
    ok "URL blocklist: $url_count unique URLs"
}

# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════

header "PRX-SD Signatures Sync — $DATE_SHORT"

case "$CATEGORY" in
    all)
        sync_hashes
        sync_yara
        sync_clamav
        sync_ioc
        ;;
    hashes)  sync_hashes ;;
    yara)    sync_yara ;;
    clamav)  sync_clamav ;;
    ioc)     sync_ioc ;;
    *)       err "Unknown category: $CATEGORY"; exit 1 ;;
esac

echo ""
show_stats
echo ""
ok "Sync complete!"
