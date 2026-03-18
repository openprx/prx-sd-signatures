# PRX-SD Signatures

Open-source threat intelligence database for [PRX-SD](https://github.com/openprx/prx-sd) antivirus engine.

This repository aggregates malware signatures, YARA detection rules, and IOC blocklists from multiple free and open-source threat intelligence feeds. It is updated automatically every 6 hours via GitHub Actions.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/openprx/prx-sd-signatures.git

# Sync all sources (downloads latest signatures)
cd prx-sd-signatures
./sync.sh

# Use with PRX-SD engine
sd import prx-sd-signatures/hashes/sha256/malwarebazaar.txt
sd scan /path/to/file
```

## Directory Structure

```
prx-sd-signatures/
├── hashes/              # Hash-based signatures
│   ├── sha256/          #   SHA-256 blocklists (one per source)
│   └── md5/             #   MD5 blocklists (VirusShare, --full mode)
│
├── yara/                # YARA detection rules (38,800+ rules)
│   ├── builtin/         #   PRX-SD curated rules (MIT licensed)
│   ├── signature-base/  #   Neo23x0 APT/crime rules
│   ├── yara-rules/      #   Community rules
│   ├── reversinglabs/   #   Commercial-grade open-source rules
│   ├── elastic/         #   Endpoint protection rules
│   ├── icewater/        #   Archived large rule set
│   ├── gcti/            #   Google threat intelligence
│   ├── eset/            #   APT tracking rules
│   └── inquest/         #   Document malware rules
│
├── ioc/                 # Indicators of Compromise
│   ├── ip-blocklist.txt    # 585K+ malicious IPs (FireHOL + IPsum)
│   ├── domain-blocklist.txt # Malicious domains (SANS + abuse.ch)
│   └── url-blocklist.txt   # Malicious URLs (URLhaus + ET)
│
├── clamav/              # ClamAV signature databases (.cvd)
├── feeds/               # Raw threat intelligence feeds
├── sync.sh              # Main synchronization script
└── sync.conf            # Source configuration
```

## Sources

### Hash Signatures

| Source | Type | Update Frequency | License |
|--------|------|-----------------|---------|
| abuse.ch MalwareBazaar | SHA-256 | Every 5 min | Free |
| abuse.ch URLhaus | SHA-256 | Hourly | Free |
| abuse.ch Feodo Tracker | SHA-256 | Every 5 min | Free |
| abuse.ch ThreatFox | SHA-256 | Continuous | Free |
| abuse.ch SSL Blacklist | SHA-1 | Every 5 min | Free |
| VirusShare | MD5 | Periodic | Free |

### YARA Rules

| Source | Rules | License | Status |
|--------|-------|---------|--------|
| PRX-SD Built-in | 64 | MIT | Active |
| Icewater | 16,432 | Free | Archived |
| Neo23x0/signature-base | ~500 | CC-BY-NC | Active |
| Yara-Rules/rules | ~300 | GPL-2.0 | Active |
| Elastic protections | ~200 | Elastic License | Active |
| ReversingLabs | ~100 | MIT | Active |
| Google GCTI | ~100 | Apache-2.0 | Archived |
| ESET IOC | ~50 | BSD | Active |
| InQuest | ~20 | GPL | Active |

### IOC Feeds

| Source | Type | Content | License |
|--------|------|---------|---------|
| IPsum (aggregated) | IP | 585K+ IPs | Free |
| FireHOL level1 | IP | Aggregated from 400+ feeds | Free |
| Emerging Threats | IP | IDS rule-based | Free |
| SANS ISC | Domain | Daily suspicious domains | Free |
| URLhaus | URL | Malicious URL payloads | Free |

### ClamAV

| Source | Signatures | License |
|--------|-----------|---------|
| ClamAV Official DB | 11M+ | GPL-2.0 |

## Hash File Format

All hash blocklists use a unified text format:

```
# Source: abuse.ch MalwareBazaar
# Updated: 2026-03-17T15:12:07Z
# Count: 550
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test.File
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

Format: `<hex_hash> <malware_name>` (one per line). Lines starting with `#` are comments.

## Sync Commands

```bash
# Sync all sources
./sync.sh

# Sync specific category
./sync.sh --category hashes
./sync.sh --category yara
./sync.sh --category clamav
./sync.sh --category ioc

# Show statistics
./sync.sh --stats
```

## Configuration

Edit `sync.conf` to enable/disable individual sources:

```bash
# Example: disable VirusShare (very large)
VIRUSSHARE_ENABLED=false

# Example: enable ClamAV sync
CLAMAV_ENABLED=true
```

## Automated Updates

GitHub Actions runs `sync.sh` every 6 hours to keep signatures up to date.

Manual trigger: **Actions** tab > **Sync Signatures** > **Run workflow**.

## Using with PRX-SD

### Import hash signatures

```bash
sd import prx-sd-signatures/hashes/sha256/malwarebazaar.txt
sd import prx-sd-signatures/hashes/sha256/builtin.txt
```

### Import ClamAV databases

```bash
sd import-clamav prx-sd-signatures/clamav/main.cvd prx-sd-signatures/clamav/daily.cvd
```

### Use as data directory

```bash
sd --data-dir ./prx-sd-signatures scan /path/to/file
```

### Update via sd CLI

```bash
sd update
```

## Contributing Signatures

### YARA Rules

1. Place new rules in `yara/builtin/` (for PRX-SD curated rules)
2. Follow standard YARA rule format
3. Include metadata: `author`, `description`, `date`, `reference`
4. Test with `yara` or `yr` CLI before submitting

### Hash Blocklists

1. Use the unified format: `<hex_hash> <malware_name>`
2. Place in the appropriate `hashes/sha256/` or `hashes/md5/` directory
3. Include source and date comments at the top

## License

Each source retains its original license. See individual directories for details.

PRX-SD built-in rules (`yara/builtin/`) are licensed under MIT.

## Links

- [PRX-SD Engine](https://github.com/openprx/prx-sd) — The antivirus engine
- [OpenPRX](https://openprx.dev) — Project homepage
