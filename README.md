# VampSecure Labs — Professional Security Audit Toolkit

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![AsyncIO](https://img.shields.io/badge/Engine-AsyncIO%20%2B%20aiohttp-orange?style=flat-square)](https://docs.aiohttp.org)
[![Rich](https://img.shields.io/badge/Output-Rich%20%2F%20HTML%20%2F%20JSON-purple?style=flat-square)](https://github.com/Textualize/rich)
[![VampSecure](https://img.shields.io/badge/by-VampSecure%20Studios-red?style=flat-square)](https://vampsecurestudios.com)
[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)]()

> **Professional-grade offensive security auditing tools** for authorized penetration testing engagements, developed by [VampSecure Studios](https://vampsecurestudios.com) under the **VampSecure Labs** research label.

---

## Tools in This Repository

| Tool | Target | Key CVEs | Output |
|------|--------|----------|--------|
| [`vamp-forticheck`](vamp-forticheck/) | Fortinet FortiOS SSL-VPN / Admin UI | CVE-2018-13379, CVE-2022-40684, CVE-2023-27997, CVE-2024-21762 | JSON · HTML · Console |
| [`vamp-wp2shell-audit`](vamp-wp2shell-audit/) | WordPress plugins / upload vectors | CVE-2020-25213, CVE-2021-24370, CVE-2023-28121, CVE-2023-32243 + 6 more | JSON · HTML · Console |

---

## Key Differentiators vs. Existing Tools

| Feature | Existing OSS tools | VampSecure Labs tools |
|---------|--------------------|-----------------------|
| Async I/O | Mostly synchronous | `asyncio + aiohttp` — scan 1000 hosts concurrently |
| Scope enforcement | Manual | Built-in `scope.txt` validation (CIDR, wildcard, hostname) |
| Exposure analysis | CVE flag only | Secondary vector enumeration after initial confirmation |
| Output formats | Plain text or basic JSON | Rich console + JSON + interactive dark-theme HTML |
| Canary upload cleanup | No cleanup | Auto-delete immediately after accessibility confirmation |
| Version detection | Banner-only | Multi-pattern: HTML, JS assets, REST API, headers |
| False-positive reduction | High | Non-destructive confirmation steps before flagging |

---

## Installation

### pip (recommended)

```bash
pip install aiohttp rich
```

### poetry

```bash
poetry add aiohttp rich
```

### Clone & run directly

```bash
git clone https://github.com/vampsecure-labs/audit-toolkit.git
cd audit-toolkit/vamp-forticheck
pip install -r requirements.txt
python vamp_forticheck.py --help
```

**Requirements:** Python 3.10+

---

## vamp-forticheck — FortiOS Vulnerability & Exposure Scanner

### CVE Coverage

| CVE | CVSS | Component | Detection Method |
|-----|------|-----------|-----------------|
| CVE-2018-13379 | 9.8 CRITICAL | SSL-VPN Web Portal | Active path traversal probe (non-destructive) |
| CVE-2022-40684 | 9.8 CRITICAL | Admin UI / REST API | `Forwarded` header bypass probe |
| CVE-2023-27997 | 9.2 CRITICAL | SSL-VPN (XORtigate) | Version fingerprint match |
| CVE-2024-21762 | 9.6 CRITICAL | SSL-VPN OOB Write | Version fingerprint match |

### Architecture & Vector Flow

```
Target Host
    │
    ├─[Phase 1]─ Banner Grab + Version Detection
    │               ├── /remote/login  (SSL-VPN portal)
    │               ├── /login         (Admin UI)
    │               └── HTTP headers + HTML content
    │
    ├─[Phase 2]─ CVE Probes (async, non-destructive)
    │               ├── CVE-2018-13379: Path traversal → binary content check
    │               ├── CVE-2022-40684: Forwarded bypass → /api/v2/cmdb/system/admin
    │               ├── INFO-DISCLOSURE: /api/v2/monitor/system/status
    │               └── Version-match: map detected version to CVE affected ranges
    │
    ├─[Phase 3]─ Exposure Analysis (only if FortiOS confirmed)
    │               ├── HSTS / X-Frame-Options header audit
    │               ├── WAF detection
    │               ├── API endpoint enumeration (post CVE-2022-40684 confirmation)
    │               └── SSL-VPN portal exposure surface
    │
    └─[Output]── Console (Rich) + JSON + HTML report
```

### Usage

```bash
# Single target
python vamp_forticheck.py -t 192.168.1.1

# Multiple targets with scope enforcement
python vamp_forticheck.py -i targets.txt -s scope.txt -c 20

# Full report output
python vamp_forticheck.py -t vpn.client.com -o results.json --html report.html

# High-concurrency scan of a /24
python vamp_forticheck.py -i ips.txt -c 50 --timeout 8 --html fortinet_audit.html
```

**Options:**

```
-t, --target HOST [HOST ...]   Target host(s) or IP(s)
-i, --input FILE               Targets file (one per line)
-s, --scope FILE               Scope file (CIDR / hostname / wildcard)
-c, --concurrency INT          Concurrent scans (default: 10)
    --timeout INT              Per-request timeout seconds (default: 10)
-o, --output FILE              JSON report
    --html FILE                HTML report
-v, --verbose                  Verbose output
```

### scope.txt format

```
# IP ranges
192.168.1.0/24
10.0.0.0/8

# Exact hosts
vpn.example.com
192.168.1.100

# Wildcard subdomains
*.example.com
```

---

## vamp-wp2shell-audit — WordPress Upload & Shell Vector Auditor

### CVE / Plugin Coverage

| Plugin | CVE | CVSS | Auth Required | Vector |
|--------|-----|------|---------------|--------|
| WP File Manager | CVE-2020-25213 | 9.8 | ❌ No | Arbitrary file upload → RCE |
| Fancy Product Designer | CVE-2021-24370 | 9.8 | ❌ No | Arbitrary file upload |
| WooCommerce Payments | CVE-2023-28121 | 9.8 | ❌ No | Auth bypass → upload |
| Essential Addons for Elementor | CVE-2023-32243 | 9.8 | ❌ No | Privilege escalation |
| Formidable Forms | CVE-2023-0303 | 8.8 | ✅ Yes | Arbitrary file upload → RCE |
| Advanced Custom Fields | CVE-2023-30777 | 7.1 | ✅ Yes | XSS → RCE chain |
| WPForms | CVE-2023-3343 | 8.8 | ✅ Yes | SQL injection |
| Ninja Forms | CVE-2023-37979 | 7.3 | ❌ No | Reflected XSS / CSRF |
| Contact Form 7 | CVE-2023-6449 | 7.5 | ❌ No | MIME type bypass upload |
| Duplicator | CVE-2022-2443 | 7.5 | ❌ No | Path traversal / file read |

### Architecture & Vector Flow

```
Target WordPress Site
    │
    ├─[Phase 1]─ WordPress Detection
    │               ├── /wp-content/, /wp-includes/ indicator check
    │               ├── Generator meta tag version extraction
    │               └── Asset query string (?ver=X.X.X) parsing
    │
    ├─[Phase 2]─ Attack Surface Mapping
    │               ├── XML-RPC enabled check
    │               ├── REST API user enumeration (/wp-json/wp/v2/users)
    │               ├── Upload directory listing check
    │               ├── WP_DEBUG output detection
    │               └── Error-based SQLi probe (safe params)
    │
    ├─[Phase 3]─ Plugin & Theme Fingerprinting
    │               ├── readme.txt / style.css version extraction
    │               └── Async concurrent enumeration of all known slugs
    │
    ├─[Phase 4]─ Vulnerability Mapping
    │               ├── Version comparison against affected ranges
    │               ├── Upload endpoint accessibility probe
    │               └── MIME bypass technique documentation
    │
    ├─[Phase 5]─ Canary Upload (--canary only, authorized use)
    │               ├── Inert PHP file: echo deterministic string + die()
    │               ├── MIME spoof: uploaded as image/jpeg
    │               ├── Accessibility check: confirm execution
    │               └── Auto-delete: immediate cleanup regardless of outcome
    │
    └─[Output]── Console (Rich) + JSON + HTML report
```

### Usage

```bash
# Single target
python vamp_wp2shell_audit.py -t https://example.com

# Batch scan with scope
python vamp_wp2shell_audit.py -i targets.txt -s scope.txt -c 10

# Full report
python vamp_wp2shell_audit.py -t https://client.com -o wp_audit.json --html wp_report.html

# With canary upload (REQUIRES written authorization)
python vamp_wp2shell_audit.py -t https://client.com --canary --html full_report.html
```

**Options:**

```
-t, --target URL [URL ...]   Target WordPress URL(s)
-i, --input FILE             Targets file (one per line)
-s, --scope FILE             Scope file (CIDR / hostname / wildcard)
-c, --concurrency INT        Concurrent scans (default: 5)
    --timeout INT            Per-request timeout seconds (default: 10)
    --canary                 Enable dry-run canary upload test (authorized use only)
    --force                  Audit even if WordPress is not detected
-o, --output FILE            JSON report
    --html FILE              HTML report
-v, --verbose                Verbose output
```

### Canary Upload — How It Works

The `--canary` flag enables a **safe, inert file upload test** for confirmed vulnerable endpoints:

1. A PHP file is generated with a unique per-target filename: `vamp_canary_[hash].php`
2. Content is: `<?php $t='VAMPSECURE_CANARY_' . md5(__FILE__ . $_SERVER['HTTP_HOST']); header('Content-Type: text/plain'); echo $t; die(); ?>`
3. It is uploaded via the confirmed vulnerable plugin endpoint with MIME type spoofed as `image/jpeg`
4. The tool checks if the file is accessible and if PHP was executed
5. **The file is immediately deleted** via REST API or direct DELETE request
6. Result is logged: `accessible=true|false`, `deleted=true|false`, `evidence`

> ⚠ If cleanup fails (network drop, server error), the filename is included in the report so you can manually remove it during the engagement cleanup phase.

---

## Risk Scoring Model

Both tools calculate a composite risk score (0–10):

| Score | Level | Meaning |
|-------|-------|---------|
| 9.0–10.0 | 🔴 CRITICAL | Confirmed exploitable CVE(s) or canary execution |
| 7.0–8.9  | 🟠 HIGH | Version-matched critical CVE or high-CVSS plugin |
| 4.0–6.9  | 🟡 MEDIUM | Moderate CVEs, attack surface issues |
| 0.1–3.9  | 🔵 LOW | Informational findings, misconfigurations |
| 0.0      | ⚪ INFO | Target detected but no actionable findings |

---

## Mitigation Matrix for Client Reports

### FortiOS Findings

| CVE | Immediate Action | Verification |
|-----|-----------------|--------------|
| CVE-2018-13379 | Upgrade to FortiOS 6.0.5+ or 5.6.8+ | `GET /remote/fgt_lang?lang=en/../../../etc/passwd` returns 404 |
| CVE-2022-40684 | Upgrade to 7.0.7+ / 7.2.2+; disable HTTP/HTTPS admin | `Forwarded` bypass returns 401 |
| CVE-2023-27997 | Upgrade to 7.2.5+ / 7.0.10+; disable SSL-VPN | Confirm updated build number |
| CVE-2024-21762 | Upgrade to 7.2.7+ / 7.4.3+; disable SSL-VPN as interim | Run vendor detection script |

### WordPress Upload Findings

| Finding | Immediate Action | Verification |
|---------|-----------------|--------------|
| Vulnerable plugin | Update or remove plugin immediately | Rerun scan — version should not match |
| XML-RPC enabled | Disable if not needed (`xmlrpc.php` → `deny all` in nginx) | HTTP 405/403 on `xmlrpc.php` |
| REST API user enum | Restrict `/wp-json/wp/v2/users` in nginx or with plugin | Returns 401 or empty array |
| Upload dir listing | Add `Options -Indexes` or `autoindex off` | `403 Forbidden` on `/wp-content/uploads/` |
| WP_DEBUG visible | Set `WP_DEBUG = false` in `wp-config.php` | No PHP notices/warnings in HTML |

---

## Output Examples

### Console (Rich terminal)
![Rich terminal output with colored table and finding panels]

### HTML Report
Dark-theme interactive report with risk badges, stat cards, and per-target CVE detail.

### JSON Structure

```json
{
  "tool": "vamp-forticheck",
  "version": "1.0",
  "generated": "2026-07-31T12:00:00Z",
  "summary": {
    "total_targets": 10,
    "fortios_confirmed": 3,
    "confirmed_cves": 2,
    "critical_targets": 1
  },
  "results": [
    {
      "target": "vpn.example.com",
      "is_fortios": true,
      "detected_version": "7.0.5",
      "risk_level": "CRITICAL",
      "risk_score": 9.8,
      "cve_findings": [...],
      "exposure_vectors": [...]
    }
  ]
}
```

---

## Legal Disclaimer

> **These tools are provided exclusively for authorized security testing, penetration testing engagements, vulnerability assessments, and educational research.**
>
> You must obtain **explicit written authorization** from the system owner before running any scan against a target. Unauthorized use of these tools against systems you do not own or have no permission to test is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), GDPR, and equivalent laws in most jurisdictions.
>
> VampSecure Studios and the contributors to this repository **accept no liability** for any damage, legal consequences, or misuse arising from unauthorized use of these tools.
>
> By using these tools, you confirm that you have the necessary authorization and that your use is lawful.

---

## About VampSecure Labs

**VampSecure Labs** is the public security research division of [VampSecure Studios](https://vampsecurestudios.com), focused on developing high-quality, open-source defensive security tooling for the professional pentesting community.

We build tools that prioritize:
- **Precision** over noise — confirm before flagging
- **Safety** — non-destructive probes, auto-cleanup, scope enforcement
- **Professionalism** — report-ready output for client deliverables

---

*VampSecure Labs by VampSecure Studios · Professional Security Research*
