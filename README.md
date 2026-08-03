<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
</p>

<h1 align="center">vamp-forticheck</h1>
<p align="center"><em>Multi-Vendor Edge Device CVE Scanner — VampSecure Labs</em></p>

---

## Overview

**vamp-forticheck** is an asynchronous, non-destructive security scanner that detects CVE vulnerabilities across seven major network security vendors. It performs a structured three-phase analysis:

1. **Passive detection** — identifies vendor and firmware version fingerprints from HTTP response headers, banners, and login page artifacts without triggering authentication.
2. **Semi-active CVE probes** — targeted HTTP requests that confirm specific vulnerability conditions including version disclosure, path traversal, and pre-auth RCE indicators.
3. **Secondary exposure analysis** — checks for administrative interfaces, management APIs, and credential-exposure endpoints exposed on the same host.

Coverage spans **16 CVEs across 7 vendors**: FortiOS/FortiGate, Palo Alto PAN-OS, Cisco ASA, Cisco IOS-XE, Check Point Gateway, Juniper Junos, and F5 BIG-IP.

---

## Features

- Fully asynchronous scanning via `asyncio` + `aiohttp` with configurable concurrency
- Seven-vendor CVE database including actively exploited critical vulnerabilities
- Scope enforcement via allowlist file — prevents unintended out-of-scope probing
- Risk scoring: `CVSS × confidence_factor` (1.0 for confirmed findings, 0.55 for version-match only)
- Bulk target input from file or direct command-line arguments
- Standalone HTML report for client delivery or archival
- Client-grade HTML + PDF reporting via the shared `vampsec_report` module

---

## Requirements

```
Python 3.11+
aiohttp >= 3.9.0
rich >= 13.7.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/belky-me/vamp-forticheck.git
cd vamp-forticheck
pip install -r requirements.txt
```

---

## Usage

```
python vamp_forticheck.py [OPTIONS]

Target selection:
  -t, --target HOST [HOST ...]   One or more targets (IP, hostname, or HOST:PORT)
  -i, --input FILE               File with one target per line

Scope:
  -s, --scope FILE               Allowlist file (CIDR blocks, wildcards, or exact hosts)

Performance:
  -c, --concurrency N            Maximum concurrent connections (default: 10)
      --timeout N                Per-request timeout in seconds (default: 10)

Output:
  -o, --output FILE              Write all findings to a JSON file
      --html FILE                Generate a standalone HTML report
  -v, --verbose                  Show detailed probe traces and HTTP responses
```

---

## Examples

Scan a single edge device and write a JSON report:

```bash
python vamp_forticheck.py -t 203.0.113.1 -o results.json
```

Scan a target list within a defined scope, with HTML output and verbose logging:

```bash
python vamp_forticheck.py -i targets.txt -s scope.txt --html report.html -v
```

Scan multiple hosts with increased concurrency:

```bash
python vamp_forticheck.py -t 10.0.0.1 10.0.0.2 10.0.0.254 -c 20 -o findings.json
```

Scan a management interface on a non-standard port:

```bash
python vamp_forticheck.py -t firewall.corp.example:8443 --html firewall_report.html
```

---

## Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich table with vendor, CVE IDs, CVSS score, and risk level per host |
| JSON | `-o FILE` | Machine-readable findings with full metadata and probe details |
| HTML | `--html FILE` | Standalone dark-theme report for browser viewing or archival |
| Client report | Configured via `vampsec_report` | Executive HTML + PDF for client delivery |

---

## Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No findings — all targets clean | Pass gate |
| `1` | Medium / Low findings present | Review recommended |
| `2` | High / Critical findings confirmed | Fail gate — escalate immediately |

---

## Risk Levels

| Level | Computed score |
|-------|---------------|
| CRITICAL | ≥ 9.0 |
| HIGH | ≥ 7.0 |
| MEDIUM | ≥ 4.0 |
| LOW | > 0.0 |
| INFO | 0.0 |

Score = `CVSS_base × confidence_factor`. Confidence is 1.0 when a probe confirms the vulnerability condition, and 0.55 when the finding is based on version disclosure alone.

---

## Part of VampSecure Labs Toolkit

`vamp-forticheck` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>
