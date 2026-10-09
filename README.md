<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.1.1-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/async-aiohttp-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-forticheck/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-forticheck</h1>
<p align="center"><em>Multi-Vendor Edge Device CVE Scanner — VampSecure Labs</em></p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

**vamp-forticheck** is an asynchronous, non-destructive security scanner that detects CVE vulnerabilities across seven major network security vendors. It performs a structured three-phase analysis:

1. **Passive detection** — identifies vendor and firmware version fingerprints from HTTP response headers, banners, and login page artifacts without triggering authentication.
2. **Semi-active CVE probes** — targeted HTTP requests that confirm specific vulnerability conditions including version disclosure, path traversal, and pre-auth RCE indicators.
3. **Secondary exposure analysis** — checks for administrative interfaces, management APIs, and credential-exposure endpoints exposed on the same host.

Coverage spans **16 CVEs across 7 vendors**: FortiOS/FortiGate, Palo Alto PAN-OS, Cisco ASA, Cisco IOS-XE, Check Point Gateway, Juniper Junos, and F5 BIG-IP.

---

### Features

- Fully asynchronous scanning via `asyncio` + `aiohttp` with configurable concurrency
- Seven-vendor CVE database including actively exploited critical vulnerabilities
- Scope enforcement via allowlist file — prevents unintended out-of-scope probing
- Risk scoring: `CVSS × confidence_factor` (1.0 for confirmed findings, 0.55 for version-match only)
- Bulk target input from file or direct command-line arguments
- Standalone HTML report for client delivery or archival
- Client-grade HTML + PDF reporting via the shared `vampsec_report` module

---

### Requirements

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

### Installation

```bash
pip install vamp-forticheck
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-forticheck
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-forticheck.git
cd vamp-forticheck
pip install -r requirements.txt
```

---

### Usage

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

### Examples

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

### Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich table with vendor, CVE IDs, CVSS score, and risk level per host |
| JSON | `-o FILE` | Machine-readable findings with full metadata and probe details |
| HTML | `--html FILE` | Standalone dark-theme report for browser viewing or archival |
| Client report | Configured via `vampsec_report` | Executive HTML + PDF for client delivery |

---

### Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No findings — all targets clean | Pass gate |
| `1` | Medium / Low findings present | Review recommended |
| `2` | High / Critical findings confirmed | Fail gate — escalate immediately |

---

### Risk Levels

| Level | Computed score |
|-------|---------------|
| CRITICAL | ≥ 9.0 |
| HIGH | ≥ 7.0 |
| MEDIUM | ≥ 4.0 |
| LOW | > 0.0 |
| INFO | 0.0 |

Score = `CVSS_base × confidence_factor`. Confidence is 1.0 when a probe confirms the vulnerability condition, and 0.55 when the finding is based on version disclosure alone.

---

### Sample Output

```
$ python vamp_forticheck.py -i targets.txt -s scope.txt --html report.html -v

 vamp-forticheck v1.1.1 — VampSecure Labs
 Targets: 6  |  Scope file: scope.txt  |  Concurrency: 10

 [Phase 1] Passive detection
  192.168.1.1    FortiOS 7.0.x   (HTTP header + login page artifact)
  192.168.1.254  PAN-OS 10.1.x   (X-FRAME-OPTIONS + GP portal fingerprint)
  10.0.0.1       Cisco IOS-XE    (HTTP/1.1 401 + Server: cisco-IOS)
  10.0.0.254     Cisco ASA       (SSL VPN portal fingerprint)
  10.10.0.1      F5 BIG-IP       (BigIP cookie + TMUI artifact)
  10.10.0.2      Unknown         (no vendor fingerprint matched)

 [Phase 2] CVE probes
  192.168.1.1    CVE-2024-21762  confirmed     (pre-auth RCE — path traversal response)
  192.168.1.1    CVE-2023-27997  confirmed     (heap overflow — SSL-VPN probe positive)
  192.168.1.254  CVE-2024-3400   version-match (PAN-OS 10.1 < 10.1.13-h3)
  10.0.0.1       CVE-2023-20198  confirmed     (HTTP server process — privilege escalation)
  10.10.0.1      CVE-2023-46747  confirmed     (TMUI unauthenticated RCE — 401 bypass)

 [Phase 3] Secondary exposure
  192.168.1.1    Admin interface exposed on port 8443 (HTTPS)
  10.0.0.254     REST API management endpoint /api/cli reachable
  10.10.0.1      iControl REST accessible without authentication

 ─────────────────────────────────────────────────────────────────────────────────
 Host             Vendor      CVEs   Risk score    Level
 192.168.1.1      FortiOS     2      9.6           CRITICAL
 192.168.1.254    PAN-OS      1      6.0 (v-match) HIGH
 10.0.0.1         IOS-XE      1      9.6           CRITICAL
 10.0.0.254       Cisco ASA   0      0.0           INFO
 10.10.0.1        F5 BIG-IP   1      9.6           CRITICAL
 10.10.0.2        Unknown     0      0.0           INFO
 ─────────────────────────────────────────────────────────────────────────────────
 Summary: 3 CRITICAL · 1 HIGH · 0 MEDIUM · 2 INFO
 HTML report: report.html  |  Exit code: 2
```

### Why vamp-forticheck vs. Shodan CVE lookup · Tenable Nessus · Rapid7 Nexpose

| Capability | vamp-forticheck | Shodan CVE lookup | Tenable Nessus | Rapid7 Nexpose |
|---|---|---|---|---|
| Self-hosted — no cloud dependency | ✅ | ❌ cloud API | ❌ cloud/server | ❌ cloud/server |
| Seven-vendor CVE coverage in one tool | ✅ | ⚠️ data only | ✅ | ✅ |
| Scope enforcement via allowlist file | ✅ | ❌ | ✅ | ✅ |
| Confidence-adjusted risk score (CVSS × factor) | ✅ | ❌ raw CVSS only | ✅ | ✅ |
| Non-destructive — no authentication required | ✅ | ✅ passive | ❌ credentialed | ❌ credentialed |
| VSL engagement HTML + PDF report | ✅ | ❌ | ⚠️ proprietary | ⚠️ proprietary |
| CI/CD machine-readable exit codes | ✅ | ❌ | ❌ | ❌ |
| Free, no per-scan licence fee | ✅ | ⚠️ API plan | ❌ paid | ❌ paid |

- **Vendor-specific CVE intelligence**: generic vuln scanners apply the same probe logic to all hosts. `vamp-forticheck` uses vendor-specific HTTP artifacts, header patterns, and path-traversal conditions that produce confirmed findings rather than version-match guesses.
- **Scope enforcement as a first-class feature**: the allowlist file (`-s scope.txt`) prevents accidental out-of-scope probing during a client engagement — a safeguard absent from ad-hoc Shodan lookups.
- **Confidence-adjusted scoring**: a confirmed pre-auth RCE probe scores `CVSS × 1.0`; a version-only match scores `× 0.55`, preserving the distinction between what is proven and what is inferred.
- **Zero cloud footprint**: no target IPs, banners, or findings leave the audit machine — critical when scanning client infrastructure under NDA.

### Check Coverage

| Check ID | Description | Standard | Severity |
|---|---|---|---|
| FTC-001 | CVE-2024-21762 — FortiOS SSL-VPN pre-auth remote code execution | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-002 | CVE-2023-27997 — FortiOS SSL-VPN heap overflow | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-003 | CVE-2024-3400 — PAN-OS GlobalProtect OS command injection | NIST NVD, CVSS 10.0 | CRITICAL |
| FTC-004 | CVE-2023-20198 — Cisco IOS-XE Web UI privilege escalation | NIST NVD, CVSS 10.0 | CRITICAL |
| FTC-005 | CVE-2016-6366 — Cisco ASA SNMP buffer overflow | NIST NVD, CVSS 8.1 | HIGH |
| FTC-006 | CVE-2023-46747 — F5 BIG-IP TMUI unauthenticated RCE (iControl bypass) | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-007 | CVE-2023-46748 — F5 BIG-IP authenticated SQL injection | NIST NVD, CVSS 8.8 | HIGH |
| FTC-008 | CVE-2023-36845 — Juniper Junos pre-auth PHP environment variable injection | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-009 | CVE-2024-21591 — Juniper Junos J-Web unauthenticated RCE | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-010 | Admin/management interface reachable without authentication (secondary exposure) | CIS Critical Controls 7.1 | HIGH |
| FTC-011 | REST/iControl API endpoint exposed without authentication | CIS Critical Controls 7.1 | HIGH |
| FTC-012 | Vendor firmware version disclosed in HTTP response — enables targeted exploitation | CIS Critical Controls 7.7, CVSS 3.1 | MEDIUM |

### Part of VampSecure Labs Toolkit

`vamp-forticheck` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/Vampsecure-Labs/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/Vampsecure-Labs/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

### Version History

| Version | Main changes |
|---------|-------------|
| v1.1.1 | Bilingual README (EN/ES) |
| v1.1.0 | Initial public release — 7 vendors, 16 CVEs, 3-phase async scanner, confidence-adjusted scoring |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---

<a name="español"></a>
## 🇪🇸 Español

**vamp-forticheck** es un escáner de seguridad asíncrono y no destructivo que detecta vulnerabilidades CVE en siete grandes fabricantes de seguridad de red. Realiza un análisis estructurado en tres fases:

1. **Detección pasiva** — identifica huellas de fabricante y versión de firmware en cabeceras HTTP, banners y artefactos de la página de login sin disparar autenticación.
2. **Sondas CVE semi-activas** — peticiones HTTP dirigidas que confirman condiciones de vulnerabilidad específicas: divulgación de versión, path traversal e indicadores de RCE pre-auth.
3. **Análisis de exposición secundaria** — comprueba interfaces administrativas, APIs de gestión y endpoints de exposición de credenciales en el mismo host.

Cobertura de **16 CVEs en 7 fabricantes**: FortiOS/FortiGate, Palo Alto PAN-OS, Cisco ASA, Cisco IOS-XE, Check Point Gateway, Juniper Junos y F5 BIG-IP.

---

### Características

- Escaneo completamente asíncrono via `asyncio` + `aiohttp` con concurrencia configurable
- Base de datos CVE de siete fabricantes con vulnerabilidades críticas activamente explotadas
- Aplicación de scope via fichero de lista blanca — evita sondeo no intencionado fuera de scope
- Puntuación de riesgo: `CVSS × confidence_factor` (1.0 para hallazgos confirmados, 0.55 solo por coincidencia de versión)
- Entrada masiva de objetivos desde fichero o argumentos de línea de comandos
- Informe HTML autónomo para entrega al cliente o archivo
- Informes HTML + PDF de grado cliente via el módulo compartido `vampsec_report`

---

### Requisitos

```
Python 3.11+
aiohttp >= 3.9.0
rich >= 13.7.0
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

---

### Instalación

```bash
pip install vamp-forticheck
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-forticheck
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-forticheck.git
cd vamp-forticheck
pip install -r requirements.txt
```

---

### Uso

```
python vamp_forticheck.py [OPCIONES]

Selección de objetivo:
  -t, --target HOST [HOST ...]   Uno o más objetivos (IP, hostname o HOST:PUERTO)
  -i, --input FICHERO            Fichero con un objetivo por línea

Scope:
  -s, --scope FICHERO            Fichero de lista blanca (bloques CIDR, wildcards o hosts exactos)

Rendimiento:
  -c, --concurrency N            Máximo de conexiones concurrentes (por defecto: 10)
      --timeout N                Timeout por petición en segundos (por defecto: 10)

Salida:
  -o, --output FICHERO           Escribir todos los hallazgos en un fichero JSON
      --html FICHERO             Generar un informe HTML autónomo
  -v, --verbose                  Mostrar trazas detalladas de sondas y respuestas HTTP
```

---

### Ejemplos

Escanear un único dispositivo de borde y escribir un informe JSON:

```bash
python vamp_forticheck.py -t 203.0.113.1 -o results.json
```

Escanear una lista de objetivos dentro de un scope definido, con salida HTML y logging detallado:

```bash
python vamp_forticheck.py -i targets.txt -s scope.txt --html report.html -v
```

Escanear múltiples hosts con mayor concurrencia:

```bash
python vamp_forticheck.py -t 10.0.0.1 10.0.0.2 10.0.0.254 -c 20 -o findings.json
```

Escanear una interfaz de gestión en un puerto no estándar:

```bash
python vamp_forticheck.py -t firewall.corp.example:8443 --html firewall_report.html
```

---

### Formatos de salida

| Formato | Cómo activar | Descripción |
|---------|--------------|-------------|
| Consola | Por defecto | Tabla Rich con fabricante, IDs CVE, puntuación CVSS y nivel de riesgo por host |
| JSON | `-o FICHERO` | Hallazgos legibles por máquina con metadatos completos y detalles de sondas |
| HTML | `--html FICHERO` | Informe dark-theme autónomo para visualización en navegador o archivo |
| Informe de cliente | Configurado via `vampsec_report` | HTML + PDF ejecutivo para entrega al cliente |

---

### Exit codes

| Código | Significado | Uso CI/CD |
|--------|-------------|-----------|
| `0` | Sin hallazgos — todos los objetivos limpios | Puerta de paso |
| `1` | Hallazgos Medium / Low presentes | Revisión recomendada |
| `2` | Hallazgos High / Critical confirmados | Bloquear pipeline — escalar inmediatamente |

---

### Niveles de riesgo

| Nivel | Puntuación calculada |
|-------|---------------------|
| CRITICAL | ≥ 9.0 |
| HIGH | ≥ 7.0 |
| MEDIUM | ≥ 4.0 |
| LOW | > 0.0 |
| INFO | 0.0 |

Puntuación = `CVSS_base × confidence_factor`. La confianza es 1.0 cuando una sonda confirma la condición de vulnerabilidad, y 0.55 cuando el hallazgo se basa únicamente en la divulgación de versión.

---

### Por qué vamp-forticheck frente a Shodan CVE lookup · Tenable Nessus · Rapid7 Nexpose

| Capacidad | vamp-forticheck | Shodan CVE lookup | Tenable Nessus | Rapid7 Nexpose |
|---|---|---|---|---|
| Self-hosted — sin dependencia de cloud | ✅ | ❌ API cloud | ❌ cloud/servidor | ❌ cloud/servidor |
| Cobertura CVE de siete fabricantes en una sola herramienta | ✅ | ⚠️ solo datos | ✅ | ✅ |
| Aplicación de scope via fichero de lista blanca | ✅ | ❌ | ✅ | ✅ |
| Puntuación de riesgo ajustada por confianza (CVSS × factor) | ✅ | ❌ solo CVSS bruto | ✅ | ✅ |
| No destructivo — sin autenticación requerida | ✅ | ✅ pasivo | ❌ con credenciales | ❌ con credenciales |
| Informe HTML + PDF de engagement VSL | ✅ | ❌ | ⚠️ propietario | ⚠️ propietario |
| Exit codes legibles por CI/CD | ✅ | ❌ | ❌ | ❌ |
| Gratuito, sin tarifa por escaneo | ✅ | ⚠️ plan API | ❌ de pago | ❌ de pago |

- **Inteligencia CVE específica por fabricante**: los escáneres de vulnerabilidades genéricos aplican la misma lógica de sondas a todos los hosts. `vamp-forticheck` usa artefactos HTTP específicos del fabricante, patrones de cabeceras y condiciones de path-traversal que producen hallazgos confirmados en lugar de suposiciones por coincidencia de versión.
- **Aplicación de scope como característica de primer orden**: el fichero de lista blanca (`-s scope.txt`) evita el sondeo accidental fuera de scope durante un engagement con el cliente — una salvaguarda ausente en las búsquedas ad-hoc de Shodan.
- **Puntuación ajustada por confianza**: una sonda pre-auth RCE confirmada puntúa `CVSS × 1.0`; una coincidencia de solo versión puntúa `× 0.55`, preservando la distinción entre lo probado y lo inferido.
- **Huella cero en la nube**: ninguna IP de objetivo, banner ni hallazgo abandona la máquina de auditoría — crítico al escanear infraestructura de cliente bajo NDA.

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|---|---|---|---|
| FTC-001 | CVE-2024-21762 — FortiOS SSL-VPN ejecución remota de código pre-auth | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-002 | CVE-2023-27997 — FortiOS SSL-VPN desbordamiento de heap | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-003 | CVE-2024-3400 — PAN-OS GlobalProtect inyección de comando OS | NIST NVD, CVSS 10.0 | CRITICAL |
| FTC-004 | CVE-2023-20198 — Cisco IOS-XE Web UI escalada de privilegios | NIST NVD, CVSS 10.0 | CRITICAL |
| FTC-005 | CVE-2016-6366 — Cisco ASA desbordamiento de buffer SNMP | NIST NVD, CVSS 8.1 | HIGH |
| FTC-006 | CVE-2023-46747 — F5 BIG-IP TMUI RCE sin autenticación (bypass iControl) | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-007 | CVE-2023-46748 — F5 BIG-IP inyección SQL autenticada | NIST NVD, CVSS 8.8 | HIGH |
| FTC-008 | CVE-2023-36845 — Juniper Junos inyección de variable de entorno PHP pre-auth | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-009 | CVE-2024-21591 — Juniper Junos J-Web RCE sin autenticación | NIST NVD, CVSS 9.8 | CRITICAL |
| FTC-010 | Interfaz admin/gestión accesible sin autenticación (exposición secundaria) | CIS Critical Controls 7.1 | HIGH |
| FTC-011 | Endpoint REST/iControl expuesto sin autenticación | CIS Critical Controls 7.1 | HIGH |
| FTC-012 | Versión de firmware del fabricante divulgada en respuesta HTTP — permite explotación dirigida | CIS Critical Controls 7.7, CVSS 3.1 | MEDIUM |

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.1.1 | README bilingüe (EN/ES) |
| v1.1.0 | Lanzamiento público inicial — 7 fabricantes, 16 CVEs, escáner async de 3 fases, puntuación ajustada por confianza |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  Uso exclusivo en evaluaciones de seguridad autorizadas. El uso no autorizado está prohibido.
</p>
