<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

<p align="center">
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research_Division-8b0000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Herramientas-30%2B-teal?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<h1 align="center">VampSecure Labs — Security Audit Toolkit</h1>

<p align="center">
  <em>Suite profesional de herramientas de auditoría de seguridad ofensiva y defensiva</em><br/>
  <strong>© VampSecure Studios — VampSecure Labs Security Research Division</strong>
</p>

---

## Descripción

**VampSecure Labs** es la división de investigación en seguridad de [VampSecure Studios](https://vampsecurestudios.com). Este repositorio agrupa más de 30 herramientas CLI de auditoría de seguridad para pruebas de penetración autorizadas, evaluaciones de vulnerabilidades y ejercicios de equipo rojo/azul.

Todas las herramientas comparten los mismos principios de diseño:

- **Asíncrono por defecto** — `asyncio + aiohttp` para escaneos de alta concurrencia
- **No destructivo** — sondeos de confirmación antes de clasificar como vulnerable
- **Salida profesional** — consola enriquecida (Rich), JSON estructurado e informes HTML dark-theme
- **Integrable en CI/CD** — códigos de salida normalizados
- **Scope enforcement** — validación de IPs/dominios autorizados antes de cualquier prueba

> **USO EXCLUSIVO EN ENTORNOS CON AUTORIZACIÓN EXPRESA.**
> El uso de estas herramientas contra sistemas sin autorización escrita es ilegal.

---

## Instalación

Cada herramienta se instala de forma independiente:

```bash
pip install vamp-<herramienta>
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-<herramienta>
```

Ejemplo:

```bash
pip install vamp-cve-oracle
pip install vamp-orchestrator
pip install vamp-passive-recon
```

Para instalar todas las herramientas publicadas:

```bash
pip install vamp-arp-sentinel vamp-passive-recon vamp-http-audit vamp-jwt-audit \
    vamp-ssl-audit vamp-wp2shell-audit vamp-subdomain-takeover vamp-cloud-enum \
    vamp-docker-audit vamp-k8s-audit vamp-cve-oracle vamp-log-analyzer \
    vamp-log-hunter vamp-secrets-scanner vamp-mail-audit vamp-forticheck \
    vamp-llm-probe vamp-entropy-watch vamp-orchestrator vamp-penreport \
    vamp-mcp-audit vamp-gcp-audit vamp-graphql-audit vamp-easm \
    vamp-shodan-hunt vamp-darkweb-intel vamp-forensic-query vamp-azure-audit \
    vamp-oauth-audit
```

---

## Catálogo de herramientas

### Reconocimiento y OSINT

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-passive-recon`](vamp-passive-recon/) | 1.2.0 | Reconocimiento pasivo OSINT: 8 fuentes concurrentes + correlación CVE via cve.circl.lu |
| [`vamp-easm`](vamp-easm/) | 1.3 | Gestión continua de superficie de ataque externa (EASM) con histórico diff en 3 capas |
| [`vamp-shodan-hunt`](vamp-shodan-hunt/) | 1.1 | OSINT especializado vía API Shodan para mapear exposición global |
| [`vamp-subdomain-takeover`](vamp-subdomain-takeover/) | 1.3 | Detección de takeover CNAME + NS/MX + `--monitor` polling DNS continuo |
| [`vamp-cloud-enum`](vamp-cloud-enum/) | 1.3 | Enumeración S3/Azure/GCS + misconfiguraciones + GCP Cloud Functions expuestas (`--check-functions`) |
| [`vamp-darkweb-intel`](vamp-darkweb-intel/) | 1.1.0 | Lookup multi-fuente de IOCs + `--monitor` daemon de vigilancia continua con estado persistido |

### Auditoría de aplicaciones web

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-http-audit`](vamp-http-audit/) | 1.2.0 | Cabeceras OWASP + IDOR + Host Header Injection + Open Redirect (modo `--active`) |
| [`vamp-jwt-audit`](vamp-jwt-audit/) | 1.3.0 | alg=none + confusión RS256→HS256 + kid injection + JWKS spoofing |
| [`vamp-graphql-audit`](vamp-graphql-audit/) | 1.4.0 | DAST para GraphQL: introspección, BOLA/IDOR, DoS, injections, APQ persisted queries |
| [`vamp-oauth-audit`](vamp-oauth-audit/) | 1.1 | Auditoría de flujos OAuth 2.0 y OIDC: PKCE, state, redirect_uri, tokens JWT |
| [`vamp-wp2shell-audit`](vamp-wp2shell-audit/) | 1.1 | WordPress 40+ CVEs + ACF/Yoast/WooCommerce + detección multi-CMS |

### Auditoría de infraestructura

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-ssl-audit`](vamp-ssl-audit/) | 1.3.0 | TLS/SSL + DANE/TLSA + Certificate Transparency logs |
| [`vamp-mail-audit`](vamp-mail-audit/) | 1.1 | SPF/DKIM/DMARC + BIMI + MTA-STS |
| [`vamp-docker-audit`](vamp-docker-audit/) | 1.3 | Auditoría Docker CIS Benchmark + generación de SBOM CycloneDX |
| [`vamp-k8s-audit`](vamp-k8s-audit/) | 1.3 | Auditoría Kubernetes: RBAC, Network Policies, Helm charts (`--helm`) |
| [`vamp-forticheck`](vamp-forticheck/) | 1.1.0 | CVEs FortiOS/Cisco/PAN-OS con detección de versión vía HTTP |
| [`vamp-arp-sentinel`](vamp-arp-sentinel/) | 2.2 | Detección ARP spoofing + IPv6 NDP spoofing con `--json` / `--json-output` + integración vamp-orchestrator |
| [`vamp-azure-audit`](vamp-azure-audit/) | 1.1 | Auditoría Microsoft Azure: IAM, Storage, AKS, NSG, Key Vault, Defender |

### Auditoría cloud

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-gcp-audit`](vamp-gcp-audit/) | 1.2 | GCP: Service Accounts, GCS, GKE, BigQuery, PubSub |
| [`vamp-cloud-enum`](vamp-cloud-enum/) | 1.3 | Enumeración S3/Azure/GCS + misconfiguraciones + GCP Cloud Functions (`--check-functions`) |

### Inteligencia de amenazas y CVEs

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-cve-oracle`](vamp-cve-oracle/) | 3.1 | NVD + EPSS + CISA KEV: motor RBVM con check de exploits activos |
| [`vamp-shodan-hunt`](vamp-shodan-hunt/) | 1.1 | Búsqueda OSINT especializada en Shodan |

### Análisis forense y logs

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-log-analyzer`](vamp-log-analyzer/) | 2.1 | FORA: 25 detectores + STIX 2.1 + parser Wazuh + baseline profiling |
| [`vamp-log-hunter`](vamp-log-hunter/) | 1.3 | Hunting de IoC en logs: AbuseIPDB + OTX + `--fast-mode` (triage rápido &lt;5s) + `--max-ips` |
| [`vamp-forensic-query`](vamp-forensic-query/) | 1.2 | Consultas forenses sobre logs/CSV + evidencia firmada + cadena de custodia |
| [`vamp-entropy-watch`](vamp-entropy-watch/) | 2.1 | Detección de ransomware por entropía Shannon + `--threshold` + `--whitelist` |

### Auditoría de secretos y código

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-secrets-scanner`](vamp-secrets-scanner/) | 2.4 | 77 patrones + historia Git + Docker runtime + Kubernetes Secrets (`--k8s`) + GitHub Actions CI + SARIF |

### Seguridad de IA / LLM

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-llm-probe`](vamp-llm-probe/) | 1.6.0 | Prompt injection + ASCII smuggling + RAG injection + dataset red team |
| [`vamp-mcp-audit`](vamp-mcp-audit/) | 2.2 | Seguridad de servidores MCP: ASCII smuggling + tool poisoning + OWASP Agentic AI + `--monitor` continuo |

### Herramientas de reporting y orquestación

| Herramienta | Versión | Descripción |
|---|---|---|
| [`vamp-orchestrator`](vamp-orchestrator/) | 2.3 | Orquestador de 19 herramientas VSL con pipeline YAML configurable + notificaciones Telegram |
| [`vamp-penreport`](vamp-penreport/) | 2.5 | Agregador de informes pentest + CVSS 3.1 + export Jira/Defect Dojo + `--pdf` plantilla HTML personalizable |

### Laboratorios de investigación (PoC / Formación)

| Herramienta | Descripción |
|---|---|
| [`vamp-shellcode-lab`](vamp-shellcode-lab/) | Laboratorio de shellcode ARM64 educativo (mmap RWX, ASM inline, syscalls) |
| [`vamp-icmp-shadow`](vamp-icmp-shadow/) | Canal encubierto ICMP para validación de reglas IDS/IPS (PoC/formación) |
| [`vamp-llm-payloads`](vamp-llm-payloads/) | Datasets adversariales para red team de sistemas LLM |

---

## Uso con el orquestador

`vamp-orchestrator` auto-descubre las herramientas instaladas y ejecuta el subconjunto adecuado según el objetivo:

```bash
# Auditoría completa de un dominio
vamp-orchestrator --domain ejemplo.com --html informe.html

# Auditoría de una URL específica
vamp-orchestrator --url https://api.ejemplo.com --json hallazgos.json

# Auditoría de infraestructura
vamp-orchestrator --host 10.0.0.1 --html informe_infra.html

# Análisis de logs forenses
vamp-orchestrator --log-dir /var/log/nginx/ --html analisis_logs.html

# Pipeline personalizado vía YAML
vamp-orchestrator --pipeline mi_pipeline.yml --html resultado.html
```

---

## Formatos de salida (todos los tools)

| Formato | Flag | Descripción |
|---|---|---|
| Consola | Por defecto | Tablas y paneles con Rich (colores, badges de severidad) |
| JSON | `--json FILE` o `--output FILE` | Hallazgos estructurados — machine-readable |
| HTML | `--html FILE` | Informe dark-theme autocontenido — listo para cliente |
| Markdown | `--markdown FILE` | Exportación GFM para wikis o tickets (tools que lo soporten) |
| PDF | `--report-pdf FILE` | Informe PDF ejecutivo (tools con vampsec_report) |

---

## Contribuciones

Este repositorio es mantenido exclusivamente por **VampSecure Studios**. No se aceptan contribuciones externas.

---

## Aviso legal

> Estas herramientas se proporcionan **exclusivamente para pruebas de penetración autorizadas, evaluaciones de seguridad y formación en ciberseguridad**.
>
> Debes obtener **autorización escrita explícita** del propietario del sistema antes de ejecutar cualquier escaneo. El uso no autorizado puede ser ilegal bajo el Código Penal español (art. 197 bis), la CFAA, el Computer Misuse Act y leyes equivalentes en la mayoría de jurisdicciones.
>
> VampSecure Studios **no asume responsabilidad** por daños, consecuencias legales o usos indebidos derivados del uso no autorizado.

---

## Licencia

MIT License — consultar el fichero `LICENSE` en cada herramienta.

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  <em>Professional Security Research · Authorized Use Only</em>
</p>
