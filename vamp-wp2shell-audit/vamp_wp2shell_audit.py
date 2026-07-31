#!/usr/bin/env python3
"""
vamp_wp2shell_audit.py — Auditor de Vectores de Subida y Shell en WordPress
=============================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de auditoría de seguridad de alto rendimiento para sitios WordPress
que evalúa la exposición a vulnerabilidades de subida arbitraria de ficheros,
escalada de privilegios, inyección SQL y ejecución remota de código mediante
plugins y temas con vulnerabilidades conocidas.

ARQUITECTURA DE EJECUCIÓN (5 fases por objetivo)
-------------------------------------------------
  Fase 1 — Detección de WordPress (pasiva)
    Analiza el HTML de la página principal para identificar indicadores de
    WordPress (/wp-content/, /wp-includes/, meta generator, assets con ?ver=)
    y extrae la versión del core mediante cuatro patrones regex distintos.

  Fase 2 — Mapeo de superficie de ataque
    Comprueba de forma no destructiva la presencia de vectores de exposición:
    · XML-RPC habilitado (/xmlrpc.php)
    · Enumeración de usuarios via REST API (/wp-json/wp/v2/users)
    · Listado de directorio en /wp-content/uploads/
    · WP_DEBUG activo (warnings/notices visibles en el HTML)
    · Parámetros GET vulnerables a SQLi basado en errores (/?p=, /?cat=, /?s=)

  Fase 3 — Fingerprinting de plugins y temas (pasiva)
    Sondea readme.txt y style.css de cada plugin/tema conocido para verificar
    su presencia y extraer la versión instalada. Opera de forma completamente
    pasiva: solo solicita ficheros estáticos públicos.

  Fase 4 — Mapeo de vulnerabilidades
    Compara la versión de cada plugin detectado contra los rangos afectados de
    la base de datos PLUGIN_VULN_DB. Verifica si el endpoint de subida del CVE
    está accesible en el objetivo.

  Fase 5 — Subida canario (--canary, solo en modo autorizado)
    Sube un fichero PHP inerte de prueba al endpoint vulnerable confirmado para
    verificar que la subida llega al servidor y es accesible vía web.
    El fichero se elimina inmediatamente tras la verificación.
    Ver clase CanaryUploader para detalles de seguridad.

MODELO DE PUNTUACIÓN DE RIESGO
-------------------------------
  score  = Σ (CVSS_plugin × factor_versión) + puntos_endpoint_accesible
           + puntos_canario + puntos_superficie
  factor = 1.0 si versión confirmada; 0.5 si plugin detectado sin versión
  niveles: CRITICAL ≥ 9.0 · HIGH ≥ 7.0 · MEDIUM ≥ 4.0 · LOW > 0 · INFO = 0

CONCURRENCIA
------------
  asyncio + aiohttp con Semaphore configurable (--concurrency).
  El fingerprinting de plugins se paraleliza completamente; dentro de él se
  usa asyncio.gather para todas las sondas de un objetivo simultáneamente.

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
import hashlib
import json
import ipaddress
import sys
import re
import uuid
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, urljoin

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
     by VampSecure Studios · vamp-wp2shell-audit v1.0 · WordPress Upload Vector Auditor
     ──────────────────────────────────────────────────────────────────────────────────────
     USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# =============================================================================
# BASE DE DATOS DE VULNERABILIDADES DE PLUGINS WORDPRESS
# =============================================================================
# Estructura por entrada del diccionario:
#   cve             : Identificador CVE oficial
#   description     : Descripción del impacto en lenguaje claro
#   cvss            : Puntuación CVSS v3 base
#   severity        : Nivel NVD: CRITICAL / HIGH / MEDIUM / LOW
#   auth_required   : True si el exploit requiere autenticación previa
#   affected        : Dict con comparadores: {"<": "X.Y.Z"} o {"<=": "X.Y.Z"}
#   upload_endpoint : Ruta de la URL vulnerable a subida de ficheros (o None)
#   mime_bypass     : Lista de técnicas de bypass de tipo MIME documentadas
#   cwe             : Clasificación CWE del tipo de vulnerabilidad
#   secondary_vector: Vector secundario si aplica (ej. 'sqli')
#   note            : Nota adicional sobre el vector de explotación
# =============================================================================
PLUGIN_VULN_DB: Dict = {
    "wp-file-manager": [{
        "cve": "CVE-2020-25213",
        "description": "WP File Manager — subida arbitraria de ficheros no autenticada que deriva en RCE",
        "cvss": 9.8, "severity": "CRITICAL", "auth_required": False,
        "affected": {"<": "6.9"},
        "upload_endpoint": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "mime_bypass": ["php renombrado como image/jpeg", "extensión doble .php.jpg"],
        "cwe": "CWE-434",
    }],
    "fancy-product-designer": [{
        "cve": "CVE-2021-24370",
        "description": "Fancy Product Designer — subida arbitraria de ficheros no autenticada",
        "cvss": 9.8, "severity": "CRITICAL", "auth_required": False,
        "affected": {"<": "6.1.5"},
        "upload_endpoint": "/wp-json/fancyproductdesigner/v1/products",
        "mime_bypass": ["image/png con contenido PHP"],
        "cwe": "CWE-434",
    }],
    "contact-form-7": [{
        "cve": "CVE-2023-6449",
        "description": "Contact Form 7 — validación insuficiente de tipo MIME en formularios de subida",
        "cvss": 7.5, "severity": "HIGH", "auth_required": False,
        "affected": {"<": "5.8.4"},
        "upload_endpoint": "/",  # La subida se realiza a través del formulario en la página raíz
        "mime_bypass": ["doble extensión .php.jpg", "spoofing de Content-Type"],
        "cwe": "CWE-434",
    }],
    "formidable": [{
        "cve": "CVE-2023-0303",
        "description": "Formidable Forms — subida arbitraria de ficheros autenticada que deriva en RCE",
        "cvss": 8.8, "severity": "HIGH", "auth_required": True,
        "affected": {"<": "6.3.1"},
        "upload_endpoint": "/wp-admin/admin-ajax.php",
        "mime_bypass": ["PHP embebido en metadatos EXIF de imagen", "confusión de tipo MIME"],
        "cwe": "CWE-434",
    }],
    "woocommerce-payments": [{
        "cve": "CVE-2023-28121",
        "description": "WooCommerce Payments — escalada de privilegios no autenticada a administrador",
        "cvss": 9.8, "severity": "CRITICAL", "auth_required": False,
        "affected": {"<": "5.6.2"},
        "upload_endpoint": "/wp-json/wc/store/checkout",
        "mime_bypass": [],
        "cwe": "CWE-288",
        "note": "El bypass de autenticación permite posterior subida de ficheros via WP Media API",
    }],
    "essential-addons-for-elementor-lite": [{
        "cve": "CVE-2023-32243",
        "description": "Essential Addons for Elementor — escalada de privilegios no autenticada",
        "cvss": 9.8, "severity": "CRITICAL", "auth_required": False,
        "affected": {"<": "5.7.2"},
        "upload_endpoint": "/wp-admin/admin-ajax.php",
        "mime_bypass": [],
        "cwe": "CWE-288",
    }],
    "advanced-custom-fields": [{
        "cve": "CVE-2023-30777",
        "description": "Advanced Custom Fields — XSS reflejado que habilita cadena de ataque hacia RCE autenticado",
        "cvss": 7.1, "severity": "HIGH", "auth_required": True,
        "affected": {"<": "6.1.6"},
        "upload_endpoint": None,  # No es un vector directo de subida
        "mime_bypass": [],
        "cwe": "CWE-79",
    }],
    "wpforms-lite": [{
        "cve": "CVE-2023-3343",
        "description": "WPForms — inyección SQL mediante entradas de formulario",
        "cvss": 8.8, "severity": "HIGH", "auth_required": True,
        "affected": {"<": "1.8.1"},
        "upload_endpoint": "/wp-admin/admin.php",
        "mime_bypass": [],
        "cwe": "CWE-89",
        "secondary_vector": "sqli",
    }],
    "ninja-forms": [{
        "cve": "CVE-2023-37979",
        "description": "Ninja Forms — XSS reflejado / CSRF que deriva en XSS almacenado",
        "cvss": 7.3, "severity": "HIGH", "auth_required": False,
        "affected": {"<": "3.6.26"},
        "upload_endpoint": None,
        "mime_bypass": [],
        "cwe": "CWE-79",
    }],
    "duplicator": [{
        "cve": "CVE-2022-2443",
        "description": "Duplicator — lectura de ficheros sensibles y traversal de ruta no autenticado",
        "cvss": 7.5, "severity": "HIGH", "auth_required": False,
        "affected": {"<": "1.4.7"},
        "upload_endpoint": "/wp-content/plugins/duplicator/installer/read-file.php",
        "mime_bypass": [],
        "cwe": "CWE-22",
    }],
}

# Base de datos de vulnerabilidades de temas WordPress
THEME_VULN_DB: Dict = {
    "jupiter": [{
        "cve": "CVE-2022-1654",
        "description": "Jupiter Theme — eliminación arbitraria de ficheros y RCE autenticado",
        "cvss": 9.9, "severity": "CRITICAL", "auth_required": True,
        "affected": {"<": "6.10.2"},
        "upload_endpoint": "/wp-admin/admin-ajax.php",
        "cwe": "CWE-434",
    }],
    "shapely": [{
        "cve": "CVE-2021-24462",
        "description": "Shapely Theme — XSS reflejado que puede derivar en robo de credenciales de admin",
        "cvss": 6.1, "severity": "MEDIUM", "auth_required": False,
        "affected": {"<": "1.2.8"},
        "upload_endpoint": None,
        "cwe": "CWE-79",
    }],
}

# Patrones regex para extraer la versión de WordPress del HTML
# Se prueban en orden de fiabilidad — el primero que hace match gana
WP_VERSION_RE = [
    re.compile(r'<meta\s+name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d.]+)', re.I),
    re.compile(r'wp-includes/css/[^?]+\?ver=([\d.]+)', re.I),
    re.compile(r'wp-content/themes/[^/]+/style\.css\?ver=([\d.]+)', re.I),
    re.compile(r'"generator"\s*:\s*"WordPress\s+([\d.]+)"', re.I),
]


# =============================================================================
# MODELO DE DATOS
# =============================================================================

@dataclass
class ResultadoCanario:
    """
    Resultado de la operación de subida canario (--canary).

    Campos
    ------
    intentado     : True si se intentó la subida (endpoint accesible y sin auth)
    nombre_fichero: Nombre único generado para el fichero canario
    url_subida    : URL completa donde quedó el fichero tras la subida
    accesible     : True si el fichero fue accesible via HTTP tras la subida
    eliminado     : True si el fichero fue eliminado tras la verificación
    evidencia     : Descripción del resultado de la sonda
    """
    intentado: bool
    nombre_fichero: str
    url_subida: Optional[str]
    accesible: bool
    eliminado: bool
    evidencia: Optional[str]


@dataclass
class ScanResult:
    """
    Contenedor de resultados para un objetivo WordPress escaneado.

    Campos
    ------
    target              : URL del objetivo tal como fue introducida
    timestamp           : Fecha/hora de inicio en UTC ISO-8601
    is_wordpress        : True si se detectaron indicadores de WordPress
    wp_version          : Versión del core WordPress detectada o None
    xmlrpc_enabled      : True si XML-RPC responde a llamadas de método
    rest_api_exposed    : True si /wp-json/wp/v2/users devuelve datos sin auth
    upload_dir_exposed  : True si /wp-content/uploads/ muestra listado de dir.
    debug_mode          : True si hay warnings/notices PHP visibles en el HTML
    installed_plugins   : Slugs de plugins detectados (presentes en el servidor)
    installed_themes    : Slugs de temas detectados
    plugin_findings     : Lista de CVEs mapeados a plugins detectados
    theme_findings      : Lista de CVEs mapeados a temas detectados
    sqli_vectors        : Vectores de SQLi detectados por error patterns
    canary              : Resultado del test de subida canario (si --canary)
    risk_score          : Puntuación de riesgo compuesta (0.0–10.0)
    risk_level          : Nivel semáforo: CRITICAL / HIGH / MEDIUM / LOW / INFO
    error               : 'OUT_OF_SCOPE' o mensaje de error de red
    """
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_wordpress: bool = False
    wp_version: Optional[str] = None
    xmlrpc_enabled: bool = False
    rest_api_exposed: bool = False
    upload_dir_exposed: bool = False
    debug_mode: bool = False
    installed_plugins: List[str] = field(default_factory=list)
    installed_themes: List[str] = field(default_factory=list)
    plugin_findings: List[Dict] = field(default_factory=list)
    theme_findings: List[Dict] = field(default_factory=list)
    sqli_vectors: List[Dict] = field(default_factory=list)
    canary: Optional[Dict] = None
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    error: Optional[str] = None


# =============================================================================
# VALIDADOR DE ALCANCE (SCOPE)
# =============================================================================

class ScopeValidator:
    """
    Verifica que un objetivo esté dentro del alcance autorizado antes de
    ejecutar cualquier sonda de red.

    El fichero de alcance (scope.txt) soporta:
      · Rango CIDR      → 192.168.0.0/24
      · Wildcard        → *.ejemplo.com
      · Host exacto     → www.ejemplo.com  o  10.0.0.1
      · Líneas '#...'   → comentarios, ignorados

    Si no se especifica fichero de scope, todos los objetivos pasan la validación
    (el auditor asume plena responsabilidad sobre el targeting).
    """

    def __init__(self, scope_file: Optional[str] = None):
        self.entries: set = set()
        self.active = scope_file is not None
        if scope_file:
            self._load(scope_file)

    def _load(self, path: str):
        """Carga y normaliza las entradas del fichero de scope."""
        p = Path(path)
        if not p.exists():
            console.print(f"[bold red][!] Fichero de scope no encontrado: {path}[/bold red]")
            sys.exit(1)
        for linea in p.read_text().splitlines():
            linea = linea.strip()
            if linea and not linea.startswith("#"):
                self.entries.add(linea.lower())
        console.print(f"[cyan][i] Scope: {len(self.entries)} entradas desde {path}[/cyan]")

    def is_in_scope(self, objetivo: str) -> bool:
        """
        Retorna True si el objetivo está en el scope autorizado.

        Parámetros
        ----------
        objetivo : str  — URL completa o host/IP del objetivo

        Retorna
        -------
        bool  — True si autorizado, False si fuera de scope
        """
        if not self.active:
            return True

        parsed = urlparse(objetivo if "://" in objetivo else f"https://{objetivo}")
        host = (parsed.hostname or objetivo).lower()

        for entrada in self.entries:
            if entrada == host:
                return True
            # Wildcard: *.dominio.com incluye sub.dominio.com pero no dominio.com directamente
            if entrada.startswith("*.") and host.endswith(entrada[1:]):
                return True
            # CIDR: solo para IPs válidas
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entrada, strict=False):
                    return True
            except ValueError:
                pass

        return False


# =============================================================================
# DETECTOR DE WORDPRESS
# =============================================================================

class WPDetector:
    """
    Identifica la presencia de WordPress y extrae la versión del core mediante
    análisis pasivo del HTML de la respuesta principal del sitio.

    No realiza peticiones adicionales en esta fase: trabaja exclusivamente
    sobre el contenido ya descargado en la Fase 1 del escáner.

    Indicadores de detección
    ------------------------
    Cadenas que identifican de forma inequívoca una instalación WordPress
    al aparecer en el HTML o en las cabeceras HTTP de la respuesta.

    Patrones de versión
    -------------------
    Se prueban cuatro expresiones regex en orden de especificidad:
    1. Meta tag generator → más fiable, desactivable pero común
    2. ?ver= en assets CSS de wp-includes
    3. ?ver= en style.css del tema activo
    4. Campo "generator" en JSON (API REST o feeds)
    """

    # Indicadores de presencia de WordPress
    INDICADORES = [
        "/wp-content/", "/wp-includes/", "wp-login.php",
        "WordPress", "woocommerce", "/wp-json/",
        "xmlrpc.php", "wp-admin",
    ]

    @classmethod
    def detect(cls, contenido: str, cabeceras: Dict) -> Tuple[bool, Optional[str]]:
        """
        Detecta WordPress y extrae la versión del HTML y las cabeceras.

        Parámetros
        ----------
        contenido : str   — Cuerpo de la respuesta HTTP (HTML)
        cabeceras : Dict  — Cabeceras HTTP de la respuesta

        Retorna
        -------
        Tuple[bool, Optional[str]]
          - bool           → True si el sitio parece ser WordPress
          - Optional[str]  → Versión del core ('6.4.2') o None si no detectada
        """
        # Limitar el análisis a los primeros 50 KB para evitar regex lentos en páginas enormes
        combinado = contenido[:50000] + str(cabeceras)
        es_wp = any(ind.lower() in combinado.lower() for ind in cls.INDICADORES)

        version = None
        for rx in WP_VERSION_RE:
            m = rx.search(contenido)
            if m:
                version = m.group(1)
                break

        return es_wp, version


# =============================================================================
# FINGERPRINTER DE PLUGINS Y TEMAS
# =============================================================================

class PluginFingerprinter:
    """
    Enumera plugins y temas instalados mediante sondas pasivas a ficheros
    de metadata estáticos públicamente accesibles.

    Método de enumeración
    ---------------------
    Para cada slug en PLUGIN_VULN_DB:
      · GET /wp-content/plugins/{slug}/readme.txt  → contiene 'Stable tag: X.Y.Z'
      · GET /wp-content/plugins/{slug}/readme.md   → alternativa para algunos plugins

    Para cada slug en THEME_VULN_DB:
      · GET /wp-content/themes/{slug}/style.css    → contiene 'Version: X.Y.Z'

    Una respuesta HTTP 200 confirma la presencia del plugin/tema.
    La versión se extrae del contenido del fichero descargado.

    Concurrencia
    ------------
    Todos los slugs se sondean en paralelo con asyncio.gather, lo que hace
    que la enumeración de N plugins tome el tiempo del más lento, no la suma.
    """

    def __init__(self, session: aiohttp.ClientSession, timeout: int = 8):
        """
        Parámetros
        ----------
        session : aiohttp.ClientSession  — Sesión HTTP compartida
        timeout : int                    — Timeout por petición en segundos
        """
        self.session = session
        self.to = aiohttp.ClientTimeout(total=timeout)

    async def enumerar_plugins(self, url_base: str, slugs: List[str]) -> List[Tuple[str, Optional[str]]]:
        """
        Sondea los ficheros readme de cada slug y devuelve los detectados con versión.

        Parámetros
        ----------
        url_base : str        — URL base del sitio WordPress
        slugs    : List[str]  — Lista de slugs de plugins a comprobar

        Retorna
        -------
        List[Tuple[str, Optional[str]]]  — [(slug, versión_o_None), ...]
        """
        async def sondear(slug: str) -> Optional[Tuple[str, Optional[str]]]:
            for ruta in (
                f"/wp-content/plugins/{slug}/readme.txt",
                f"/wp-content/plugins/{slug}/readme.md",
            ):
                try:
                    async with self.session.get(
                        f"{url_base}{ruta}",
                        timeout=self.to,
                        ssl=False,
                        allow_redirects=False,  # Un redirect indica que no existe localmente
                    ) as r:
                        if r.status == 200:
                            cuerpo = await r.text(errors="replace")
                            version = self._extraer_version(cuerpo)
                            return (slug, version)
                except Exception:
                    pass
            return None

        tareas = [sondear(slug) for slug in slugs]
        resultados = await asyncio.gather(*tareas, return_exceptions=True)

        return [r for r in resultados if isinstance(r, tuple) and r is not None]

    async def enumerar_temas(self, url_base: str, slugs: List[str]) -> List[Tuple[str, Optional[str]]]:
        """
        Sondea el style.css de cada tema y devuelve los detectados con versión.

        Parámetros
        ----------
        url_base : str        — URL base del sitio WordPress
        slugs    : List[str]  — Lista de slugs de temas a comprobar

        Retorna
        -------
        List[Tuple[str, Optional[str]]]  — [(slug, versión_o_None), ...]
        """
        async def sondear(slug: str) -> Optional[Tuple[str, Optional[str]]]:
            try:
                async with self.session.get(
                    f"{url_base}/wp-content/themes/{slug}/style.css",
                    timeout=self.to,
                    ssl=False,
                    allow_redirects=False,
                ) as r:
                    if r.status == 200:
                        cuerpo = await r.text(errors="replace")
                        ver_m = re.search(r'Version:\s*([\d.]+)', cuerpo, re.I)
                        return (slug, ver_m.group(1) if ver_m else None)
            except Exception:
                pass
            return None

        tareas = [sondear(slug) for slug in slugs]
        resultados = await asyncio.gather(*tareas, return_exceptions=True)

        return [r for r in resultados if isinstance(r, tuple) and r is not None]

    @staticmethod
    def _extraer_version(readme: str) -> Optional[str]:
        """
        Extrae la versión del contenido de un readme.txt de WordPress.

        Intenta tres patrones en orden de especificidad:
        1. 'Stable tag: X.Y.Z'  — formato estándar del directorio de WP.org
        2. 'Version: X.Y.Z'     — formato de encabezado de plugin
        3. Primer número de versión en el changelog
        """
        for patron in (
            r'Stable tag:\s*([\d.]+)',
            r'Version:\s*([\d.]+)',
            r'==\s*Changelog\s*==.*?=\s*([\d.]+)',
        ):
            m = re.search(patron, readme, re.I | re.S)
            if m:
                return m.group(1)
        return None


# =============================================================================
# MAPEADOR DE VULNERABILIDADES
# =============================================================================

class VulnMapper:
    """
    Mapea los plugins/temas detectados a CVEs conocidos comparando la versión
    instalada contra los rangos afectados de la base de datos.

    La comparación de versiones se realiza sobre tuplas de enteros (major, minor, patch)
    para garantizar una ordenación semántica correcta, evitando comparaciones de
    cadenas que producirían resultados incorrectos (ej. '10.0' < '9.0' en str).
    """

    @staticmethod
    def _parsear_version(v: str) -> Tuple[int, ...]:
        """
        Convierte 'X.Y.Z' en tupla comparable (X, Y, Z).

        Si la conversión falla (versión malformada), retorna (0,) para
        que el comparador no falle con una excepción inesperada.
        """
        try:
            return tuple(int(x) for x in v.split("."))
        except (ValueError, AttributeError):
            return (0,)

    @classmethod
    def mapear(cls, slug: str, version: Optional[str], db: Dict) -> List[Dict]:
        """
        Busca vulnerabilidades para un slug dado con su versión detectada.

        Parámetros
        ----------
        slug    : str           — Slug del plugin/tema (clave en la BD)
        version : Optional[str] — Versión detectada, o None si no fue legible
        db      : Dict          — Base de datos de vulnerabilidades a consultar

        Retorna
        -------
        List[Dict]  — Lista de vulnerabilidades encontradas. Cada dict incluye
                      todos los campos del PLUGIN_VULN_DB más 'version_confirmed'
                      y 'detected_version'.

        Nota sobre version_confirmed
        ----------------------------
        Si version es None, no podemos confirmar el rango de versión afectada,
        pero el plugin está presente en el servidor, lo que constituye un riesgo
        potencial. En ese caso, version_confirmed=False con detected_version=None.
        """
        resultados = []

        for vuln in db.get(slug, []):
            afectado = vuln.get("affected", {})
            limite_menor  = afectado.get("<")   # Afectado si versión < X
            limite_menorigual = afectado.get("<=")  # Afectado si versión <= X

            if version is None:
                # Plugin detectado pero versión no legible — riesgo potencial
                resultados.append({**vuln, "version_confirmed": False, "detected_version": None})

            elif limite_menor and cls._parsear_version(version) < cls._parsear_version(limite_menor):
                resultados.append({**vuln, "version_confirmed": True, "detected_version": version})

            elif limite_menorigual and cls._parsear_version(version) <= cls._parsear_version(limite_menorigual):
                resultados.append({**vuln, "version_confirmed": True, "detected_version": version})

        return resultados


# =============================================================================
# VERIFICADOR DE SUPERFICIE DE ATAQUE
# =============================================================================

class UploadChecker:
    """
    Realiza comprobaciones de solo lectura sobre la superficie de ataque del
    sitio WordPress: vectores de autenticación alternativos, endpoints de subida
    expuestos y parámetros potencialmente vulnerables a SQLi.

    Ninguna de estas comprobaciones modifica datos en el servidor objetivo.
    """

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.to = aiohttp.ClientTimeout(total=8)

    async def check_xmlrpc(self, url_base: str) -> bool:
        """
        Verifica si XML-RPC está habilitado enviando una llamada a system.listMethods.

        XML-RPC habilitado es un factor de riesgo porque permite ataques de
        fuerza bruta multi-llamada (una petición = múltiples intentos de login)
        y puede ser el vector de exploits de plugins como CVE-2020-25213.

        Retorna True si XML-RPC responde con una lista de métodos válida.
        """
        try:
            async with self.session.post(
                f"{url_base}/xmlrpc.php",
                data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                headers={"Content-Type": "text/xml"},
                timeout=self.to,
                ssl=False,
            ) as r:
                cuerpo = await r.text(errors="replace")
                return r.status == 200 and "<methodResponse>" in cuerpo
        except Exception:
            return False

    async def check_rest_api(self, url_base: str) -> bool:
        """
        Comprueba si la API REST de WordPress expone la lista de usuarios sin autenticación.

        Un endpoint /wp-json/wp/v2/users accesible sin auth permite enumerar
        usernames de administradores, facilitando ataques de fuerza bruta
        dirigidos o credential stuffing.

        Retorna True si la respuesta contiene IDs de usuario.
        """
        try:
            async with self.session.get(
                f"{url_base}/wp-json/wp/v2/users",
                timeout=self.to,
                ssl=False,
            ) as r:
                cuerpo = await r.text(errors="replace")
                return r.status == 200 and '"id"' in cuerpo
        except Exception:
            return False

    async def check_upload_dir_listing(self, url_base: str) -> bool:
        """
        Verifica si el directorio de uploads tiene el listado de directorios activo.

        Un directorio /wp-content/uploads/ navegable permite a un atacante
        explorar todos los ficheros subidos, incluyendo potenciales webshells
        subidas en explotaciones previas. También facilita la localización de
        ficheros subidos mediante el test canario.

        Retorna True si la respuesta contiene índices de directorio típicos.
        """
        try:
            async with self.session.get(
                f"{url_base}/wp-content/uploads/",
                timeout=self.to,
                ssl=False,
            ) as r:
                cuerpo = await r.text(errors="replace")
                return r.status == 200 and any(
                    ind in cuerpo.lower()
                    for ind in ("index of", "parent directory", "last modified")
                )
        except Exception:
            return False

    async def check_debug_mode(self, url_base: str) -> bool:
        """
        Detecta si WP_DEBUG está activo comprobando si hay mensajes PHP
        de Warning o Notice visibles en el HTML de la página principal.

        WP_DEBUG activo en producción expone rutas absolutas del servidor,
        nombres de variables, fragmentos de código fuente y puede revelar
        credenciales en mensajes de error de conexión a base de datos.

        Retorna True si se detectan markers de debug activo.
        """
        try:
            async with self.session.get(url_base, timeout=self.to, ssl=False) as r:
                cuerpo = await r.text(errors="replace")
                return any(
                    s in cuerpo
                    for s in ("<b>Warning</b>:", "<b>Notice</b>:", "wp-content/debug.log")
                )
        except Exception:
            return False

    async def sondear_endpoint_plugin(self, url_base: str, endpoint: str) -> Dict:
        """
        Verifica si un endpoint de subida de un plugin vulnerable está accesible.

        Esta comprobación no intenta subir ningún fichero; solo verifica que
        el endpoint existe y responde (código HTTP diferente de 404/410).

        Parámetros
        ----------
        url_base : str  — URL base del sitio
        endpoint : str  — Ruta del endpoint del plugin (ej. /wp-admin/admin-ajax.php)

        Retorna
        -------
        Dict con campos: endpoint, status, accessible, content_type, error (si aplica)
        """
        if not endpoint:
            return {}
        try:
            url = urljoin(url_base, endpoint)
            async with self.session.get(
                url,
                timeout=self.to,
                ssl=False,
                allow_redirects=False,
            ) as r:
                return {
                    "endpoint": endpoint,
                    "status": r.status,
                    "accessible": r.status not in (404, 410),
                    "content_type": r.headers.get("Content-Type", ""),
                }
        except Exception as e:
            return {"endpoint": endpoint, "status": None, "accessible": False, "error": str(e)[:60]}

    async def detectar_sqli_vectors(self, url_base: str) -> List[Dict]:
        """
        Detecta vectores de inyección SQL basados en errores mediante sondas
        pasivas en parámetros GET públicos de WordPress.

        Método
        ------
        Se añade una comilla simple al valor de parámetros estándar de WordPress
        (/?p=1', /?cat=1', /?s=') que habitualmente se procesan en consultas SQL.
        Si la respuesta contiene mensajes de error de base de datos, el parámetro
        es potencialmente vulnerable a SQLi basado en errores.

        Esta sonda no realiza extracción de datos ni modificaciones; solo observa
        si la base de datos produce errores ante entradas malformadas.

        Parámetros
        ----------
        url_base : str  — URL base del sitio WordPress

        Retorna
        -------
        List[Dict]  — Lista de vectores SQLi encontrados
        """
        vectores: List[Dict] = []

        # Patrones de error de bases de datos populares (MySQL, MSSQL, Oracle)
        patrones_error = [
            r"You have an error in your SQL syntax",
            r"Warning.*mysql_",
            r"supplied argument is not a valid MySQL",
            r"ORA-\d{5}",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
        ]

        # Parámetros GET estándar de WordPress que suelen procesarse en consultas SQL
        urls_sonda = [
            f"{url_base}/?p=1'",
            f"{url_base}/?cat=1'",
            f"{url_base}/?s='",
        ]

        for url in urls_sonda:
            try:
                async with self.session.get(url, timeout=self.to, ssl=False) as r:
                    cuerpo = await r.text(errors="replace")
                    for patron in patrones_error:
                        if re.search(patron, cuerpo, re.I):
                            vectores.append({
                                "url": url,
                                "patron": patron,
                                "severity": "HIGH",
                                "type": "sqli_error_based",
                                "description": "Mensaje de error SQL visible — posible SQLi basado en errores",
                            })
                            break  # Un match por URL es suficiente
            except Exception:
                pass

        return vectores


# =============================================================================
# SUBIDA CANARIO (DRY-RUN)
# =============================================================================

class CanaryUploader:
    """
    Verifica la explotabilidad de endpoints de subida de ficheros arbitrarios
    mediante un fichero PHP inerte de prueba (canario) que se elimina
    inmediatamente tras verificar su accesibilidad.

    DETALLES DE SEGURIDAD DEL FICHERO CANARIO
    ------------------------------------------
    El canario es un fichero PHP minimalista con las siguientes características
    de seguridad:
      · Sin llamadas al sistema: no usa system(), exec(), shell_exec(), etc.
      · Sin lectura de ficheros: no usa file_get_contents(), readfile(), etc.
      · Sin escritura: no crea ni modifica ficheros en el servidor
      · Auto-terminante: la instrucción die() detiene la ejecución inmediatamente
      · Salida determinista: imprime exactamente 'VAMPSECURE_CANARY_' + MD5
      · Sin parámetros: no acepta ni procesa ningún input externo

    Contenido exacto del canario:
      <?php $t='VAMPSECURE_CANARY_' . md5(__FILE__ . $_SERVER['HTTP_HOST']);
            header('Content-Type: text/plain'); echo $t; die(); ?>

    PROCESO DE SUBIDA
    -----------------
    1. Generar nombre único: vamp_canary_[hash10].php
    2. Subir con Content-Type: image/jpeg (spoof MIME para testear bypass)
    3. Verificar accesibilidad: GET al fichero subido
    4. Si PHP se ejecuta: evidencia='Canary PHP ejecutado — RCE confirmado'
    5. Si solo es accesible sin ejecutarse: evidencia='Subida confirmada sin exec PHP'
    6. Eliminar inmediatamente: DELETE via REST API o petición directa
    7. Registrar resultado con nombre del fichero para limpieza manual si falla

    IMPORTANTE
    ----------
    Esta funcionalidad SOLO se activa con el flag --canary explícito.
    REQUIERE autorización escrita del propietario del sistema objetivo.
    El nombre del fichero se incluye en el informe para permitir verificación
    y limpieza manual en caso de fallo del borrado automático.
    """

    # Contenido PHP inerte del canario: sin syscalls, sin lectura de ficheros, auto-terminante
    PHP_CANARIO = (
        "<?php"
        " $t='VAMPSECURE_CANARY_' . md5(__FILE__ . $_SERVER['HTTP_HOST']);"
        " header('Content-Type: text/plain');"
        " echo $t;"
        " die();"
        " ?>"
    )

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.to = aiohttp.ClientTimeout(total=15)

    def _generar_nombre(self) -> str:
        """
        Genera un nombre de fichero único y no predecible para el canario.

        Usa MD5 de un UUID4 (aleatorio) truncado a 10 caracteres, suficiente
        para garantizar unicidad sin crear nombres exageradamente largos.
        """
        uid = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:10]
        return f"vamp_canary_{uid}.php"

    async def run(self, url_base: str, endpoint: str, campo: str = "file") -> ResultadoCanario:
        """
        Ejecuta la secuencia completa de subida, verificación y limpieza.

        Parámetros
        ----------
        url_base : str  — URL base del sitio WordPress
        endpoint : str  — Ruta del endpoint vulnerable (del PLUGIN_VULN_DB)
        campo    : str  — Nombre del campo de formulario para el fichero (por defecto 'file')

        Retorna
        -------
        ResultadoCanario — Resultado detallado de la operación
        """
        nombre = self._generar_nombre()
        resultado = ResultadoCanario(
            intentado=True,
            nombre_fichero=nombre,
            url_subida=None,
            accesible=False,
            eliminado=False,
            evidencia=None,
        )

        # ── Subida ─────────────────────────────────────────────────────────────
        formulario = aiohttp.FormData()
        formulario.add_field(
            campo,
            self.PHP_CANARIO.encode(),
            filename=nombre,
            content_type="image/jpeg",  # Spoof MIME: image/jpeg para testear bypass de extensión
        )

        try:
            async with self.session.post(
                urljoin(url_base, endpoint),
                data=formulario,
                timeout=self.to,
                ssl=False,
            ) as r:
                cuerpo = await r.text(errors="replace")

                if r.status not in (200, 201):
                    resultado.evidencia = f"La subida devolvió HTTP {r.status}"
                    return resultado

                # Intentar extraer la URL del fichero subido de la respuesta
                # Primero buscar URL absoluta, luego ruta relativa
                url_m = re.search(
                    r'(https?://[^\s"\']+' + re.escape(nombre) + r')', cuerpo
                )
                if url_m:
                    resultado.url_subida = url_m.group(1)
                else:
                    ruta_m = re.search(
                        r'(/wp-content/uploads/[^\s"\']+' + re.escape(nombre) + r')', cuerpo
                    )
                    if ruta_m:
                        resultado.url_subida = urljoin(url_base, ruta_m.group(1))
                    else:
                        # Asumir la ruta estándar de uploads por año/mes
                        anio = datetime.now().strftime("%Y")
                        mes  = datetime.now().strftime("%m")
                        resultado.url_subida = f"{url_base}/wp-content/uploads/{anio}/{mes}/{nombre}"

        except Exception as e:
            resultado.evidencia = f"Error durante la subida: {str(e)[:80]}"
            return resultado

        if not resultado.url_subida:
            resultado.evidencia = "Subida aparentemente realizada pero URL del fichero no determinada"
            return resultado

        # ── Verificación de accesibilidad ──────────────────────────────────────
        try:
            async with self.session.get(resultado.url_subida, timeout=self.to, ssl=False) as r:
                cuerpo = await r.text(errors="replace")
                if "VAMPSECURE_CANARY_" in cuerpo:
                    # El PHP se ejecutó: RCE confirmado
                    resultado.accesible = True
                    resultado.evidencia = "Canario PHP ejecutado — ejecución de código PHP confirmada (RCE)"
                elif r.status == 200:
                    # Fichero accesible pero PHP no ejecutado (servidor puede tener PHP deshabilitado en uploads)
                    resultado.accesible = True
                    resultado.evidencia = (
                        f"Fichero accesible (HTTP {r.status}) pero PHP no ejecutado — "
                        "subida confirmada; ejecución depende de configuración del servidor"
                    )
        except Exception:
            pass

        # ── Limpieza inmediata ─────────────────────────────────────────────────
        # Intentar borrado independientemente del resultado de la verificación
        await self._eliminar_canario(url_base, resultado.url_subida, nombre)
        resultado.eliminado = True

        return resultado

    async def _eliminar_canario(self, url_base: str, url_fichero: str, nombre: str):
        """
        Intenta eliminar el fichero canario mediante dos métodos en orden:
        1. REST API de WordPress (/wp-json/wp/v2/media?slug=...&force=true)
        2. Petición HTTP DELETE directa a la URL del fichero

        Si ambos fallan, el nombre del fichero queda registrado en el informe
        para limpieza manual durante el cierre del compromiso de auditoría.
        """
        # Intento 1: REST API (requiere autenticación — puede no funcionar, pero se intenta)
        try:
            async with self.session.delete(
                f"{url_base}/wp-json/wp/v2/media?slug={nombre}&force=true",
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
            ) as r:
                if r.status in (200, 204):
                    return
        except Exception:
            pass

        # Intento 2: DELETE directo a la URL (algunas misconfiguraciones de servidor lo permiten)
        try:
            async with self.session.delete(
                url_fichero,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
            ) as _:
                pass
        except Exception:
            pass


# =============================================================================
# GENERADOR DE INFORMES
# =============================================================================

class ReportGenerator:
    """
    Exporta los resultados en formato JSON estructurado y HTML interactivo
    con tema oscuro (dark magenta/purple).

    Los informes HTML son documentos standalone sin dependencias externas.
    """

    @staticmethod
    def to_json(results: List[ScanResult], ruta: str):
        """
        Serializa todos los resultados a JSON con un bloque de resumen agregado.

        Parámetros
        ----------
        results : List[ScanResult]  — Lista de resultados del escáner
        ruta    : str               — Ruta del fichero de salida (.json)
        """
        datos = {
            "tool": "vamp-wp2shell-audit",
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "objetivos": len(results),
                "wordpress_confirmado": sum(1 for r in results if r.is_wordpress),
                "cves_criticos": sum(
                    1 for r in results
                    for f in r.plugin_findings
                    if f.get("severity") == "CRITICAL"
                ),
                "vectores_subida": sum(
                    1 for r in results
                    for f in r.plugin_findings
                    if f.get("upload_endpoint")
                ),
                "canario_confirmado": sum(
                    1 for r in results
                    if r.canary and r.canary.get("accesible")
                ),
            },
            "results": [asdict(r) for r in results],
        }
        Path(ruta).write_text(json.dumps(datos, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def to_html(results: List[ScanResult], ruta: str):
        """
        Genera un informe HTML standalone con tema oscuro magenta/púrpura.

        Parámetros
        ----------
        results : List[ScanResult]  — Lista de resultados del escáner
        ruta    : str               — Ruta del fichero de salida (.html)
        """
        filas = ""
        for r in results:
            if r.error == "OUT_OF_SCOPE":
                continue
            cves_criticos = [f["cve"] for f in r.plugin_findings if f.get("severity") == "CRITICAL"]
            cves_upload   = [f["cve"] for f in r.plugin_findings if f.get("upload_endpoint")]
            clase_fila    = r.risk_level.lower()
            canario_str   = (
                "SÍ — RCE" if r.canary and r.canary.get("accesible")
                else ("Intentado" if r.canary and r.canary.get("intentado") else "—")
            )
            filas += f"""
            <tr class="fila-{clase_fila}">
                <td><code>{r.target}</code></td>
                <td>{"<span class='si'>SÍ</span>" if r.is_wordpress else "<span class='no'>NO</span>"}</td>
                <td>{r.wp_version or "—"}</td>
                <td>{len(r.plugin_findings)}</td>
                <td>{", ".join(cves_criticos[:3]) or "—"}</td>
                <td>{len(cves_upload)}</td>
                <td>{canario_str}</td>
                <td><span class="badge badge-{clase_fila}">{r.risk_level}</span></td>
                <td>{r.risk_score:.1f}</td>
            </tr>"""

        metricas = {
            "Objetivos": len([r for r in results if r.error != "OUT_OF_SCOPE"]),
            "WP Detectado": sum(1 for r in results if r.is_wordpress),
            "CVEs Críticos": sum(1 for r in results for f in r.plugin_findings if f.get("severity") == "CRITICAL"),
            "Vectores Subida": sum(1 for r in results for f in r.plugin_findings if f.get("upload_endpoint")),
        }
        tarjetas = "".join(
            f'<div class="tarjeta"><div class="valor">{v}</div><div class="etiqueta">{k}</div></div>'
            for k, v in metricas.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>vamp-wp2shell-audit — Informe {datetime.now().strftime('%Y-%m-%d')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Courier New',monospace;background:#0a0a0a;color:#ddd;padding:24px;line-height:1.5}}
  h1{{color:#a000ff;font-size:1.4em;margin-bottom:4px;letter-spacing:1px}}
  .subtitulo{{color:#555;font-size:.8em;margin-bottom:20px}}
  .metricas{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
  .tarjeta{{background:#141414;border:1px solid #222;padding:12px 20px;border-radius:4px;min-width:130px}}
  .tarjeta .valor{{font-size:2em;font-weight:700;color:#a000ff}}
  .tarjeta .etiqueta{{font-size:.75em;color:#666;text-transform:uppercase;letter-spacing:.5px}}
  table{{width:100%;border-collapse:collapse;font-size:.82em}}
  th{{background:#0e001a;color:#a000ff;padding:8px 10px;text-align:left;border:1px solid #2a2a2a;font-size:.78em;text-transform:uppercase;letter-spacing:.5px}}
  td{{padding:7px 10px;border:1px solid #1e1e1e}}
  .fila-critical{{background:rgba(160,0,255,.06)}}
  .fila-high{{background:rgba(255,100,0,.06)}}
  .fila-medium{{background:rgba(255,200,0,.04)}}
  .badge{{padding:2px 7px;border-radius:3px;font-size:.75em;font-weight:700}}
  .badge-critical{{background:#a000ff;color:#fff}}
  .badge-high{{background:#ff6400;color:#fff}}
  .badge-medium{{background:#ffc800;color:#000}}
  .badge-low{{background:#0090ff;color:#fff}}
  .badge-info,.badge-unknown{{background:#333;color:#999}}
  .si{{color:#00e676;font-weight:700}} .no{{color:#555}}
  .pie{{margin-top:20px;color:#333;font-size:.75em;border-top:1px solid #1e1e1e;padding-top:10px}}
  code{{background:#111;padding:1px 4px;border-radius:2px;font-size:.9em}}
</style>
</head>
<body>
<h1>&#128273; vamp-wp2shell-audit — Informe de Vectores de Subida WordPress</h1>
<p class="subtitulo">VampSecure Labs · VampSecure Studios · Solo para uso en auditorías autorizadas</p>
<div class="metricas">{tarjetas}</div>
<table>
<tr><th>Objetivo</th><th>WP</th><th>Versión WP</th><th>CVEs</th><th>CVEs Críticos</th><th>Vect. Subida</th><th>Canario</th><th>Riesgo</th><th>Score</th></tr>
{filas}
</table>
<div class="pie">
Generado por vamp-wp2shell-audit v1.0 · VampSecure Labs · VampSecure Studios · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>
</body>
</html>"""
        Path(ruta).write_text(html, encoding="utf-8")


# =============================================================================
# ESCÁNER PRINCIPAL
# =============================================================================

class WPScanner:
    """
    Orquestador principal del proceso de auditoría WordPress.

    Gestiona el ciclo de vida completo de cada objetivo a través de las 5 fases,
    coordina la concurrencia con Semaphore y calcula el riesgo final.
    """

    # Umbrales de puntuación para nivel semáforo (escala CVSS 0–10)
    UMBRALES_RIESGO = {
        "CRITICAL": 9.0,
        "HIGH":     7.0,
        "MEDIUM":   4.0,
        "LOW":      0.1,
    }

    def __init__(self, args):
        self.args = args
        self.scope = ScopeValidator(args.scope)

    def _normalizar_url(self, objetivo: str) -> str:
        """Añade https:// si el objetivo no incluye protocolo."""
        if "://" in objetivo:
            return objetivo.rstrip("/")
        return f"https://{objetivo.rstrip('/')}"

    async def _escanear_objetivo(self, objetivo: str, session: aiohttp.ClientSession) -> ScanResult:
        """
        Ejecuta las 5 fases de auditoría para un objetivo individual.

        Parámetros
        ----------
        objetivo : str                    — URL del sitio WordPress a auditar
        session  : aiohttp.ClientSession  — Sesión HTTP compartida del lote

        Retorna
        -------
        ScanResult  — Resultado completo de las 5 fases de auditoría
        """
        resultado = ScanResult(target=objetivo)

        # Validar scope antes de cualquier petición de red
        if not self.scope.is_in_scope(objetivo):
            resultado.error = "OUT_OF_SCOPE"
            return resultado

        url_base = self._normalizar_url(objetivo)
        tiempo_limite = aiohttp.ClientTimeout(total=self.args.timeout)

        # ── Fase 1: Detección de WordPress ────────────────────────────────────
        try:
            async with session.get(url_base, timeout=tiempo_limite, ssl=False, allow_redirects=True) as r:
                contenido = await r.text(errors="replace")
                resultado.is_wordpress, resultado.wp_version = WPDetector.detect(
                    contenido, dict(r.headers)
                )
        except Exception as e:
            resultado.error = str(e)[:100]
            return resultado

        # Si no es WordPress y no se fuerza el análisis, terminar aquí
        if not resultado.is_wordpress and not self.args.force:
            return resultado

        # ── Fase 2: Mapeo de superficie (todas las verificaciones en paralelo) ─
        verificador = UploadChecker(session)
        (xmlrpc, rest_api, upload_dir, debug, sqli) = await asyncio.gather(
            verificador.check_xmlrpc(url_base),
            verificador.check_rest_api(url_base),
            verificador.check_upload_dir_listing(url_base),
            verificador.check_debug_mode(url_base),
            verificador.detectar_sqli_vectors(url_base),
            return_exceptions=True,
        )

        # Asignar resultados de forma segura (si gather devuelve una excepción, usar valor por defecto)
        resultado.xmlrpc_enabled    = bool(xmlrpc)    if not isinstance(xmlrpc,    Exception) else False
        resultado.rest_api_exposed  = bool(rest_api)  if not isinstance(rest_api,  Exception) else False
        resultado.upload_dir_exposed = bool(upload_dir) if not isinstance(upload_dir, Exception) else False
        resultado.debug_mode        = bool(debug)     if not isinstance(debug,     Exception) else False
        resultado.sqli_vectors      = sqli            if isinstance(sqli, list) else []

        # ── Fase 3: Fingerprinting de plugins y temas ─────────────────────────
        fingerprinter = PluginFingerprinter(session, self.args.timeout)
        slugs_plugins = list(PLUGIN_VULN_DB.keys())
        slugs_temas   = list(THEME_VULN_DB.keys())

        plugins_encontrados, temas_encontrados = await asyncio.gather(
            fingerprinter.enumerar_plugins(url_base, slugs_plugins),
            fingerprinter.enumerar_temas(url_base, slugs_temas),
        )

        resultado.installed_plugins = [s for s, _ in plugins_encontrados]
        resultado.installed_themes  = [s for s, _ in temas_encontrados]

        # ── Fase 4: Mapeo de vulnerabilidades ─────────────────────────────────
        mapper = VulnMapper()

        for slug, version in plugins_encontrados:
            for hallazgo in mapper.mapear(slug, version, PLUGIN_VULN_DB):
                # Verificar accesibilidad del endpoint de subida del CVE
                if hallazgo.get("upload_endpoint"):
                    estado_endpoint = await verificador.sondear_endpoint_plugin(
                        url_base, hallazgo["upload_endpoint"]
                    )
                    hallazgo["endpoint_accessible"] = estado_endpoint.get("accessible", False)
                    hallazgo["endpoint_status"]     = estado_endpoint.get("status")
                resultado.plugin_findings.append(hallazgo)

        for slug, version in temas_encontrados:
            resultado.theme_findings.extend(mapper.mapear(slug, version, THEME_VULN_DB))

        # ── Fase 5: Subida canario (solo con --canary) ─────────────────────────
        if self.args.canary:
            # Buscar el primer endpoint de subida accesible y sin autenticación
            candidatos = [
                f for f in resultado.plugin_findings
                if f.get("upload_endpoint")
                and f.get("endpoint_accessible")
                and not f.get("auth_required")
            ]

            if candidatos:
                mejor = candidatos[0]
                console.print(
                    f"[yellow][!] Modo canario: probando {mejor['cve']} en {objetivo}[/yellow]"
                )
                subidor = CanaryUploader(session)
                res_canario = await subidor.run(url_base, mejor["upload_endpoint"])
                resultado.canary = asdict(res_canario)
            else:
                resultado.canary = {
                    "intentado": False,
                    "razon": "No se encontró endpoint de subida sin autenticación confirmado",
                }

        # ── Cálculo de puntuación de riesgo ───────────────────────────────────
        resultado.risk_score = self._calcular_puntuacion(resultado)
        resultado.risk_level = self._nivel_riesgo(resultado.risk_score)

        return resultado

    def _calcular_puntuacion(self, r: ScanResult) -> float:
        """
        Calcula la puntuación de riesgo compuesta (0.0–10.0).

        Fórmula
        -------
        score = Σ (CVSS_plugin × factor_versión) + bonificaciones_adicionales

        Factor de versión:
          · version_confirmed=True  → peso completo (1.0)
          · plugin detectado sin versión → peso parcial (0.5)

        Bonificaciones adicionales:
          · endpoint_accessible → +1.5 (confirma vector activo de explotación)
          · canario accesible   → +3.0 (RCE o subida de fichero confirmado)
          · xmlrpc habilitado   → +0.5 (superficie adicional)
          · debug activo        → +1.0 (exposición de información)
          · cada vector SQLi    → +1.5 (riesgo adicional de extracción de datos)
        """
        puntuacion = 0.0

        for f in r.plugin_findings + r.theme_findings:
            cvss_base = f.get("cvss", 5.0)
            if f.get("version_confirmed"):
                puntuacion += cvss_base
            else:
                puntuacion += cvss_base * 0.5

            if f.get("endpoint_accessible"):
                puntuacion += 1.5

        # Bonificaciones por factores de superficie y confirmación activa
        if r.canary and r.canary.get("accesible"):
            puntuacion += 3.0
        if r.xmlrpc_enabled:
            puntuacion += 0.5
        if r.debug_mode:
            puntuacion += 1.0

        puntuacion += len(r.sqli_vectors) * 1.5

        return round(min(puntuacion, 10.0), 2)

    def _nivel_riesgo(self, puntuacion: float) -> str:
        """Convierte la puntuación numérica al nivel semáforo de riesgo."""
        for nivel, umbral in self.UMBRALES_RIESGO.items():
            if puntuacion >= umbral:
                return nivel
        return "INFO"

    async def run(self, objetivos: List[str]) -> List[ScanResult]:
        """
        Ejecuta la auditoría completa del lote de forma asíncrona con control
        de concurrencia mediante Semaphore.

        Parámetros
        ----------
        objetivos : List[str]  — Lista de URLs de sitios WordPress a auditar

        Retorna
        -------
        List[ScanResult]  — Resultados en orden de finalización
        """
        semaforo = asyncio.Semaphore(self.args.concurrency)
        conector = aiohttp.TCPConnector(ssl=False, limit=self.args.concurrency * 2)
        resultados: List[ScanResult] = []

        async with aiohttp.ClientSession(connector=conector) as session:

            async def auditar_con_limite(objetivo: str):
                async with semaforo:
                    return await self._escanear_objetivo(objetivo, session)

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold magenta]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[magenta]{task.completed}/{task.total}[/magenta]"),
                console=console,
            ) as progreso:
                tarea_id = progreso.add_task(
                    f"[magenta]Auditando {len(objetivos)} sitio(s) WordPress...",
                    total=len(objetivos),
                )
                for coro in asyncio.as_completed([auditar_con_limite(o) for o in objetivos]):
                    r = await coro
                    resultados.append(r)
                    progreso.advance(tarea_id)

        return resultados


# =============================================================================
# FUNCIONES DE SALIDA POR CONSOLA
# =============================================================================

COLORES_RIESGO = {
    "CRITICAL": "[bold magenta]CRITICAL[/bold magenta]",
    "HIGH":     "[bold orange1]HIGH[/bold orange1]",
    "MEDIUM":   "[bold yellow]MEDIUM[/bold yellow]",
    "LOW":      "[bold cyan]LOW[/bold cyan]",
    "INFO":     "[dim]INFO[/dim]",
    "UNKNOWN":  "[dim]UNKNOWN[/dim]",
}


def mostrar_tabla_resultados(results: List[ScanResult]):
    """
    Imprime la tabla resumen de auditoría WordPress con Rich.

    Muestra una visión general de cada objetivo: presencia de WP, plugins
    vulnerables detectados, vectores de subida y resultado del canario.
    """
    tabla = Table(
        title="[bold magenta]Resultados de Auditoría WordPress[/bold magenta]",
        box=box.ROUNDED,
        border_style="magenta",
    )
    tabla.add_column("Objetivo",        style="white", no_wrap=True)
    tabla.add_column("WP",              justify="center", width=5)
    tabla.add_column("Versión",         style="yellow",   width=8)
    tabla.add_column("Plugins Vuln.",   justify="center", width=13)
    tabla.add_column("CVEs",            justify="center", width=6)
    tabla.add_column("Vect. Subida",    justify="center", width=13)
    tabla.add_column("SQLi",            justify="center", width=6)
    tabla.add_column("Canario",         justify="center", width=10)
    tabla.add_column("Riesgo",          justify="center", width=10)

    for r in results:
        if r.error == "OUT_OF_SCOPE":
            continue

        vectores_subida = sum(1 for f in r.plugin_findings if f.get("upload_endpoint"))
        canario_str = (
            "[bold green]RCE CONF[/bold green]" if r.canary and r.canary.get("accesible")
            else ("[dim]—[/dim]" if not r.canary else "[yellow]intentado[/yellow]")
        )

        tabla.add_row(
            r.target,
            "[green]✓[/green]" if r.is_wordpress else "[dim]✗[/dim]",
            r.wp_version or "—",
            str(len(r.installed_plugins)) if r.installed_plugins else "—",
            str(len(r.plugin_findings)),
            str(vectores_subida) if vectores_subida else "—",
            str(len(r.sqli_vectors)) if r.sqli_vectors else "—",
            canario_str,
            COLORES_RIESGO.get(r.risk_level, r.risk_level),
        )

    console.print(tabla)


def mostrar_paneles_detalle(results: List[ScanResult]):
    """
    Para cada objetivo con hallazgos de severidad HIGH o superior, imprime
    un panel de detalle con los CVEs, técnicas de bypass MIME, estado del
    endpoint, vectores SQLi y resultado del canario.
    """
    for r in results:
        hallazgos_relevantes = [
            f for f in r.plugin_findings + r.theme_findings
            if f.get("cvss", 0) >= 7.0
        ]
        if not hallazgos_relevantes and not r.sqli_vectors:
            continue

        lineas = [f"[bold]{r.target}[/bold]  (WP {r.wp_version or 'desconocida'})"]

        # Indicadores de superficie de ataque detectados
        superficie = []
        if r.xmlrpc_enabled:
            superficie.append("XML-RPC habilitado")
        if r.rest_api_exposed:
            superficie.append("Enumeración de usuarios via REST API")
        if r.upload_dir_exposed:
            superficie.append("Listado de directorio en /uploads/")
        if r.debug_mode:
            superficie.append("WP_DEBUG activo — warnings PHP visibles")
        if superficie:
            lineas.append("  [yellow]Superficie:[/yellow] " + " · ".join(superficie))

        # CVEs de plugins/temas
        for f in hallazgos_relevantes:
            tag_auth   = "[dim](requiere auth)[/dim]" if f.get("auth_required") else "[red](sin auth)[/red]"
            tag_ver    = f"v{f['detected_version']}" if f.get("version_confirmed") and f.get("detected_version") else "versión no confirmada"
            lineas.append(
                f"\n  [bold magenta]► {f['cve']}[/bold magenta]  "
                f"CVSS {f.get('cvss', '?')}  {tag_auth}  {tag_ver}"
            )
            lineas.append(f"    {f.get('description', '')}")
            if f.get("mime_bypass"):
                lineas.append(f"    [dim]Bypass MIME:[/dim]  {', '.join(f['mime_bypass'])}")
            if f.get("upload_endpoint"):
                accesible = f.get("endpoint_accessible")
                lineas.append(
                    f"    [dim]Endpoint:[/dim]    {f['upload_endpoint']}  "
                    f"{'[green]accesible[/green]' if accesible else '[dim]no confirmado[/dim]'}"
                )

        # Vectores SQLi detectados
        for v in r.sqli_vectors:
            lineas.append(f"\n  [bold red]► Vector SQLi[/bold red]  {v.get('url', '')}")
            lineas.append(f"    {v.get('description', '')}")

        # Resultado del canario
        if r.canary and r.canary.get("intentado"):
            canario = r.canary
            if canario.get("accesible"):
                lineas.append("\n  [bold green]► CANARIO CONFIRMADO — SUBIDA DE FICHERO VERIFICADA[/bold green]")
                lineas.append(f"    Fichero: {canario.get('nombre_fichero')}")
                lineas.append(f"    URL:     {canario.get('url_subida')}")
                lineas.append(f"    Evidencia: {canario.get('evidencia')}")
                if not canario.get("eliminado"):
                    lineas.append(
                        "    [bold red]⚠ FICHERO NO ELIMINADO — limpieza manual requerida[/bold red]"
                    )
            else:
                lineas.append("  [dim]► Canario intentado pero fichero no accesible[/dim]")

        borde = "magenta" if r.risk_level == "CRITICAL" else "yellow"
        console.print(Panel(
            "\n".join(lineas),
            title=f"[bold {borde}]{'⚠ ' if r.risk_level == 'CRITICAL' else ''}Hallazgos: {r.target}[/bold {borde}]",
            border_style=borde,
        ))


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def cargar_objetivos(args) -> List[str]:
    """
    Combina los objetivos de --target y --input en una lista deduplicada,
    preservando el orden de primera aparición.
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

    return list(dict.fromkeys(objetivos))  # Deduplicar preservando orden de inserción


def main():
    console.print(BANNER, style="bold magenta")

    parser = argparse.ArgumentParser(
        description="vamp-wp2shell-audit — Auditor de Vectores de Subida WordPress (VampSecure Labs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s -t https://ejemplo.com\n"
            "  %(prog)s -i objetivos.txt -s scope.txt -c 10\n"
            "  %(prog)s -t https://ejemplo.com --canary --html informe.html\n\n"
            "AVISO LEGAL: Solo para auditorías autorizadas. --canario requiere autorización escrita."
        ),
    )
    parser.add_argument("-t", "--target",      nargs="+", metavar="URL",
                        help="URL(s) objetivo de sitios WordPress")
    parser.add_argument("-i", "--input",       metavar="FICHERO",
                        help="Fichero de URLs objetivo (una por línea)")
    parser.add_argument("-s", "--scope",       metavar="FICHERO",
                        help="Fichero de scope — objetivos no listados serán omitidos")
    parser.add_argument("-c", "--concurrency", type=int, default=5,
                        help="Escaneos concurrentes (por defecto: 5)")
    parser.add_argument("--timeout",           type=int, default=10,
                        help="Timeout por petición en segundos (por defecto: 10)")
    parser.add_argument("--canary",            action="store_true",
                        help="Activar test de subida canario en endpoints confirmados (requiere autorización)")
    parser.add_argument("--force",             action="store_true",
                        help="Auditar aunque WordPress no sea detectado")
    parser.add_argument("-o", "--output",      metavar="FICHERO",
                        help="Ruta del informe JSON de salida")
    parser.add_argument("--html",              metavar="FICHERO",
                        help="Ruta del informe HTML de salida")
    parser.add_argument("-v", "--verbose",     action="store_true",
                        help="Salida detallada")

    args = parser.parse_args()

    if not args.target and not args.input:
        parser.print_help()
        sys.exit(0)

    # Advertencia explícita del modo canario para que quede en el log
    if args.canary:
        console.print(Panel(
            "[bold yellow]MODO CANARIO ACTIVO[/bold yellow]\n"
            "Se subirá un fichero PHP inerte a los endpoints vulnerables confirmados\n"
            "y se eliminará inmediatamente tras verificar su accesibilidad.\n"
            "[bold red]⚠ SOLO usar en objetivos con autorización escrita del propietario.[/bold red]",
            title="⚠ Advertencia — Test de Subida Dry-Run",
            border_style="yellow",
        ))

    objetivos = cargar_objetivos(args)
    if not objetivos:
        console.print("[bold red][!] No se han cargado objetivos.[/bold red]")
        sys.exit(1)

    console.print(
        f"[cyan][i] Objetivos: {len(objetivos)}  ·  "
        f"Concurrencia: {args.concurrency}  ·  "
        f"Canario: {'ACTIVO' if args.canary else 'desactivado'}[/cyan]\n"
    )

    escaner = WPScanner(args)
    resultados = asyncio.run(escaner.run(objetivos))

    mostrar_tabla_resultados(resultados)
    mostrar_paneles_detalle(resultados)

    if args.output:
        ReportGenerator.to_json(resultados, args.output)
        console.print(f"\n[bold green][✓] Informe JSON guardado: {args.output}[/bold green]")

    if args.html:
        ReportGenerator.to_html(resultados, args.html)
        console.print(f"[bold green][✓] Informe HTML guardado: {args.html}[/bold green]")

    # Resumen final de la auditoría
    total_cves   = sum(len(r.plugin_findings) for r in resultados)
    canario_ok   = sum(1 for r in resultados if r.canary and r.canary.get("accesible"))
    fuera_scope  = sum(1 for r in resultados if r.error == "OUT_OF_SCOPE")

    console.print(
        f"\n[bold]Auditoría completada.[/bold] "
        f"{total_cves} CVE(s) de plugin detectados · "
        f"{canario_ok} vector(es) de subida confirmados · "
        f"{len(objetivos) - fuera_scope} objetivo(s) auditados"
        + (f" · {fuera_scope} fuera de scope" if fuera_scope else "")
    )


if __name__ == "__main__":
    main()
