# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Fixtures compartidos para los tests de vamp-forticheck.
Proporciona HTML/cabeceras de FortiOS, ScanResult simulados y
mocks de aiohttp.ClientSession para tests asíncronos.
"""

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_forticheck import (
    CVEChecker,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Fixtures de HTML FortiOS
# ---------------------------------------------------------------------------

@pytest.fixture()
def html_fortios_705():
    """HTML típico de la página de login de FortiOS 7.0.5."""
    return """<!DOCTYPE html>
<html>
<head>
<title>FortiGate — Autenticación</title>
<script src="/fgt_lang?lang=en"></script>
<link rel="stylesheet" href="/sslvpn/portal.css" />
</head>
<body id="fgt-gui">
<p>FortiGate v7.0.5 SSL-VPN Portal</p>
<p>Copyright Fortinet Inc.</p>
</body>
</html>"""


@pytest.fixture()
def html_sin_fortios():
    """HTML de un servidor genérico sin indicadores FortiOS."""
    return """<!DOCTYPE html>
<html>
<head><title>Router Cisco</title></head>
<body>
<p>Cisco IOS Web Interface</p>
</body>
</html>"""


@pytest.fixture()
def cabeceras_fortios():
    """Cabeceras HTTP típicas de un FortiGate."""
    return {
        "Server": "xxxxxxxx-xxxxx",
        "Content-Type": "text/html; charset=utf-8",
        "X-Frame-Options": "SAMEORIGIN",
        "FGSP-session": "",
    }


@pytest.fixture()
def cabeceras_vacias():
    """Cabeceras genéricas sin indicadores de FortiOS."""
    return {"Content-Type": "text/html", "Server": "nginx"}


# ---------------------------------------------------------------------------
# Fixtures de ScanResult
# ---------------------------------------------------------------------------

@pytest.fixture()
def scan_result_fortios_705():
    """ScanResult de un FortiGate detectado con versión 7.0.5."""
    r = ScanResult(target="https://192.168.1.1")
    r.is_fortios = True
    r.detected_version = "7.0.5"
    r.banner = "FortiGate"
    r.cve_findings = []
    r.exposure_vectors = []
    r.risk_score = 0.0
    r.risk_level = "UNKNOWN"
    r.error = None
    return r


@pytest.fixture()
def scan_result_sin_fortios():
    """ScanResult de un servidor que NO es FortiOS."""
    r = ScanResult(target="https://192.168.1.2")
    r.is_fortios = False
    r.detected_version = None
    r.banner = None
    r.cve_findings = []
    r.exposure_vectors = []
    r.risk_score = 0.0
    r.risk_level = "UNKNOWN"
    r.error = None
    return r


# ---------------------------------------------------------------------------
# Fixture de CVEChecker con sesión mock
# ---------------------------------------------------------------------------

@pytest.fixture()
def cve_checker_mock():
    """CVEChecker con sesión aiohttp simulada."""
    session = MagicMock()
    session.get = MagicMock()
    checker = CVEChecker(session=session, timeout=5)
    return checker
