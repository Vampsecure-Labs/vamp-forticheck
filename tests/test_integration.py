# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests de integración para vamp-forticheck.
Simula respuestas HTTP de un FortiGate con aiohttp mock para verificar
el flujo completo: detect → versión → CVE check → risk scoring.
"""

import sys
import os
import asyncio
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_forticheck import (
    VersionDetector,
    CVEChecker,
    ScanResult,
    FORTIOS_CVE_DB,
)


# ---------------------------------------------------------------------------
# Helpers: construir respuestas aiohttp mock
# ---------------------------------------------------------------------------

def _mock_respuesta_http(status: int, cuerpo: str, cabeceras: dict = None):
    """Crea un contexto mock de aiohttp que devuelve una respuesta HTTP simulada."""
    respuesta = AsyncMock()
    respuesta.status = status
    respuesta.text = AsyncMock(return_value=cuerpo)
    respuesta.headers = cabeceras or {}
    respuesta.read = AsyncMock(return_value=cuerpo.encode("utf-8"))

    @asynccontextmanager
    async def _ctx(*args, **kwargs):
        yield respuesta

    return _ctx


# ---------------------------------------------------------------------------
# Test 1: Detección de FortiOS + extracción de versión
# ---------------------------------------------------------------------------

class TestIntegracionDeteccion:
    """Verifica la detección y versión extraídas desde HTML real."""

    def test_html_705_detecta_y_extrae(self, html_fortios_705, cabeceras_fortios):
        """Flujo completo: HTML FortiOS 7.0.5 → detectado + versión 7.0.5."""
        es_forti, version = VersionDetector.detect(html_fortios_705, cabeceras_fortios)
        assert es_forti is True
        assert version == "7.0.5"

    def test_html_sin_forti_no_detecta(self, html_sin_fortios, cabeceras_vacias):
        """HTML genérico → no detectado."""
        es_forti, version = VersionDetector.detect(html_sin_fortios, cabeceras_vacias)
        assert es_forti is False
        assert version is None

    def test_cabeceras_con_sslvpn_detecta(self):
        """SSL-VPN en cabecera Server → detectado."""
        es_forti, _ = VersionDetector.detect("", {"Server": "SSLVPN FortiOS"})
        assert es_forti is True


# ---------------------------------------------------------------------------
# Test 2: CVEChecker.check_version_cves — flujo completo por versión
# ---------------------------------------------------------------------------

class TestIntegracionVersionCVEs:
    """Verifica el mapeo de versiones a CVEs en escenarios realistas."""

    def test_7_0_5_mapea_a_cve_2022_40684(self, cve_checker_mock):
        """7.0.5 está en el rango 7.0.0–7.0.6 → CVE-2022-40684."""
        findings = cve_checker_mock.check_version_cves("7.0.5")
        assert any(f["cve"] == "CVE-2022-40684" for f in findings)

    def test_6_0_3_mapea_a_cve_2018_13379(self, cve_checker_mock):
        """6.0.3 afectado por CVE-2018-13379."""
        findings = cve_checker_mock.check_version_cves("6.0.3")
        assert any(f["cve"] == "CVE-2018-13379" for f in findings)

    def test_7_2_3_mapea_a_cve_2023_27997(self, cve_checker_mock):
        """7.2.3 afectado por CVE-2023-27997 (XORtigate heap overflow)."""
        findings = cve_checker_mock.check_version_cves("7.2.3")
        assert any(f["cve"] == "CVE-2023-27997" for f in findings)

    def test_version_reciente_sin_findings(self, cve_checker_mock):
        """Versión hipotética reciente sin CVEs conocidos."""
        findings = cve_checker_mock.check_version_cves("8.0.0")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Test 3: CVEChecker.check_cve_2022_40684 con mock HTTP
# ---------------------------------------------------------------------------

class TestIntegracionCVE40684:
    """Verifica la sonda activa de CVE-2022-40684 con respuestas HTTP simuladas."""

    def test_respuesta_200_con_results_confirma_cve(self, cve_checker_mock):
        """HTTP 200 con '\"results\"' → confirmed=True."""
        cuerpo_admin = '{"results": [{"admin": "admin", "type": "super_admin"}]}'
        ctx_mock = _mock_respuesta_http(200, cuerpo_admin)
        cve_checker_mock.session.get = ctx_mock

        resultado = asyncio.run(
            cve_checker_mock.check_cve_2022_40684("https://192.168.1.1")
        )
        assert resultado["confirmed"] is True
        assert resultado["cve"] == "CVE-2022-40684"

    def test_respuesta_401_no_confirma(self, cve_checker_mock):
        """HTTP 401 → no confirmado (protegido o parcheado)."""
        ctx_mock = _mock_respuesta_http(401, "Unauthorized")
        cve_checker_mock.session.get = ctx_mock

        resultado = asyncio.run(
            cve_checker_mock.check_cve_2022_40684("https://192.168.1.1")
        )
        assert resultado["confirmed"] is False

    def test_respuesta_200_sin_datos_admin_no_confirma(self, cve_checker_mock):
        """HTTP 200 con HTML genérico sin datos admin → no confirmado."""
        ctx_mock = _mock_respuesta_http(200, "<html>Forbidden</html>")
        cve_checker_mock.session.get = ctx_mock

        resultado = asyncio.run(
            cve_checker_mock.check_cve_2022_40684("https://192.168.1.1")
        )
        assert resultado["confirmed"] is False
