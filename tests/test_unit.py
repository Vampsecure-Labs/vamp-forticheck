# © VampSecure Studios — VampSecure Labs Security Research Division
"""
Tests unitarios para vamp-forticheck.
Cubre: VersionDetector.detect, VersionDetector.parse_version,
       CVEChecker.check_version_cves, ScopeValidator, FORTIOS_CVE_DB integridad,
       puntuación de riesgo y rangos de versiones afectadas.
"""

import sys
import os
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vamp_forticheck import (
    VersionDetector,
    CVEChecker,
    ScopeValidator,
    ScanResult,
    FORTIOS_CVE_DB,
)


# ---------------------------------------------------------------------------
# Tests de VersionDetector.detect
# ---------------------------------------------------------------------------

class TestVersionDetectorDetect:
    """Verifica la detección de FortiOS a partir de HTML y cabeceras."""

    def test_detecta_fortios_por_fgt_lang(self, html_fortios_705):
        """fgt_lang en el HTML indica FortiOS."""
        es_forti, _ = VersionDetector.detect(html_fortios_705, {})
        assert es_forti is True

    def test_extrae_version_705(self, html_fortios_705):
        """La versión 7.0.5 debe extraerse del HTML de login."""
        _, version = VersionDetector.detect(html_fortios_705, {})
        assert version == "7.0.5"

    def test_no_detecta_sin_indicadores(self, html_sin_fortios, cabeceras_vacias):
        """HTML genérico sin indicadores FortiOS → (False, None)."""
        es_forti, version = VersionDetector.detect(html_sin_fortios, cabeceras_vacias)
        assert es_forti is False
        assert version is None

    def test_detecta_por_cabecera_sslvpn(self):
        """Indicador SSL-VPN en cabecera → FortiOS detectado."""
        _, version = VersionDetector.detect("", {"Server": "SSL-VPN FortiGate"})
        es_forti, _ = VersionDetector.detect("", {"Server": "SSL-VPN FortiGate"})
        assert es_forti is True

    def test_detecta_por_fortigate_en_html(self):
        """FortiGate en el HTML → detectado."""
        html = "<title>FortiGate Login</title>"
        es_forti, _ = VersionDetector.detect(html, {})
        assert es_forti is True

    def test_version_none_si_no_hay_indicador(self):
        """FortiOS detectado pero sin versión → version None."""
        html = '<script src="/sslvpn/portal.css"></script>'
        _, version = VersionDetector.detect(html, {})
        assert version is None


# ---------------------------------------------------------------------------
# Tests de VersionDetector.parse_version
# ---------------------------------------------------------------------------

class TestParseVersion:
    """Verifica la conversión de cadenas de versión a tuplas."""

    def test_version_tres_partes(self):
        assert VersionDetector.parse_version("7.0.5") == (7, 0, 5)

    def test_version_dos_partes(self):
        assert VersionDetector.parse_version("6.4") == (6, 4, 0)

    def test_version_invalida_devuelve_none(self):
        assert VersionDetector.parse_version("invalida") is None

    def test_version_vacia_devuelve_none(self):
        assert VersionDetector.parse_version("") is None

    def test_comparacion_numerica_correcta(self):
        """(7, 0, 10) > (7, 0, 9) — comparación numérica, no lexicográfica."""
        v10 = VersionDetector.parse_version("7.0.10")
        v9 = VersionDetector.parse_version("7.0.9")
        assert v10 > v9


# ---------------------------------------------------------------------------
# Tests de CVEChecker.check_version_cves
# ---------------------------------------------------------------------------

class TestCheckVersionCVEs:
    """Verifica la comparación de versiones contra rangos de CVEs."""

    def test_version_en_rango_cve_2022_40684(self, cve_checker_mock):
        """7.0.5 está en el rango 7.0.0–7.0.6 de CVE-2022-40684."""
        findings = cve_checker_mock.check_version_cves("7.0.5")
        cves = [f["cve"] for f in findings]
        assert "CVE-2022-40684" in cves

    def test_version_fuera_de_rango_cve_2022_40684(self, cve_checker_mock):
        """7.0.7 (parcheado) no está en el rango afectado de CVE-2022-40684."""
        findings = cve_checker_mock.check_version_cves("7.0.7")
        cves_40684 = [f for f in findings if f["cve"] == "CVE-2022-40684"]
        assert len(cves_40684) == 0

    def test_version_none_retorna_lista_vacia(self, cve_checker_mock):
        """Sin versión detectada → sin findings."""
        findings = cve_checker_mock.check_version_cves(None)
        assert findings == []

    def test_version_no_afectada_retorna_lista_vacia(self, cve_checker_mock):
        """Versión reciente no afectada por ningún CVE → lista vacía."""
        findings = cve_checker_mock.check_version_cves("7.4.99")
        assert findings == []

    def test_method_es_version_match(self, cve_checker_mock):
        """Todos los findings por versión deben tener method='version_match'."""
        findings = cve_checker_mock.check_version_cves("7.0.5")
        for f in findings:
            assert f["method"] == "version_match"

    def test_confirmed_es_false(self, cve_checker_mock):
        """Findings por comparación de versión → confirmed=False."""
        findings = cve_checker_mock.check_version_cves("7.0.5")
        for f in findings:
            assert f["confirmed"] is False

    def test_version_en_rango_cve_2018_13379(self, cve_checker_mock):
        """6.0.3 en rango 6.0.0–6.0.4 de CVE-2018-13379."""
        findings = cve_checker_mock.check_version_cves("6.0.3")
        cves = [f["cve"] for f in findings]
        assert "CVE-2018-13379" in cves

    def test_version_en_rango_cve_2023_27997(self, cve_checker_mock):
        """7.2.3 en rango 7.2.0–7.2.4 de CVE-2023-27997."""
        findings = cve_checker_mock.check_version_cves("7.2.3")
        cves = [f["cve"] for f in findings]
        assert "CVE-2023-27997" in cves


# ---------------------------------------------------------------------------
# Tests de ScopeValidator
# ---------------------------------------------------------------------------

class TestScopeValidator:
    """Verifica la validación de objetivos contra el alcance definido."""

    def test_sin_scope_file_todo_valido(self):
        """Sin fichero de scope, todos los objetivos son válidos."""
        v = ScopeValidator(scope_file=None)
        assert v.is_in_scope("192.168.1.1") is True
        assert v.is_in_scope("vpn.example.com") is True

    def test_scope_inactivo_sin_fichero(self):
        """Sin fichero de scope, active=False."""
        v = ScopeValidator(scope_file=None)
        assert v.active is False


# ---------------------------------------------------------------------------
# Tests de integridad de FORTIOS_CVE_DB
# ---------------------------------------------------------------------------

class TestFortiOSCVEDB:
    """Verifica la estructura e integridad de la base de datos de CVEs."""

    def test_cve_2022_40684_presente(self):
        assert "CVE-2022-40684" in FORTIOS_CVE_DB

    def test_todos_tienen_cvss(self):
        for cve_id, meta in FORTIOS_CVE_DB.items():
            assert "cvss" in meta, f"Falta cvss en {cve_id}"
            assert isinstance(meta["cvss"], (int, float))

    def test_todos_tienen_severity(self):
        niveles_validos = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for cve_id, meta in FORTIOS_CVE_DB.items():
            assert meta.get("severity") in niveles_validos

    def test_cve_2022_40684_cvss_98(self):
        assert FORTIOS_CVE_DB["CVE-2022-40684"]["cvss"] == 9.8

    def test_cve_2024_21762_cvss_96(self):
        assert FORTIOS_CVE_DB["CVE-2024-21762"]["cvss"] == 9.6

    def test_affected_versions_son_tuplas(self):
        """Los rangos de versiones deben ser pares de tuplas de 3 enteros."""
        for cve_id, meta in FORTIOS_CVE_DB.items():
            for minimo, maximo in meta.get("affected_versions", []):
                assert len(minimo) == 3
                assert len(maximo) == 3

    def test_contiene_al_menos_4_cves(self):
        assert len(FORTIOS_CVE_DB) >= 4
