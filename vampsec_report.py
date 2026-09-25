#!/usr/bin/env python3
"""
vampsec_report.py — Módulo de Informes Unificado VampSecure Labs
=================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas

DESCRIPCIÓN
-----------
Módulo compartido de generación de informes para todas las herramientas
del toolkit VampSecure Labs. Proporciona una estructura de datos y formatos
de salida unificados para la entrega profesional de resultados a clientes.

  · Finding       — estructura normalizada de un hallazgo de seguridad
  · ReportMeta    — metadatos del engagement (cliente, auditor, scope)
  · VampSecReport — clase principal con métodos de exportación:
      · to_json()        — JSON estructurado (esquema estándar VSL)
      · to_markdown()    — Markdown para wikis y sistemas de tickets
      · to_html_client() — HTML profesional light para entrega al cliente
      · to_pdf()         — PDF nativo vía fpdf2 para entrega al cliente

DEPENDENCIAS
------------
  Requeridas : stdlib únicamente
  Opcionales : fpdf2 >= 2.7.0  (solo para to_pdf())
               pip install fpdf2

INTEGRACIÓN
-----------
Copiar este fichero al directorio raíz de cada herramienta. No se
distribuye como paquete independiente para mantener la autonomía de cada
repositorio.

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Mapas de severidad y paletas de color
# ---------------------------------------------------------------------------

# Orden de severidad de mayor a menor (usado en la ordenación de findings)
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

# Colores tema claro/profesional para informe de cliente (hex CSS)
_LIGHT_BG: Dict[str, str] = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#d35400",
    "MEDIUM":   "#d4ac0d",
    "LOW":      "#2980b9",
    "INFO":     "#7f8c8d",
    "UNKNOWN":  "#95a5a6",
}

# Color del texto sobre el badge de cada severidad
_LIGHT_TEXT: Dict[str, str] = {
    "CRITICAL": "#ffffff",
    "HIGH":     "#ffffff",
    "MEDIUM":   "#2c3e50",
    "LOW":      "#ffffff",
    "INFO":     "#ffffff",
    "UNKNOWN":  "#ffffff",
}

# Tuplas RGB para fpdf2 (fondo badge)
_PDF_BG: Dict[str, tuple] = {
    "CRITICAL": (192, 57, 43),
    "HIGH":     (211, 84, 0),
    "MEDIUM":   (212, 172, 13),
    "LOW":      (41, 128, 185),
    "INFO":     (127, 140, 141),
    "UNKNOWN":  (149, 165, 166),
}

# Tuplas RGB para el texto sobre el badge PDF
_PDF_FG: Dict[str, tuple] = {
    "CRITICAL": (255, 255, 255),
    "HIGH":     (255, 255, 255),
    "MEDIUM":   (44, 62, 80),
    "LOW":      (255, 255, 255),
    "INFO":     (255, 255, 255),
    "UNKNOWN":  (255, 255, 255),
}


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Representa un único hallazgo de seguridad en formato normalizado VSL.

    Campos obligatorios
    -------------------
    id          : Identificador único en formato PREFIX-NNN (p.ej. FTC-001)
    title       : Título corto del hallazgo (recomendado: < 80 caracteres)
    severity    : CRITICAL | HIGH | MEDIUM | LOW | INFO
    description : Descripción técnica detallada del problema
    evidence    : Prueba técnica concreta (respuesta HTTP, versión, hash…)
    affected    : Activo, host, endpoint o fichero afectado
    remediation : Acciones concretas de mitigación o corrección

    Campos opcionales
    -----------------
    cvss        : Puntuación CVSS base 0.0–10.0
    cve         : ID CVE si aplica (p.ej. CVE-2024-3400)
    references  : URLs de advisories, RFCs o documentación técnica
    tags        : Etiquetas para agrupación temática
    """

    id          : str
    title       : str
    severity    : str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description : str
    evidence    : str
    affected    : str
    remediation : str
    cvss        : Optional[float] = None
    cve         : Optional[str]   = None
    references  : List[str]       = field(default_factory=list)
    tags        : List[str]       = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "INFO"


@dataclass
class ReportMeta:
    """
    Metadatos del engagement de auditoría incluidos en todos los informes.

    Attributes
    ----------
    tool         : Nombre de la herramienta (p.ej. "vamp-forticheck")
    tool_version : Versión de la herramienta (p.ej. "2.0")
    client       : Nombre del cliente (aparece en portada y cabecera)
    engagement   : Nombre o referencia del engagement
    auditor      : Nombre del auditor o equipo
    scope        : Descripción del alcance del análisis
    generated    : Fecha/hora de generación ISO-8601 UTC; auto si vacío
    """

    tool         : str
    tool_version : str
    client       : str = "Confidencial"
    engagement   : str = ""
    auditor      : str = "VampSecure Labs — Security Research Division"
    scope        : str = ""
    generated    : str = ""

    def __post_init__(self) -> None:
        if not self.generated:
            self.generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Clase principal de generación de informes
# ---------------------------------------------------------------------------

class VampSecReport:
    """
    Generador de informes unificado para el toolkit VampSecure Labs.

    Recibe los metadatos del engagement y la lista de hallazgos en formato
    normalizado Finding y puede exportar en cuatro formatos:

      · JSON          — esquema VSL estándar (machine-readable)
      · Markdown      — para wikis, sistemas de tickets, README de engagement
      · HTML cliente  — tema claro/profesional para entrega al cliente
      · PDF           — documento PDF nativo para entrega al cliente (fpdf2)

    Los findings se ordenan automáticamente por severidad decreciente.

    Ejemplo de uso
    --------------
    >>> from vampsec_report import Finding, ReportMeta, VampSecReport
    >>> meta = ReportMeta(tool="vamp-forticheck", tool_version="2.0",
    ...                   client="AcmeCorp S.A.", engagement="Pentest-2026-07")
    >>> findings = [
    ...     Finding(id="FTC-001", title="Path traversal SSL-VPN", severity="CRITICAL",
    ...             description="...", evidence="...", affected="vpn.acme.com",
    ...             remediation="...", cve="CVE-2018-13379", cvss=9.8),
    ... ]
    >>> report = VampSecReport(meta, findings)
    >>> report.to_html_client("informe_cliente.html")
    >>> report.to_pdf("informe_cliente.pdf")        # requiere fpdf2
    """

    # Versión del esquema JSON VSL — incrementar si cambia la estructura
    SCHEMA_VERSION = "1.0"
    BRAND          = "VampSecure Labs"
    BRAND_FULL     = "VampSecure Labs — Security Research Division"
    COPYRIGHT      = "© VampSecure Studios. Todos los derechos reservados."
    CONFIDENTIAL   = "CONFIDENCIAL — Uso exclusivo del cliente destinatario."

    def __init__(self, meta: ReportMeta, findings: List[Finding]) -> None:
        self.meta     = meta
        self.findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # ── Estadísticas de resumen ────────────────────────────────────────────

    def _stats(self) -> Dict[str, int]:
        """Devuelve el conteo de findings por severidad ordenado de mayor a menor."""
        counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    # ── JSON ───────────────────────────────────────────────────────────────

    def to_json(self, path: str) -> None:
        """
        Exporta el informe como JSON con esquema estándar VSL.

        Estructura:
          schema_version · generated · meta · summary.by_severity ·
          summary.total · findings[]
        """
        stats = self._stats()
        datos = {
            "schema_version": self.SCHEMA_VERSION,
            "generated":      self.meta.generated,
            "meta": {
                "tool":         self.meta.tool,
                "tool_version": self.meta.tool_version,
                "client":       self.meta.client,
                "engagement":   self.meta.engagement,
                "auditor":      self.meta.auditor,
                "scope":        self.meta.scope,
            },
            "summary": {
                "total":       len(self.findings),
                "by_severity": stats,
            },
            "findings": [asdict(f) for f in self.findings],
        }
        Path(path).write_text(json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8")

    # ── Markdown ───────────────────────────────────────────────────────────

    def to_markdown(self, path: str) -> None:
        """
        Exporta el informe en formato Markdown.

        Incluye resumen ejecutivo con tabla de severidades y hallazgos
        detallados con descripción, evidencia y remediación.
        """
        stats  = self._stats()
        lineas = [
            f"# Informe de Seguridad — {self.meta.client}",
            "",
            f"**Herramienta:** {self.meta.tool} v{self.meta.tool_version}  ",
            f"**Auditor:** {self.meta.auditor}  ",
            f"**Engagement:** {self.meta.engagement or '—'}  ",
            f"**Generado:** {self.meta.generated}  ",
            f"**Scope:** {self.meta.scope or '—'}",
            "",
            f"> {self.CONFIDENTIAL}",
            "",
            "---",
            "",
            "## Resumen Ejecutivo",
            "",
            "| Severidad | Hallazgos |",
            "|-----------|-----------|",
        ]
        for sev in SEVERITY_ORDER:
            if stats[sev]:
                lineas.append(f"| {sev} | {stats[sev]} |")
        lineas += [
            f"| **TOTAL** | **{len(self.findings)}** |",
            "",
            "---",
            "",
            "## Hallazgos",
            "",
        ]
        for f in self.findings:
            cvss_str = f" · CVSS {f.cvss:.1f}" if f.cvss is not None else ""
            cve_str  = f" · {f.cve}" if f.cve else ""
            lineas += [
                f"### {f.id} — {f.title}",
                "",
                f"**Severidad:** {f.severity}{cvss_str}{cve_str}  ",
                f"**Afectado:** `{f.affected}`",
                "",
                "**Descripción:**  ",
                f.description,
                "",
                "**Evidencia:**  ",
                "```",
                f.evidence,
                "```",
                "",
                "**Remediación:**  ",
                f.remediation,
                "",
            ]
            if f.references:
                lineas.append("**Referencias:**  ")
                for ref in f.references:
                    lineas.append(f"- {ref}")
                lineas.append("")
            lineas.append("---")
            lineas.append("")
        lineas += [
            f"*{self.BRAND_FULL}*  ",
            f"*{self.COPYRIGHT}*  ",
            f"*Generado: {self.meta.generated}*",
        ]
        Path(path).write_text("\n".join(lineas), encoding="utf-8")

    # ── HTML cliente (tema claro/profesional) ──────────────────────────────

    def to_html_client(self, path: str) -> None:
        """
        Genera informe HTML con tema claro/profesional para entrega al cliente.

        Características:
          · Fondo blanco, tipografía oscura, paleta VampSecure (rojo #c0392b)
          · Portada virtual con datos del engagement
          · Resumen ejecutivo con distribución de riesgos en barras
          · Tabla de hallazgos con código de color por severidad
          · Tarjetas de hallazgo detallado con evidencia y remediación
          · Marca de agua CSS «CONFIDENCIAL» en todas las páginas
          · @media print para impresión directa a PDF desde el navegador
          · Completamente standalone: sin CDN ni dependencias externas
        """
        stats    = self._stats()
        filas    = self._filas_tabla()
        detalles = self._tarjetas_hallazgo()
        barras   = self._barras_riesgo(stats)
        kpis     = " ".join(
            f'<div class="kpi"><div class="kv" style="color:{_LIGHT_BG[s]}">{v}</div>'
            f'<div class="kl">{s}</div></div>'
            for s, v in stats.items() if v > 0
        )
        badge_css = " ".join(
            f'.sev-{s.lower()}{{background:{_LIGHT_BG[s]};color:{_LIGHT_TEXT[s]}}}'
            for s in _LIGHT_BG
        )

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de Seguridad — {self.meta.client} — {self.meta.generated[:10]}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
        background:#f4f4f8;color:#1a1a2e;line-height:1.65;font-size:14px}}
  a{{color:#2980b9;text-decoration:none}}
  code{{font-family:'Courier New',monospace;background:#f0f0f5;
        padding:1px 5px;border-radius:3px;font-size:.88em}}
  pre{{background:#f4f4f8;border:1px solid #dde;border-radius:4px;
       padding:10px 12px;font-size:.8em;white-space:pre-wrap;
       word-break:break-all;line-height:1.5;font-family:'Courier New',monospace}}
  .wrap{{max-width:980px;margin:0 auto;background:#fff;
         box-shadow:0 2px 16px rgba(0,0,0,.09)}}

  /* Portada */
  .portada{{background:linear-gradient(140deg,#1a1a2e 0%,#8b0000 60%,#c0392b 100%);
            color:#fff;padding:56px 48px 48px;position:relative;overflow:hidden;
            page-break-after:always}}
  .portada::before{{content:"";position:absolute;top:-60px;right:-60px;
                    width:260px;height:260px;border-radius:50%;
                    background:rgba(255,255,255,.04)}}
  .portada-logo{{font-size:.78em;letter-spacing:3px;text-transform:uppercase;
                 opacity:.65;margin-bottom:36px}}
  .portada-titulo{{font-size:1.9em;font-weight:700;letter-spacing:.5px;margin-bottom:4px}}
  .portada-sub{{font-size:.95em;opacity:.7;margin-bottom:32px}}
  .portada-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:.83em}}
  .portada-item span{{display:block;opacity:.55;font-size:.78em;
                      text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px}}
  .portada-item strong{{font-weight:600}}
  .portada-item.full{{grid-column:1/-1}}
  .conf-badge{{position:absolute;top:20px;right:28px;font-size:.7em;
               letter-spacing:2px;border:1px solid rgba(255,255,255,.3);
               padding:3px 8px;border-radius:3px;opacity:.6;text-transform:uppercase}}

  /* Secciones */
  .sec{{padding:30px 48px;border-bottom:1px solid #eef}}
  .sec:last-child{{border-bottom:none}}
  .sec-title{{font-size:1em;font-weight:700;color:#c0392b;text-transform:uppercase;
              letter-spacing:.6px;margin-bottom:18px;display:flex;
              align-items:center;gap:10px}}
  .sec-title::after{{content:'';flex:1;height:1px;background:#eef}}

  /* KPIs */
  .kpis{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}}
  .kpi{{background:#f8f8fa;border:1px solid #e5e5ef;border-radius:6px;
        padding:14px 20px;min-width:110px;text-align:center;
        border-top:3px solid #c0392b}}
  .kv{{font-size:2em;font-weight:700;color:#1a1a2e}}
  .kl{{font-size:.7em;color:#999;text-transform:uppercase;letter-spacing:.4px;margin-top:2px}}

  /* Barras de riesgo */
  .bars{{display:flex;flex-direction:column;gap:9px;margin-bottom:22px}}
  .bar-row{{display:flex;align-items:center;gap:10px}}
  .bar-track{{flex:1;background:#eef0f5;border-radius:3px;height:16px;overflow:hidden}}
  .bar-fill{{height:100%;border-radius:3px}}
  .bar-count{{font-size:.8em;color:#aaa;width:22px;text-align:right}}

  /* Badges de severidad */
  .badge{{display:inline-block;padding:2px 8px;border-radius:3px;
          font-size:.74em;font-weight:700;letter-spacing:.3px}}
  {badge_css}

  /* Tabla */
  table{{width:100%;border-collapse:collapse;font-size:.84em}}
  th{{background:#f7f7fa;color:#666;padding:8px 10px;text-align:left;
      border-bottom:2px solid #e8e8ef;font-size:.76em;text-transform:uppercase;
      letter-spacing:.4px;font-weight:700}}
  td{{padding:8px 10px;border-bottom:1px solid #f0f0f5;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#fafafa}}

  /* Tarjetas de hallazgo */
  .card{{background:#fff;border:1px solid #e5e5ef;border-radius:6px;
         margin:14px 0;overflow:hidden;page-break-inside:avoid}}
  .card-head{{padding:13px 18px;border-bottom:1px solid #f0f0f5;
              display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
  .card-id{{font-size:.78em;color:#999;font-family:'Courier New',monospace;font-weight:600}}
  .card-name{{font-weight:700;flex:1;color:#1a1a2e}}
  .card-body{{padding:16px 18px;display:grid;
              grid-template-columns:1fr 1fr;gap:16px}}
  .card-body.solo{{grid-template-columns:1fr}}
  .fld{{}}
  .fld-lbl{{font-size:.7em;color:#bbb;text-transform:uppercase;
            letter-spacing:.5px;margin-bottom:4px;font-weight:700}}
  .fld-val{{font-size:.85em;color:#2c3e50;line-height:1.6}}
  .card-evi{{padding:0 18px 14px}}
  .card-rem{{padding:14px 18px;background:#f9fff8;border-top:1px solid #eef5ee}}
  .card-refs{{padding:8px 18px;background:#f8f8fa;border-top:1px solid #eee;
              font-size:.76em}}

  /* Marca de agua */
  body::before{{content:"CONFIDENCIAL";position:fixed;top:50%;left:50%;
                transform:translate(-50%,-50%) rotate(-35deg);
                font-size:7em;color:rgba(192,57,43,.035);font-weight:900;
                letter-spacing:8px;pointer-events:none;z-index:0;white-space:nowrap}}

  /* Pie */
  .pie{{background:#f7f7fa;border-top:1px solid #e8e8ef;padding:14px 48px;
        font-size:.72em;color:#bbb;display:flex;
        justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px}}
  .pie strong{{color:#aaa}}

  /* Print */
  @media print{{
    body{{background:#fff;font-size:11pt}}
    body::before{{display:none}}
    .wrap{{box-shadow:none;max-width:100%}}
    .portada{{page-break-after:always;-webkit-print-color-adjust:exact;
              print-color-adjust:exact}}
    .card{{page-break-inside:avoid}}
    .sec{{padding:18px 32px}}
    .pie{{position:fixed;bottom:0;left:0;right:0;
          -webkit-print-color-adjust:exact;print-color-adjust:exact}}
    .badge,.bar-fill,.kpi{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  }}
</style>
</head>
<body>
<div class="wrap">

<!-- PORTADA -->
<div class="portada">
  <div class="conf-badge">Confidencial</div>
  <div class="portada-logo">&#9679; {self.BRAND}</div>
  <div class="portada-titulo">Informe de Auditoría de Seguridad</div>
  <div class="portada-sub">{self.meta.tool} v{self.meta.tool_version}</div>
  <div class="portada-grid">
    <div class="portada-item"><span>Cliente</span><strong>{self.meta.client}</strong></div>
    <div class="portada-item"><span>Engagement</span><strong>{self.meta.engagement or '—'}</strong></div>
    <div class="portada-item"><span>Auditor</span><strong>{self.meta.auditor}</strong></div>
    <div class="portada-item"><span>Fecha</span><strong>{self.meta.generated}</strong></div>
    <div class="portada-item full"><span>Scope / Alcance</span><strong>{self.meta.scope or '—'}</strong></div>
  </div>
</div>

<!-- RESUMEN EJECUTIVO -->
<div class="sec">
  <div class="sec-title">Resumen Ejecutivo</div>
  <div class="kpis">
    <div class="kpi"><div class="kv">{len(self.findings)}</div><div class="kl">Total</div></div>
    {kpis}
  </div>
  {barras}
</div>

<!-- TABLA DE HALLAZGOS -->
<div class="sec">
  <div class="sec-title">Tabla de Hallazgos</div>
  <table>
  <tr><th>#</th><th>ID</th><th>Hallazgo</th><th>Severidad</th><th>CVSS</th><th>Activo Afectado</th></tr>
  {filas}
  </table>
</div>

<!-- HALLAZGOS DETALLADOS -->
<div class="sec">
  <div class="sec-title">Hallazgos Detallados</div>
  {detalles}
</div>

<!-- PIE -->
<div class="pie">
  <span><strong>{self.BRAND_FULL}</strong> · {self.COPYRIGHT}</span>
  <span>{self.CONFIDENTIAL}</span>
</div>
</div>
</body>
</html>"""
        Path(path).write_text(html, encoding="utf-8")

    def _barras_riesgo(self, stats: Dict[str, int]) -> str:
        total = sum(stats.values()) or 1
        partes = ['<div class="bars">']
        for sev, count in stats.items():
            if not count:
                continue
            pct  = round(count / total * 100)
            color = _LIGHT_BG.get(sev, "#888")
            partes.append(
                f'<div class="bar-row">'
                f'<span class="badge sev-{sev.lower()}" style="width:90px;text-align:center">{sev}</span>'
                f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'
                f'<span class="bar-count">{count}</span>'
                f'</div>'
            )
        partes.append('</div>')
        return "\n".join(partes)

    def _filas_tabla(self) -> str:
        if not self.findings:
            return '<tr><td colspan="6" style="text-align:center;color:#bbb;padding:18px">Sin hallazgos</td></tr>'
        lineas = ""
        for i, f in enumerate(self.findings, 1):
            cvss_s = f"{f.cvss:.1f}" if f.cvss is not None else "—"
            cve_p  = f' <span style="font-size:.78em;color:#bbb">{f.cve}</span>' if f.cve else ""
            lineas += (
                f'<tr>'
                f'<td style="color:#ccc">{i}</td>'
                f'<td><code>{f.id}</code></td>'
                f'<td><strong>{f.title}</strong>{cve_p}</td>'
                f'<td><span class="badge sev-{f.severity.lower()}">{f.severity}</span></td>'
                f'<td style="text-align:center">{cvss_s}</td>'
                f'<td><code>{f.affected[:55]}</code></td>'
                f'</tr>\n'
            )
        return lineas

    def _tarjetas_hallazgo(self) -> str:
        if not self.findings:
            return '<p style="color:#bbb;text-align:center;padding:20px">Sin hallazgos detectados.</p>'
        partes = []
        for f in self.findings:
            border = _LIGHT_BG.get(f.severity, "#888")
            cvss_b = f'<span style="font-size:.77em;color:#aaa;margin-left:6px">CVSS {f.cvss:.1f}</span>' if f.cvss is not None else ""
            cve_b  = f'<span style="font-size:.77em;color:#aaa;margin-left:6px">{f.cve}</span>' if f.cve else ""
            refs_h = "".join(f'<a href="{r}">{r}</a>&nbsp; ' for r in f.references)

            grid_class = "card-body" if f.cve else "card-body solo"
            cve_cell   = (
                f'<div class="fld"><div class="fld-lbl">CVE</div>'
                f'<div class="fld-val">{f.cve}</div></div>'
            ) if f.cve else ""

            partes.append(
                f'<div class="card" style="border-left:4px solid {border}">'
                f'<div class="card-head">'
                f'  <span class="card-id">{f.id}</span>'
                f'  <span class="card-name">{f.title}</span>'
                f'  <span class="badge sev-{f.severity.lower()}">{f.severity}</span>'
                f'  {cvss_b}{cve_b}'
                f'</div>'
                f'<div class="{grid_class}">'
                f'  <div class="fld"><div class="fld-lbl">Activo afectado</div>'
                f'    <div class="fld-val"><code>{f.affected}</code></div></div>'
                f'  {cve_cell}'
                f'  <div class="fld" style="grid-column:1/-1">'
                f'    <div class="fld-lbl">Descripción</div>'
                f'    <div class="fld-val">{f.description}</div></div>'
                f'</div>'
                f'<div class="card-evi">'
                f'  <div class="fld-lbl">Evidencia técnica</div>'
                f'  <pre>{f.evidence}</pre>'
                f'</div>'
                f'<div class="card-rem">'
                f'  <div class="fld-lbl">Remediación</div>'
                f'  <div class="fld-val">{f.remediation}</div>'
                f'</div>'
                + (f'<div class="card-refs"><strong>Referencias:</strong> {refs_h}</div>' if refs_h else "")
                + f'</div>'
            )
        return "\n".join(partes)

    # ── PDF (requiere fpdf2) ───────────────────────────────────────────────

    def to_pdf(self, path: str) -> None:
        """
        Genera informe PDF profesional para entrega al cliente.

        Requiere: pip install fpdf2 >= 2.7.0

        Estructura del PDF:
          · Página 1  — portada con datos del engagement
          · Página 2  — resumen ejecutivo y tabla de hallazgos
          · Páginas N — un hallazgo por página con descripción,
                        evidencia y remediación
          · Cabecera y pie corporativo en todas las páginas excepto portada

        Lanza RuntimeError si fpdf2 no está instalado.
        """
        try:
            from fpdf import FPDF  # noqa: F401
        except ImportError:
            raise RuntimeError("fpdf2 no está instalado. Ejecuta: pip install fpdf2")

        pdf = self._crear_pdf()
        pdf.set_auto_page_break(auto=True, margin=22)

        self._pdf_portada(pdf)
        self._pdf_resumen(pdf)
        for f in self.findings:
            self._pdf_hallazgo(pdf, f)

        pdf.output(path)

    def _crear_pdf(self):
        """Instancia FPDF con cabecera y pie corporativos VampSecure Labs."""
        from fpdf import FPDF

        meta  = self.meta
        brand = self.BRAND

        class _PDF(FPDF):
            def header(self):
                if self.page_no() == 1:
                    return
                self.set_font("Helvetica", "B", 7)
                self.set_text_color(160, 160, 180)
                self.set_y(7)
                self.cell(0, 5, brand, align="L")
                self.set_font("Helvetica", "", 7)
                self.cell(0, 5, f"{meta.client}  ·  {meta.engagement or 'Informe'}", align="R")
                self.set_draw_color(220, 220, 235)
                self.line(10, 13, 200, 13)
                self.set_y(17)

            def footer(self):
                if self.page_no() == 1:
                    return
                self.set_y(-14)
                self.set_draw_color(220, 220, 235)
                self.line(10, self.get_y(), 200, self.get_y())
                self.ln(1)
                self.set_font("Helvetica", "I", 7)
                self.set_text_color(180, 180, 195)
                self.cell(
                    0, 5,
                    f"CONFIDENCIAL  ·  Página {self.page_no()}  ·  {meta.generated}",
                    align="C",
                )

        p = _PDF()
        p.set_margins(15, 22, 15)
        return p

    def _pdf_portada(self, pdf) -> None:
        """Renderiza la portada del PDF (página 1)."""
        pdf.add_page()
        # Fondo oscuro completo
        pdf.set_fill_color(26, 26, 46)
        pdf.rect(0, 0, 210, 297, "F")
        # Banda inferior roja
        pdf.set_fill_color(192, 57, 43)
        pdf.rect(0, 230, 210, 67, "F")

        # Logo/brand
        pdf.set_y(52)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(160, 160, 200)
        pdf.cell(0, 6, self.BRAND.upper(), align="C")
        pdf.ln(3)
        pdf.set_fill_color(192, 57, 43)
        pdf.rect(55, pdf.get_y(), 100, 1, "F")
        pdf.ln(16)

        # Título
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "INFORME DE AUDITORÍA", align="C")
        pdf.ln(9)
        pdf.set_font("Helvetica", "", 13)
        pdf.set_text_color(220, 220, 220)
        pdf.cell(0, 7, "DE SEGURIDAD", align="C")
        pdf.ln(5)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(170, 170, 190)
        pdf.cell(0, 7, f"{self.meta.tool} v{self.meta.tool_version}", align="C")

        # Cuadro de datos del engagement
        pdf.set_y(142)
        pdf.set_fill_color(38, 38, 65)
        pdf.rect(24, pdf.get_y(), 162, 76, "F")
        pdf.set_y(pdf.get_y() + 9)
        campos = [
            ("Cliente",    self.meta.client),
            ("Engagement", self.meta.engagement or "—"),
            ("Auditor",    self.meta.auditor),
            ("Fecha",      self.meta.generated),
            ("Scope",      self.meta.scope or "—"),
        ]
        for lbl, val in campos:
            pdf.set_x(34)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(140, 140, 170)
            pdf.cell(32, 5, lbl.upper(), align="L")
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(240, 240, 255)
            pdf.multi_cell(118, 5, str(val)[:65], align="L")

        # CONFIDENCIAL
        pdf.set_y(248)
        pdf.set_font("Helvetica", "I", 7.5)
        pdf.set_text_color(255, 200, 200)
        pdf.cell(0, 6, self.CONFIDENTIAL, align="C")

    def _pdf_resumen(self, pdf) -> None:
        """Renderiza el resumen ejecutivo y la tabla de hallazgos (página 2)."""
        pdf.add_page()
        stats = self._stats()

        # Título sección
        pdf.set_y(17)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(26, 26, 46)
        pdf.cell(0, 8, "RESUMEN EJECUTIVO", align="L")
        pdf.ln(3)
        pdf.set_draw_color(192, 57, 43)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(8)

        # Total de hallazgos
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 80, 100)
        pdf.cell(0, 6, f"Total de hallazgos identificados: {len(self.findings)}", align="L")
        pdf.ln(9)

        # Barras de distribución por severidad
        max_count = max(stats.values()) or 1
        for sev, count in stats.items():
            if not count:
                continue
            r, g, b = _PDF_BG.get(sev, (150, 150, 150))
            rt, gt, bt = _PDF_FG.get(sev, (255, 255, 255))
            pdf.set_x(15)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(rt, gt, bt)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.cell(26, 7, sev, fill=True, align="C")
            bar_w = max(2, int(count / max_count * 130))
            pdf.set_fill_color(r, g, b)
            pdf.cell(bar_w, 7, "", fill=True)
            pdf.set_fill_color(230, 230, 238)
            pdf.cell(130 - bar_w, 7, "", fill=True)
            pdf.set_text_color(80, 80, 100)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(14, 7, str(count), align="R")
            pdf.ln(9)

        # Tabla de hallazgos
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(26, 26, 46)
        pdf.cell(0, 7, "Tabla de hallazgos", align="L")
        pdf.ln(5)
        pdf.set_draw_color(220, 220, 235)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)

        # Cabecera de tabla
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(240, 240, 248)
        pdf.set_text_color(100, 100, 130)
        for header, w in [("ID", 18), ("Hallazgo", 82), ("Severidad", 26), ("CVSS", 14), ("Activo", 55)]:
            pdf.cell(w, 6, header, fill=True, border=1, align="C" if header in ("Severidad", "CVSS") else "L")
        pdf.ln()

        # Filas de tabla
        for f in self.findings:
            r, g, b   = _PDF_BG.get(f.severity, (150, 150, 150))
            rt, gt, bt = _PDF_FG.get(f.severity, (255, 255, 255))
            cvss_s     = f"{f.cvss:.1f}" if f.cvss is not None else "—"
            pdf.set_font("Helvetica", "", 7)
            pdf.set_fill_color(252, 252, 255)
            pdf.set_text_color(60, 60, 80)
            pdf.cell(18, 6, f.id[:10], border=1)
            pdf.cell(82, 6, f.title[:52], border=1)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(rt, gt, bt)
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(26, 6, f.severity, fill=True, border=1, align="C")
            pdf.set_fill_color(252, 252, 255)
            pdf.set_text_color(60, 60, 80)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(14, 6, cvss_s, border=1, align="C")
            pdf.cell(55, 6, f.affected[:32], border=1)
            pdf.ln()

    def _pdf_hallazgo(self, pdf, f: Finding) -> None:
        """Renderiza un hallazgo individual en una nueva página del PDF."""
        pdf.add_page()
        r, g, b   = _PDF_BG.get(f.severity, (150, 150, 150))
        rt, gt, bt = _PDF_FG.get(f.severity, (255, 255, 255))

        # Banda de color con ID + título + severidad
        pdf.set_fill_color(r, g, b)
        pdf.rect(0, 10, 210, 16, "F")
        pdf.set_y(14)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(rt, gt, bt)
        pdf.set_x(15)
        pdf.cell(22, 6, f.id, align="L")
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(130, 6, f.title[:60], align="L")
        pdf.set_font("Helvetica", "", 7.5)
        cvss_p = f"CVSS {f.cvss:.1f}  " if f.cvss is not None else ""
        cve_p  = f.cve or ""
        pdf.cell(0, 6, f"{cvss_p}{cve_p}", align="R")

        pdf.set_y(30)

        def seccion(titulo: str, texto: str, mono: bool = False) -> None:
            """Renderiza una sección de hallazgo con título y cuerpo de texto."""
            pdf.ln(3)
            pdf.set_x(15)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(160, 160, 185)
            pdf.cell(0, 5, titulo.upper(), align="L")
            pdf.ln(4)
            pdf.set_x(15)
            if mono:
                pdf.set_fill_color(240, 240, 248)
                pdf.set_font("Courier", "", 7.5)
                pdf.set_text_color(44, 62, 80)
                pdf.multi_cell(180, 4.5, str(texto)[:900], fill=True, align="L")
            else:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(44, 62, 80)
                pdf.multi_cell(180, 5.2, str(texto)[:700], align="L")

        # Activo afectado (inline)
        pdf.set_x(15)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(160, 160, 185)
        pdf.cell(38, 5, "ACTIVO AFECTADO", align="L")
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(44, 62, 80)
        pdf.cell(0, 5, str(f.affected)[:80], align="L")
        pdf.ln(7)

        seccion("Descripción", f.description)
        seccion("Evidencia técnica", f.evidence, mono=True)
        seccion("Remediación", f.remediation)

        if f.references:
            pdf.ln(3)
            pdf.set_x(15)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(160, 160, 185)
            pdf.cell(0, 5, "REFERENCIAS", align="L")
            pdf.ln(4)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.set_text_color(41, 128, 185)
            for ref in f.references[:5]:
                pdf.set_x(15)
                pdf.cell(0, 4.5, str(ref)[:100], align="L")
                pdf.ln()


# ---------------------------------------------------------------------------
# Función de utilidad: construir meta desde argumentos CLI
# ---------------------------------------------------------------------------

def meta_from_args(args, tool: str, version: str) -> ReportMeta:
    """
    Construye un ReportMeta a partir de los argumentos CLI estándar VSL.

    Los argumentos esperados son: args.client, args.engagement,
    args.auditor, args.scope (todos opcionales con valores por defecto).
    Compatible con los grupos de argumentos añadidos por add_report_args().
    """
    return ReportMeta(
        tool         = tool,
        tool_version = version,
        client       = getattr(args, "client",     "Confidencial"),
        engagement   = getattr(args, "engagement", ""),
        auditor      = getattr(args, "auditor",    "VampSecure Labs — Security Research Division"),
        scope        = getattr(args, "report_scope", getattr(args, "scope", "")),
    )


def add_report_args(parser) -> None:
    """
    Añade el grupo de argumentos de informe de cliente al parser de argparse.

    Añade:
      --client NAME       nombre del cliente (portada del informe)
      --engagement REF    referencia del engagement
      --auditor NOMBRE    nombre del auditor
      --scope TEXTO       descripción del alcance
      --report-html FILE  HTML profesional para entrega al cliente
      --report-pdf  FILE  PDF para entrega al cliente (requiere fpdf2)

    Uso:
      add_report_args(parser)
      args = parser.parse_args()
      meta = meta_from_args(args, tool="vamp-xxx", version=VERSION)
    """
    grp = parser.add_argument_group(
        "Informe de cliente (VampSecure Labs formato unificado)"
    )
    grp.add_argument("--client",      metavar="NOMBRE",  default="Confidencial",
                     help="Nombre del cliente para la portada del informe")
    grp.add_argument("--engagement",  metavar="REF",     default="",
                     help="Referencia o nombre del engagement")
    grp.add_argument("--auditor",     metavar="NOMBRE",
                     default="VampSecure Labs — Security Research Division",
                     help="Nombre del auditor o equipo")
    grp.add_argument("--report-scope", metavar="TEXTO",   default="", dest="report_scope",
                     help="Descripción del alcance del análisis para el informe de cliente")
    grp.add_argument("--report-html", metavar="FICHERO", dest="report_html",
                     help="Informe HTML profesional para entrega al cliente")
    grp.add_argument("--report-pdf",  metavar="FICHERO", dest="report_pdf",
                     help="Informe PDF para entrega al cliente (requiere: pip install fpdf2)")
