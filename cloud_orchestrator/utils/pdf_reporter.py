"""
cloud_orchestrator/utils/pdf_reporter.py
==========================================
ReportLab PDF compliance report generator for Oxbuild.

Sections:
  1. Cover — summary stats, risk arc gauge, model info
  2. Violations — colour-coded detail cards per violation
  3. Risk & Fines — score breakdown + regulatory exposure table
  4. Corrected Code — full patched source with line numbers
  5. Split Diff — side-by-side original vs patched per hunk

Usage:
    from cloud_orchestrator.utils.pdf_reporter import build_pdf
    pdf_bytes = build_pdf(audit_result_dict, language="python")
"""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

# ─── Colours ─────────────────────────────────────────────────────────────────

C_BLACK    = colors.HexColor("#0a0a0a")
C_DARK     = colors.HexColor("#18181b")
C_BORDER   = colors.HexColor("#d4d4d8")
C_SURFACE  = colors.HexColor("#f4f4f5")
C_SURFACE2 = colors.HexColor("#e4e4e7")
C_MUTED    = colors.HexColor("#71717a")
C_WHITE    = colors.white

SEV_FG  = {"CRITICAL": colors.HexColor("#ef4444"), "HIGH": colors.HexColor("#f97316"),
            "MEDIUM": colors.HexColor("#ca8a04"),   "LOW":  colors.HexColor("#0284c7"),
            "INFO":   colors.HexColor("#71717a")}
SEV_BG  = {"CRITICAL": colors.HexColor("#fef2f2"), "HIGH": colors.HexColor("#fff7ed"),
            "MEDIUM": colors.HexColor("#fefce8"),   "LOW":  colors.HexColor("#f0f9ff"),
            "INFO":   colors.HexColor("#f9fafb")}
RISK_FG = {"CRITICAL": colors.HexColor("#ef4444"), "HIGH": colors.HexColor("#f97316"),
            "MEDIUM": colors.HexColor("#ca8a04"),   "LOW":  colors.HexColor("#0284c7"),
            "MINIMAL": colors.HexColor("#16a34a")}

# ─── Page geometry ────────────────────────────────────────────────────────────

PW, PH       = A4
ML = MR      = 18 * mm
MT = MB      = 16 * mm
CW           = PW - ML - MR      # usable content width


# ─── Style helpers ────────────────────────────────────────────────────────────

def _s(**kw) -> ParagraphStyle:
    return ParagraphStyle("_tmp", **kw)


S_TITLE  = _s(fontName="Helvetica-Bold",   fontSize=26, leading=32,  textColor=C_BLACK)
S_SUB    = _s(fontName="Helvetica",        fontSize=10, leading=14,  textColor=C_MUTED)
S_SEC    = _s(fontName="Helvetica-Bold",   fontSize=13, leading=17,  textColor=C_BLACK,
              spaceBefore=8, spaceAfter=3)
S_LBL    = _s(fontName="Helvetica-Bold",   fontSize=8,  leading=10,  textColor=C_MUTED,
              spaceAfter=2)
S_BODY   = _s(fontName="Helvetica",        fontSize=9,  leading=13,  textColor=C_BLACK)
S_SMALL  = _s(fontName="Helvetica",        fontSize=8,  leading=11,  textColor=C_MUTED)
S_MONO   = _s(fontName="Courier",          fontSize=7.5,leading=10.5,textColor=C_BLACK,
              backColor=C_SURFACE, leftIndent=3, rightIndent=3)
S_MONO_R = _s(fontName="Courier",          fontSize=7.5,leading=10.5,
              textColor=colors.HexColor("#b91c1c"), backColor=colors.HexColor("#fef2f2"),
              leftIndent=3)
S_MONO_G = _s(fontName="Courier",          fontSize=7.5,leading=10.5,
              textColor=colors.HexColor("#15803d"), backColor=colors.HexColor("#f0fdf4"),
              leftIndent=3)
S_NUM    = _s(fontName="Courier",          fontSize=6.5,leading=9.5, textColor=C_MUTED,
              alignment=TA_CENTER)
S_TBL_H  = _s(fontName="Helvetica-Bold",   fontSize=8,  leading=10,  textColor=C_WHITE)
S_TBL_C  = _s(fontName="Helvetica",        fontSize=8,  leading=11,  textColor=C_BLACK)
S_TBL_M  = _s(fontName="Courier",          fontSize=7,  leading=9,   textColor=C_BLACK)
S_FTR    = _s(fontName="Helvetica",        fontSize=7,  leading=9,   textColor=C_MUTED,
              alignment=TA_CENTER)
S_STAT_N = _s(fontName="Helvetica-Bold",   fontSize=30, leading=36,  textColor=C_BLACK,
              alignment=TA_CENTER)
S_STAT_L = _s(fontName="Helvetica",        fontSize=8,  leading=10,  textColor=C_MUTED,
              alignment=TA_CENTER)


# ─── Custom flowables ─────────────────────────────────────────────────────────

class _HRule(Flowable):
    def __init__(self, colour=C_BORDER, thick=0.5, width=None):
        super().__init__()
        self._c = colour; self._t = thick; self._w = width or CW
    def draw(self):
        self.canv.setStrokeColor(self._c)
        self.canv.setLineWidth(self._t)
        self.canv.line(0, 0, self._w, 0)
    def wrap(self, *_):
        return self._w, self._t + 1


class _RiskGauge(Flowable):
    """
    Semicircular risk gauge drawn with ReportLab path API.
    Uses beginPath() / arc() / drawPath() — no .stroke() call on canvas.
    """
    def __init__(self, score: int, label: str, w: float = 110):
        super().__init__()
        self._score = max(0, min(100, int(score)))
        self._label = label
        self._w = w
        self._h = w * 0.55

    def wrap(self, *_):
        return self._w, self._h + 28

    def draw(self):
        c  = self.canv
        cx = self._w / 2
        cy = 4
        r  = self._w * 0.40
        lw = 11
        col = RISK_FG.get(self._label, C_MUTED)

        # Background track (grey arc)
        c.setStrokeColor(C_SURFACE2)
        c.setLineWidth(lw)
        c.setLineCap(1)
        p = c.beginPath()
        p.arc(cx - r, cy, cx + r, cy + 2 * r, startAng=180, extent=-180)
        c.drawPath(p, stroke=1, fill=0)

        # Coloured progress arc
        extent = -180.0 * (self._score / 100.0)
        c.setStrokeColor(col)
        c.setLineWidth(lw)
        p2 = c.beginPath()
        p2.arc(cx - r, cy, cx + r, cy + 2 * r, startAng=180, extent=extent)
        c.drawPath(p2, stroke=1, fill=0)

        # Score number
        c.setFillColor(C_BLACK)
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(cx, cy + r - 14, str(self._score))

        # /100
        c.setFillColor(C_MUTED)
        c.setFont("Helvetica", 8)
        c.drawCentredString(cx, cy + r - 25, "/100")

        # Risk label
        c.setFillColor(col)
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(cx, cy - 16, self._label)


# ─── Page header / footer ────────────────────────────────────────────────────

def _page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_DARK)
    canvas.rect(0, PH - 9 * mm, PW, 9 * mm, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawString(ML, PH - 5.8 * mm, "OXBUILD COMPLIANCE REPORT")
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(PW - MR, PH - 5.8 * mm, f"Page {doc.page}  |  Confidential")
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(ML, MB - 0.5 * mm, PW - MR, MB - 0.5 * mm)
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawCentredString(
        PW / 2, MB - 4 * mm,
        "Oxbuild Compliance Agent  |  local-first  |  PII never leaves your machine",
    )
    canvas.restoreState()


# ─── Utility functions ────────────────────────────────────────────────────────

def _eur(n: float) -> str:
    if n >= 1_000_000: return f"EUR {n/1_000_000:.1f}M"
    if n >= 1_000:     return f"EUR {n/1_000:.0f}K"
    return f"EUR {n:.0f}"

def _safe(t: str) -> str:
    return (t or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _wrap(text: str, w: int = 88) -> str:
    lines = []
    for line in (text or "").splitlines():
        if len(line) <= w:
            lines.append(line)
        else:
            ind = " " * (len(line) - len(line.lstrip()))
            lines.extend(textwrap.wrap(line, width=w, subsequent_indent=ind + "  "))
    return "\n".join(lines)

def _hdr(title: str, sub: str = "") -> list:
    items: list = [Spacer(1, 6), Paragraph(title, S_SEC)]
    if sub:
        items.append(Paragraph(_safe(sub), S_SMALL))
    items.append(_HRule(C_DARK, 1.0))
    items.append(Spacer(1, 4))
    return items

def _tbl_style(extra: list | None = None) -> TableStyle:
    base = [
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("RIGHTPADDING",  (0,0),(-1,-1), 6),
        ("GRID",          (0,0),(-1,-1), 0.3, C_BORDER),
    ]
    return TableStyle(base + (extra or []))


# ─── Cover page ──────────────────────────────────────────────────────────────

def _cover(story: list, data: dict, language: str) -> None:
    audit  = data.get("audit_report", {})
    risk   = data.get("risk_assessment", {})
    ts     = datetime.now(timezone.utc).strftime("%d %b %Y  %H:%M UTC")
    regs   = ", ".join(audit.get("regulations", ["GDPR"]))
    score  = int(risk.get("normalised_score", risk.get("risk_score", 0)) or 0)
    label  = risk.get("risk_label", "MINIMAL")
    n_viol = audit.get("total_count", 0)
    n_crit = audit.get("critical_count", 0)
    t_max  = risk.get("total_exposure_max_eur", 0) or 0

    story += [
        Spacer(1, 10),
        Paragraph("Compliance Audit Report", S_TITLE),
        Spacer(1, 4),
        Paragraph(f"{ts}  |  Language: {language.title()}  |  {regs}", S_SUB),
        Spacer(1, 6),
        _HRule(C_DARK, 1.5),
        Spacer(1, 12),
    ]

    # Stat boxes + gauge
    def stat_cell(val: str, lbl: str, colour=C_BLACK) -> list:
        hex_c = "#%02x%02x%02x" % (
            int(colour.red*255), int(colour.green*255), int(colour.blue*255)
        )
        return [
            Paragraph(f'<font color="{hex_c}">{_safe(val)}</font>', S_STAT_N),
            Spacer(1, 2),
            Paragraph(_safe(lbl), S_STAT_L),
        ]

    stat_data = [[
        stat_cell(str(n_viol),                       "Total Violations", C_BLACK),
        stat_cell(str(n_crit),                       "Critical",          SEV_FG["CRITICAL"]),
        stat_cell(_eur(t_max) if t_max else "N/A",   "Max Exposure",      SEV_FG["HIGH"]),
        [_RiskGauge(score, label, w=95)],
    ]]
    stat_t = Table(stat_data, colWidths=[CW*0.23]*3 + [CW*0.31], rowHeights=[85])
    stat_t.setStyle(TableStyle([
        ("ALIGN",      (0,0),(-1,-1), "CENTER"),
        ("VALIGN",     (0,0),(-1,-1), "MIDDLE"),
        ("BOX",        (0,0),(2,0),   0.5, C_BORDER),
        ("INNERGRID",  (0,0),(2,0),   0.3, C_BORDER),
        ("BACKGROUND", (0,0),(2,0),   C_SURFACE),
        ("BOX",        (3,0),(3,0),   0.5, C_BORDER),
        ("BACKGROUND", (3,0),(3,0),   C_SURFACE),
    ]))
    story.append(stat_t)
    story.append(Spacer(1, 10))

    summary = audit.get("summary", "")
    if summary:
        story.append(Paragraph(_safe(summary), S_BODY))
        story.append(Spacer(1, 8))

    # Model metadata
    rows = [
        ["Phase", "Role", "Model / Provider"],
        ["Phase 0", "PII Scanner",    "C++ _oxscanner (local)"],
        ["Phase 1", "Legal Auditor",  _safe(audit.get("model","llama-3.3-70b-versatile"))],
        ["Phase 2", "Risk Judge",     _safe(risk.get("model","deepseek-r1-distill-llama-70b"))],
        ["Phase 3", "Architect",      _safe(data.get("patch_result",{}).get("model","llama-3.3-70b-versatile"))],
    ]
    mt = Table(rows, colWidths=[CW*0.18, CW*0.28, CW*0.54])
    mt.setStyle(_tbl_style([
        ("BACKGROUND",  (0,0),(-1,0),   C_DARK),
        ("TEXTCOLOR",   (0,0),(-1,0),   C_WHITE),
        ("FONTNAME",    (0,0),(-1,0),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1),(-1,-1), [C_WHITE, C_SURFACE]),
    ]))
    story.append(mt)
    story.append(PageBreak())


# ─── Violations ──────────────────────────────────────────────────────────────

def _violations(story: list, data: dict) -> None:
    audit = data.get("audit_report", {})
    viol  = audit.get("violations", [])
    story += _hdr("2.  Audit Violations",
                  f"{len(viol)} violation(s) detected — sorted by severity")

    if not viol:
        story.append(Paragraph("No violations detected.", S_SMALL))
        story.append(PageBreak())
        return

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    for i, v in enumerate(sorted(viol, key=lambda x: sev_order.get(x.get("severity","INFO"),5)), 1):
        sev   = v.get("severity", "INFO")
        fg    = SEV_FG.get(sev, C_MUTED)
        bg    = SEV_BG.get(sev, C_SURFACE)
        reg   = v.get("regulation","")
        art   = v.get("article","")
        title = v.get("title","")
        desc  = v.get("description","")
        hint  = v.get("line_hint","")
        rem   = v.get("remediation","")

        # Coloured header bar
        hdr_data = [[
            Paragraph(f"#{i}", _s(fontName="Helvetica-Bold",fontSize=9,textColor=C_WHITE,alignment=TA_CENTER)),
            Paragraph(_safe(sev), _s(fontName="Helvetica-Bold",fontSize=9,textColor=C_WHITE,alignment=TA_CENTER)),
            Paragraph(_safe(reg), _s(fontName="Helvetica-Bold",fontSize=9,textColor=C_WHITE)),
            Paragraph(_safe(art), _s(fontName="Helvetica",fontSize=9,textColor=C_WHITE)),
        ]]
        ht = Table(hdr_data, colWidths=[11*mm, 27*mm, 25*mm, CW-63*mm])
        ht.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),fg),
            ("VALIGN",    (0,0),(-1,-1),"MIDDLE"),
            ("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("TOPPADDING",   (0,0),(-1,-1),5),
            ("LEFTPADDING",  (0,0),(-1,-1),6),
        ]))

        # Body rows
        body = [
            [Paragraph("Title",       S_LBL), Paragraph(_safe(title), S_BODY)],
            [Paragraph("Description", S_LBL), Paragraph(_safe(desc),  S_BODY)],
        ]
        if hint:
            body.append([Paragraph("Code", S_LBL), Paragraph(_safe(hint), S_TBL_M)])
        body.append([
            Paragraph("Fix", _s(fontName="Helvetica-Bold",fontSize=8,leading=10,textColor=C_MUTED)),
            Paragraph(_safe(rem), _s(fontName="Helvetica",fontSize=9,leading=13,
                                      textColor=colors.HexColor("#15803d"))),
        ])

        bt = Table(body, colWidths=[25*mm, CW-25*mm])
        bt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), bg),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("LEFTPADDING",   (1,0),(1,-1),  8),
            ("LEFTPADDING",   (0,0),(0,-1),  6),
            ("LINEBELOW",     (0,0),(-1,-2), 0.3, C_BORDER),
        ]))

        story.append(KeepTogether([ht, bt, Spacer(1, 6)]))

    story.append(PageBreak())


# ─── Risk & Fines ────────────────────────────────────────────────────────────

def _risk(story: list, data: dict) -> None:
    risk   = data.get("risk_assessment", {})
    score  = int(risk.get("normalised_score", risk.get("risk_score", 0)) or 0)
    label  = risk.get("risk_label", "MINIMAL")
    rat    = risk.get("rationale", "")
    fines  = risk.get("fine_predictions", [])
    raw    = risk.get("raw_risk_score", 0) or 0
    t_min  = risk.get("total_exposure_min_eur", 0) or 0
    t_max  = risk.get("total_exposure_max_eur", 0) or 0

    story += _hdr("3.  Risk Assessment & Regulatory Exposure")

    # Gauge + summary side by side
    gauge_col = [_RiskGauge(score, label, w=85),
                 Spacer(1,3),
                 Paragraph(f"Raw score: {raw:.2f}", S_SMALL)]
    rat_col   = [Spacer(1,6),
                 Paragraph("Executive Summary", S_LBL),
                 Paragraph(_safe(rat), S_BODY)]
    side = Table([[gauge_col, rat_col]], colWidths=[52*mm, CW-52*mm])
    side.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("LEFTPADDING",(1,0),(1,0),10),
    ]))
    story.append(side)
    story.append(Spacer(1, 10))

    if not fines:
        story.append(PageBreak())
        return

    story.append(Paragraph("Regulatory Exposure", S_LBL))
    story.append(Spacer(1, 3))

    rows = [["Regulation","Min Exposure","Max Exposure","Legal Basis"]]
    for f in fines:
        rows.append([
            f.get("regulation",""),
            _eur(f.get("min_eur",0)),
            _eur(f.get("max_eur",0)),
            _safe(f.get("basis","")),
        ])
    rows.append(["TOTAL", _eur(t_min), _eur(t_max), "Combined across all frameworks"])

    ft = Table(rows, colWidths=[26*mm, 32*mm, 32*mm, CW-90*mm])
    ft.setStyle(_tbl_style([
        ("BACKGROUND",    (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0,1),(-1,-2), [C_WHITE, C_SURFACE]),
        ("BACKGROUND",    (0,-1),(-1,-1),colors.HexColor("#fff7ed")),
        ("FONTNAME",      (0,-1),(-1,-1),"Helvetica-Bold"),
        ("TEXTCOLOR",     (1,-1),(2,-1), SEV_FG["HIGH"]),
        ("ALIGN",         (1,0),(2,-1),  "RIGHT"),
    ]))
    story.append(ft)
    story.append(PageBreak())


# ─── Corrected code ──────────────────────────────────────────────────────────

def _patched_code(story: list, data: dict, language: str) -> None:
    patch  = data.get("patch_result", {})
    code   = patch.get("patched_code", "")
    summ   = patch.get("changes_summary", [])

    story += _hdr("4.  Corrected Code",
                  f"Complete patched {language} source file with all compliance fixes applied")

    if summ:
        story.append(Paragraph("Changes Applied", S_LBL))
        for ch in summ:
            story.append(Paragraph(
                "+ " + _safe(ch),
                _s(fontName="Helvetica",fontSize=8,leading=11,
                   textColor=colors.HexColor("#15803d"),leftIndent=8),
            ))
        story.append(Spacer(1, 6))

    if not code:
        story.append(Paragraph(
            "No patched code available. The Architect phase may need re-running.",
            S_SMALL,
        ))
        story.append(PageBreak())
        return

    story.append(Paragraph("Full patched file:", S_LBL))
    story.append(Spacer(1, 2))

    lines = _wrap(code).splitlines()
    rows  = []
    for i, line in enumerate(lines, 1):
        rows.append([
            Paragraph(str(i), S_NUM),
            Paragraph(_safe(line) or " ", S_MONO),
        ])

    ct = Table(rows, colWidths=[10*mm, CW-10*mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_SURFACE),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ("TOPPADDING",    (0,0),(-1,-1), 0),
        ("BOTTOMPADDING", (0,0),(-1,-1), 0),
        ("LEFTPADDING",   (1,0),(1,-1),  4),
        ("RIGHTPADDING",  (0,0),(-1,-1), 4),
        ("LINEAFTER",     (0,0),(0,-1),  0.4, C_BORDER),
    ]))
    story.append(ct)
    story.append(PageBreak())


# ─── Split diff ──────────────────────────────────────────────────────────────

def _split_diff(story: list, data: dict) -> None:
    patch = data.get("patch_result", {})
    hunks = patch.get("diff_hunks", [])

    story += _hdr("5.  Code Diff — Side-by-Side",
                  "Each hunk shows the original (left, red) vs. the patched version (right, green)")

    if not hunks:
        story.append(Paragraph(
            "No diff hunks available. See Section 4 for the full corrected file.",
            S_SMALL,
        ))
        return

    col_w = (CW - 4 * mm) / 2   # two equal columns

    for hunk in hunks:
        hid     = hunk.get("hunk_id", "?")
        comment = hunk.get("comment", "")
        reg     = hunk.get("regulation", "")
        art     = hunk.get("article", "")
        orig    = hunk.get("original", "")
        patched = hunk.get("patched", "")

        # Header bar
        hdr_data = [[
            Paragraph(f"HUNK {hid}", _s(fontName="Helvetica-Bold",fontSize=8,textColor=C_WHITE)),
            Paragraph(
                _safe(f"{reg} {art}  —  {comment}"),
                _s(fontName="Helvetica",fontSize=8,textColor=C_WHITE),
            ),
        ]]
        ht = Table(hdr_data, colWidths=[20*mm, CW-20*mm])
        ht.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),C_DARK),
            ("VALIGN",    (0,0),(-1,-1),"MIDDLE"),
            ("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("TOPPADDING",   (0,0),(-1,-1),5),
            ("LEFTPADDING",  (0,0),(-1,-1),6),
        ]))

        # Sub-header
        sh_data = [[
            Paragraph("- ORIGINAL", _s(fontName="Helvetica-Bold",fontSize=7,
                                        textColor=colors.HexColor("#b91c1c"))),
            Paragraph("+ PATCHED",  _s(fontName="Helvetica-Bold",fontSize=7,
                                        textColor=colors.HexColor("#15803d"))),
        ]]
        sh = Table(sh_data, colWidths=[col_w, col_w])
        sh.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,0),colors.HexColor("#fef2f2")),
            ("BACKGROUND",(1,0),(1,0),colors.HexColor("#f0fdf4")),
            ("BOTTOMPADDING",(0,0),(-1,-1),3),
            ("TOPPADDING",   (0,0),(-1,-1),3),
            ("LEFTPADDING",  (0,0),(-1,-1),5),
            ("LINEBELOW",    (0,0),(-1,-1),0.3,C_BORDER),
        ]))

        # Code rows — pad shorter side
        ol = _wrap(orig or "(empty)").splitlines()
        pl = _wrap(patched or "(no changes)").splitlines()
        mx = max(len(ol), len(pl), 1)
        ol += [""] * (mx - len(ol))
        pl += [""] * (mx - len(pl))

        code_rows = [
            [Paragraph(_safe(o) or " ", S_MONO_R),
             Paragraph(_safe(p) or " ", S_MONO_G)]
            for o, p in zip(ol, pl)
        ]
        ct = Table(code_rows, colWidths=[col_w, col_w])
        ct.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(0,-1), colors.HexColor("#fef2f2")),
            ("BACKGROUND",    (1,0),(1,-1), colors.HexColor("#f0fdf4")),
            ("VALIGN",        (0,0),(-1,-1),"TOP"),
            ("TOPPADDING",    (0,0),(-1,-1),0),
            ("BOTTOMPADDING", (0,0),(-1,-1),0),
            ("LEFTPADDING",   (0,0),(-1,-1),4),
            ("LINEAFTER",     (0,0),(0,-1), 0.5, C_BORDER),
            ("BOX",           (0,0),(-1,-1),0.4, C_BORDER),
        ]))

        story.append(KeepTogether([ht, sh, ct, Spacer(1, 8)]))


# ─── Public entry point ──────────────────────────────────────────────────────

def build_pdf(data: dict[str, Any], language: str = "python") -> bytes:
    """
    Generate the full compliance PDF and return raw bytes.

    Parameters
    ----------
    data     : FullPipelineResponse as a dict
    language : Source language for display

    Returns
    -------
    bytes — complete PDF file
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=ML, rightMargin=MR,
        topMargin=MT + 9 * mm,
        bottomMargin=MB + 7 * mm,
        title="Oxbuild Compliance Report",
        author="Oxbuild Compliance Agent",
        subject=f"Compliance Audit — {language}",
    )

    story: list = []
    _cover(story, data, language)
    _violations(story, data)
    _risk(story, data)
    _patched_code(story, data, language)
    _split_diff(story, data)

    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return buf.getvalue()