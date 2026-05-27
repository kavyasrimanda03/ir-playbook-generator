"""
Incident Response Playbook Generator
report_generator.py — PDF generation using reportlab
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime

W, H = A4

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High":     colors.HexColor("#EA580C"),
    "Medium":   colors.HexColor("#CA8A04"),
    "Low":      colors.HexColor("#16A34A"),
}

PHASE_COLORS = {
    "Identification":  colors.HexColor("#2563EB"),
    "Containment":     colors.HexColor("#DC2626"),
    "Eradication":     colors.HexColor("#EA580C"),
    "Recovery":        colors.HexColor("#16A34A"),
    "Lessons Learned": colors.HexColor("#7C3AED"),
}

DARK = colors.HexColor("#0F172A")
SLATE = colors.HexColor("#475569")
LIGHT = colors.HexColor("#F1F5F9")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20,
                                textColor=colors.white, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=10,
                                   textColor=colors.HexColor("#94A3B8"), spaceAfter=2),
        "section": ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=11,
                                  textColor=colors.white, spaceAfter=2),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9,
                               textColor=colors.HexColor("#1E293B"), spaceAfter=3, leading=14),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8,
                                textColor=SLATE, spaceAfter=1),
        "step": ParagraphStyle("step", fontName="Helvetica", fontSize=9,
                               textColor=colors.HexColor("#1E293B"), leading=13),
        "small": ParagraphStyle("small", fontName="Helvetica-Oblique", fontSize=8,
                                textColor=SLATE),
    }


def _section_table(title: str, color=DARK):
    """Colored full-width section header bar."""
    t = Table([[Paragraph(f"<b>{title}</b>",
                ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=10,
                               textColor=colors.white))]], colWidths=[170*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), color),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    return t


def generate_pdf(playbook: dict, output_path: str = None) -> str:
    if output_path is None:
        inc_type = playbook["metadata"]["incident_type"]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"playbook_{inc_type}_{ts}.pdf"

    meta = playbook["metadata"]
    inc  = playbook["incident"]
    S    = _styles()

    def on_page(canvas, doc):
        canvas.saveState()
        # header bar
        canvas.setFillColor(DARK)
        canvas.rect(0, H-14*mm, W, 14*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#94A3B8"))
        canvas.drawCentredString(W/2, H-8*mm,
            f"INCIDENT RESPONSE PLAYBOOK  |  {meta['org_name'].upper()}  |  CONFIDENTIAL")
        # footer bar
        canvas.setFillColor(DARK)
        canvas.rect(0, 0, W, 10*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#94A3B8"))
        canvas.drawCentredString(W/2, 3*mm,
            f"Generated {meta['generated_at']}  |  Page {doc.page}  |  Analyst: {meta['analyst']}")
        canvas.restoreState()

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=16*mm)
    story = []

    # ── COVER ──────────────────────────────────────────────────────────────
    sev_color = SEVERITY_COLORS.get(inc["severity"], SLATE)

    # Severity badge + title block
    cover_data = [[
        Paragraph(f"<b>● {inc['severity'].upper()} SEVERITY</b>",
                  ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
    ]]
    badge = Table(cover_data, colWidths=[50*mm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), sev_color),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
    ]))

    hero_inner = [
        [badge],
        [Paragraph(inc["name"].upper(), S["title"])],
        [Paragraph("INCIDENT RESPONSE PLAYBOOK", S["subtitle"])],
    ]
    hero = Table(hero_inner, colWidths=[170*mm])
    hero.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    story.append(hero)
    story.append(Spacer(1, 6*mm))

    # Meta info table
    info_rows = [
        ["Organization", meta["org_name"]],
        ["Prepared By",  meta["analyst"]],
        ["Generated",    meta["generated_at"]],
        ["NIST Functions", ", ".join(inc["nist_functions"])],
        ["SLA — Containment", inc["sla"]["detection_to_containment"]],
        ["SLA — Resolution",  inc["sla"]["full_resolution"]],
    ]
    info_table = Table(
        [[Paragraph(f"<b>{r[0].upper()}</b>",
                    ParagraphStyle("lbl", fontName="Helvetica-Bold", fontSize=8, textColor=SLATE)),
          Paragraph(r[1], ParagraphStyle("val", fontName="Helvetica", fontSize=9,
                                         textColor=DARK))]
         for r in info_rows],
        colWidths=[55*mm, 115*mm]
    )
    info_table.setStyle(TableStyle([
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 4*mm))

    # Description
    story.append(_section_table("INCIDENT DESCRIPTION"))
    story.append(Paragraph(inc["description"], S["body"]))
    story.append(Spacer(1, 4*mm))

    # MITRE
    story.append(_section_table("MITRE ATT&CK TACTICS"))
    for t in inc["mitre_tactics"]:
        story.append(Paragraph(f"▸  {t}", S["body"]))
    story.append(Spacer(1, 4*mm))

    # IOCs
    story.append(_section_table("INDICATORS OF COMPROMISE (IOCs)"))
    for ioc in inc["iocs"]:
        story.append(Paragraph(f"▸  {ioc}", S["body"]))
    story.append(Spacer(1, 4*mm))

    # Escalation matrix
    story.append(_section_table("ESCALATION MATRIX"))
    esc_rows = [
        [Paragraph("<b>SEVERITY</b>", ParagraphStyle("eh", fontName="Helvetica-Bold",
                   fontSize=8, textColor=colors.white)),
         Paragraph("<b>ESCALATION PATH</b>", ParagraphStyle("eh2", fontName="Helvetica-Bold",
                   fontSize=8, textColor=colors.white))]
    ]
    for level, path in inc["escalation"].items():
        lc = SEVERITY_COLORS.get(level, SLATE)
        esc_rows.append([
            Paragraph(f"<b>{level}</b>",
                      ParagraphStyle("el", fontName="Helvetica-Bold", fontSize=8,
                                     textColor=colors.white)),
            Paragraph(path, ParagraphStyle("ep", fontName="Helvetica", fontSize=8,
                                           textColor=DARK))
        ])
    esc_table = Table(esc_rows, colWidths=[35*mm, 135*mm])
    esc_style = [
        ("BACKGROUND",    (0,0), (-1,0), DARK),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]
    for i, (level, _) in enumerate(inc["escalation"].items(), 1):
        lc = SEVERITY_COLORS.get(level, SLATE)
        esc_style.append(("BACKGROUND", (0,i), (0,i), lc))
        esc_style.append(("TEXTCOLOR",  (0,i), (0,i), colors.white))
        esc_style.append(("BACKGROUND", (1,i), (1,i), LIGHT))
    esc_table.setStyle(TableStyle(esc_style))
    story.append(esc_table)

    # ── PHASES ─────────────────────────────────────────────────────────────
    for phase_name, phase_data in playbook["phases"].items():
        story.append(PageBreak())
        pc = PHASE_COLORS.get(phase_name, DARK)

        story.append(_section_table(
            f"PHASE: {phase_name.upper()}  [{phase_data['timeframe']}]", color=pc))
        story.append(Spacer(1, 2*mm))

        story.append(Paragraph(f"<i>NIST Control: {phase_data['nist_control']}</i>", S["small"]))
        story.append(Spacer(1, 2*mm))

        # Tools row
        tools_t = Table([[Paragraph(
            f"<b>TOOLS:</b>  {', '.join(phase_data['tools'])}",
            ParagraphStyle("tl", fontName="Helvetica", fontSize=8, textColor=DARK)
        )]], colWidths=[170*mm])
        tools_t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), LIGHT),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ]))
        story.append(tools_t)
        story.append(Spacer(1, 3*mm))

        story.append(Paragraph("<b>RESPONSE STEPS</b>", S["label"]))
        story.append(Spacer(1, 1*mm))

        for i, step in enumerate(phase_data["steps"], 1):
            step_rows = [[
                Paragraph(f"<b>{i}</b>",
                          ParagraphStyle("sn", fontName="Helvetica-Bold", fontSize=9,
                                         textColor=colors.white, alignment=TA_CENTER)),
                Paragraph(step, S["step"])
            ]]
            st = Table(step_rows, colWidths=[8*mm, 162*mm])
            st.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (0,0), pc),
                ("BACKGROUND",    (1,0), (1,0), colors.HexColor("#FCFCFD")),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING",   (1,0), (1,0), 8),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
                ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ]))
            story.append(st)
            story.append(Spacer(1, 1.5*mm))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return output_path
