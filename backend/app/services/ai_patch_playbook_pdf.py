"""
Analytical AI Patch Playbook PDF Generator
Produces publication-grade, technical remediation blueprints with executable code diffs,
terminal commands, verification tests, and rollback procedures.
Exclusively accessible by Pro Tier users.
"""
import io
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
)

def _escape_xml(text: str) -> str:
    """Escapes XML entities for ReportLab Paragraphs."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
    )

def _format_diff_for_flowable(diff_text: str) -> str:
    """Formats unified git diff for display inside ReportLab with syntax highlights."""
    lines = diff_text.strip().split("\n")
    formatted = []
    for line in lines:
        escaped = _escape_xml(line)
        if escaped.startswith("+") and not escaped.startswith("+++"):
            formatted.append(f"<font color='#22c55e'><b>{escaped}</b></font>")
        elif escaped.startswith("-") and not escaped.startswith("---"):
            formatted.append(f"<font color='#ef4444'><b>{escaped}</b></font>")
        elif escaped.startswith("@@"):
            formatted.append(f"<font color='#06b6d4'><i>{escaped}</i></font>")
        else:
            formatted.append(f"<font color='#94a3b8'>{escaped}</font>")
    return "<br/>".join(formatted)

def _format_code_block(code_text: str) -> str:
    """Formats terminal command block."""
    lines = code_text.strip().split("\n")
    formatted = []
    for line in lines:
        escaped = _escape_xml(line)
        if escaped.startswith("#"):
            formatted.append(f"<font color='#64748b'><i>{escaped}</i></font>")
        else:
            formatted.append(f"<font color='#38bdf8'>{escaped}</font>")
    return "<br/>".join(formatted)

def generate_ai_patch_playbook_pdf(
    scan_meta: Dict[str, Any],
    playbook_data: Dict[str, Any]
) -> bytes:
    """
    Builds the high-fidelity Analytical AI Remediation Playbook PDF.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Typography & Styles
    doc_title = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )
    badge_style = ParagraphStyle(
        "BadgeStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#3b82f6")
    )
    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )
    h3_style = ParagraphStyle(
        "H3Style",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceBefore=6,
        spaceAfter=3
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    diff_style = ParagraphStyle(
        "DiffStyle",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7,
        leading=9.5,
        textColor=colors.HexColor("#f8fafc")
    )
    cli_style = ParagraphStyle(
        "CliStyle",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#f8fafc")
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )
    table_head = ParagraphStyle(
        "TableHead",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#ffffff")
    )

    story = []

    domain = scan_meta.get("target_domain", "target.local")
    company = scan_meta.get("company_name") or domain
    scan_id = scan_meta.get("id", "SCAN-000")
    timestamp = datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M UTC")

    # 1. Header Banner
    story.append(Paragraph("PRO EDITION // AUTONOMOUS AI REMEDIATION PLAYBOOK", badge_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Executable Security Patch Blueprint: {domain}", doc_title))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"<b>Target Enterprise:</b> {company} | <b>Scan ID:</b> {scan_id[:8]}... | <b>Generated:</b> {timestamp}",
        body_style
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#06b6d4"), spaceAfter=12))

    # 2. Executive Remediation KPI Cards
    total_patches = playbook_data.get("total_patches", 0)
    crit_patches = playbook_data.get("critical_patches", 0)
    high_patches = playbook_data.get("high_patches", 0)
    med_patches = playbook_data.get("medium_patches", 0)

    summary_cards = [
        [
            Paragraph("<b>Total Playbook Patches</b>", body_style),
            Paragraph("<b>Critical CVE Hotfixes</b>", body_style),
            Paragraph("<b>High Priority Patches</b>", body_style),
            Paragraph("<b>Medium Config Fixes</b>", body_style),
            Paragraph("<b>Automation Engine</b>", body_style)
        ],
        [
            Paragraph(f"<font size=13 color='#0284c7'><b>{total_patches}</b></font>", body_style),
            Paragraph(f"<font size=13 color='#ef4444'><b>{crit_patches}</b></font>", body_style),
            Paragraph(f"<font size=13 color='#f97316'><b>{high_patches}</b></font>", body_style),
            Paragraph(f"<font size=13 color='#eab308'><b>{med_patches}</b></font>", body_style),
            Paragraph("<font size=9 color='#10b981'><b>OpenRouter Multi-Key AI</b></font>", body_style)
        ]
    ]
    card_table = Table(summary_cards, colWidths=[105, 110, 105, 105, 115])
    card_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 14))

    # 3. 30-Day Sprint Priority Table
    story.append(Paragraph("1. Rapid Remediation Sprint Schedule (Priority Queue)", h2_style))
    story.append(Paragraph(
        "The following prioritized roadmap structures engineering velocity according to CVSS exploitability and weaponized threat intelligence.",
        body_style
    ))
    story.append(Spacer(1, 6))

    sched_rows = [[
        Paragraph("Priority", table_head),
        Paragraph("Finding / CVE", table_head),
        Paragraph("Severity", table_head),
        Paragraph("Affected Service", table_head),
        Paragraph("Est. Effort", table_head),
        Paragraph("Verification Check", table_head)
    ]]

    sev_colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6"
    }

    playbook_items = playbook_data.get("playbook", [])
    for idx, item in enumerate(playbook_items[:15], 1):
        f = item.get("finding", {})
        r = item.get("remediation", {})
        sev = f.get("severity", "Medium")
        c_hex = sev_colors.get(sev, "#64748b")
        cve_str = ", ".join(f.get("cve_ids", [])) or "Policy"
        comp = r.get("affected_component", "Web / API Server")
        if len(comp) > 30:
            comp = comp[:27] + "..."
        time_est = r.get("estimated_time", "20m")

        sched_rows.append([
            Paragraph(f"Sprint #{idx}", table_cell),
            Paragraph(f"<b>{_escape_xml(f.get('title', 'Finding'))}</b><br/><font color='#64748b'>{cve_str}</font>", table_cell),
            Paragraph(f"<font color='{c_hex}'><b>{sev}</b></font>", table_cell),
            Paragraph(_escape_xml(comp), table_cell),
            Paragraph(time_est, table_cell),
            Paragraph("Automated Curl Test", table_cell)
        ])

    sched_table = Table(sched_rows, colWidths=[55, 175, 55, 115, 60, 80])
    sched_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sched_table)
    story.append(Spacer(1, 16))

    # 4. Detailed Patch Guides
    story.append(Paragraph("2. Deep-Dive Analytical Patches & Verification Procedures", h2_style))
    story.append(Paragraph(
        "Each section contains exact unified git diffs, shell deployment scripts, and zero-trust verification tests.",
        body_style
    ))
    story.append(Spacer(1, 8))

    for idx, item in enumerate(playbook_items[:12], 1):
        f = item.get("finding", {})
        r = item.get("remediation", {})
        sev = f.get("severity", "Medium")
        c_hex = sev_colors.get(sev, "#64748b")
        cve_str = ", ".join(f.get("cve_ids", [])) or "N/A"
        
        diff_text = r.get("patch_code_diff", "# No diff available")
        cli_text = r.get("terminal_commands", "# No CLI script available")
        verify_text = r.get("verification_test", "# Verification pending")
        rollback_text = r.get("rollback_procedure", "# Rollback steps")

        patch_elements = []

        # Title & Badges
        patch_elements.append(Paragraph(
            f"<b>{idx}. {_escape_xml(f.get('title', 'Finding'))}</b> "
            f"<font color='{c_hex}'>[{sev}]</font> | CVE: {cve_str}",
            h3_style
        ))

        # Root Cause Analysis
        patch_elements.append(Paragraph(
            f"<b>Root Cause & Attack Vector:</b> {_escape_xml(r.get('root_cause_analysis', 'Defect identified in asset configuration.'))}",
            body_style
        ))
        patch_elements.append(Spacer(1, 4))

        # Code Diff Box (rendered inside a stylized dark Table container)
        patch_elements.append(Paragraph("<b>Unified Configuration Patch (Git Diff):</b>", body_style))
        formatted_diff = _format_diff_for_flowable(diff_text)
        diff_cell = Paragraph(formatted_diff, diff_style)
        diff_table = Table([[diff_cell]], colWidths=[540])
        diff_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        patch_elements.append(diff_table)
        patch_elements.append(Spacer(1, 5))

        # CLI Terminal Commands
        patch_elements.append(Paragraph("<b>Terminal Execution Commands (Copy & Run):</b>", body_style))
        formatted_cli = _format_code_block(cli_text)
        cli_cell = Paragraph(formatted_cli, cli_style)
        cli_table = Table([[cli_cell]], colWidths=[540])
        cli_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#475569")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        patch_elements.append(cli_table)
        patch_elements.append(Spacer(1, 4))

        # Verification & Rollback
        verif_html = (
            f"<b>Verification Test:</b><br/>"
            f"<font face='Courier' size=7 color='#0284c7'>{_escape_xml(verify_text).replace(chr(10), '<br/>')}</font><br/>"
            f"<b>Rollback Strategy:</b> {_escape_xml(rollback_text)} | <i>Est. Time: {r.get('estimated_time', '15m')}</i>"
        )
        patch_elements.append(Paragraph(verif_html, body_style))
        patch_elements.append(Spacer(1, 8))
        patch_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=10))

        story.append(KeepTogether(patch_elements))

    # 5. Cryptographic Seal & Compliance Footer
    raw_hash_seed = f"{domain}_{scan_id}_{timestamp}_{total_patches}"
    seal_sha256 = hashlib.sha256(raw_hash_seed.encode("utf-8")).hexdigest()
    footer_text = (
        f"<b>AUDITOR SECURE INTEGRITY SEAL:</b> SHA256:{seal_sha256}<br/>"
        f"This document is classified <b>CONFIDENTIAL // PRO TIER LICENSED</b>. "
        "Generated autonomously via Hackingly Defense Intelligence Engine with zero-touch remediation capabilities."
    )
    story.append(Spacer(1, 10))
    story.append(Paragraph(footer_text, ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, leading=9, textColor=colors.HexColor("#64748b"))))

    doc.build(story)
    return buffer.getvalue()
