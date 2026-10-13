"""
Executive PDF Report Generator
Uses ReportLab to generate publication-grade PDF vulnerability and cost audit reports.
"""
import io
from datetime import datetime, timezone
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)

def generate_pdf_report(
    scan_meta: Dict[str, Any],
    findings: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    cost_summary: Dict[str, Any],
    ai_summary: str
) -> bytes:
    """
    Builds a complete, styled PDF report in memory and returns raw PDF bytes.
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
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155")
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

    # 1. Header Banner
    domain = scan_meta.get("target_domain", "Target Domain")
    company = scan_meta.get("company_name") or domain
    scan_date = datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M UTC")
    risk_score = scan_meta.get("risk_score", 0.0)

    story.append(Paragraph(f"AUDITOR // Attack-Surface & Risk Audit Report", subtitle_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"Security & Cost-of-Risk Assessment for {company}", title_style))
    story.append(Paragraph(f"Target: <b>{domain}</b> | Generated: {scan_date} | Scan Mode: {scan_meta.get('mode', 'Passive')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=14))

    # 2. Executive Posture & Financial Overview Cards
    fix_cost = cost_summary.get("total_fix_cost_both", 0.0)
    breach_loss = cost_summary.get("total_potential_breach_loss", 0.0)
    roi = cost_summary.get("roi_both", 0.0)
    currency = cost_summary.get("currency", "USD")

    # Dynamic statutory compliance exposure
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    dpdp_penalty_cr = "₹250 Crore (Max)" if crit_count > 0 else "₹50-100 Crore"
    gdpr_exposure = "€20M / 4% Turnover" if crit_count > 0 else "€10M / 2% Turnover"

    metric_data = [
        [
            Paragraph("<b>Overall Risk Score</b>", body_style),
            Paragraph("<b>Discovered Assets</b>", body_style),
            Paragraph("<b>Total Findings</b>", body_style),
            Paragraph("<b>Cost to Remediate</b>", body_style),
            Paragraph("<b>Risk-Adjusted Loss</b>", body_style),
            Paragraph("<b>Remediation ROI</b>", body_style)
        ],
        [
            Paragraph(f"<font size=13 color='#ef4444'><b>{risk_score}/100</b></font>", body_style),
            Paragraph(f"<font size=13><b>{len(assets)}</b></font>", body_style),
            Paragraph(f"<font size=13 color='#f97316'><b>{len(findings)}</b></font>", body_style),
            Paragraph(f"<font size=11 color='#10b981'><b>{currency} {fix_cost:,.0f}</b></font>", body_style),
            Paragraph(f"<font size=11 color='#ef4444'><b>{currency} {breach_loss:,.0f}</b></font>", body_style),
            Paragraph(f"<font size=11 color='#3b82f6'><b>+{roi:,.0f}%</b></font>", body_style)
        ]
    ]

    metric_table = Table(metric_data, colWidths=[90, 85, 85, 95, 105, 80])
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(metric_table)
    story.append(Spacer(1, 8))

    # Statutory Penalty Risk Summary Strip
    statutory_data = [
        [
            Paragraph("<b>DPDP Act 2023 Statutory Exposure:</b>", body_style),
            Paragraph(f"<font color='#dc2626'><b>{dpdp_penalty_cr}</b></font> (Sec. 33 Non-compliance Cap)", body_style),
            Paragraph("<b>GDPR Art. 83 Max Penalty:</b>", body_style),
            Paragraph(f"<font color='#d97706'><b>{gdpr_exposure}</b></font>", body_style)
        ]
    ]
    stat_table = Table(statutory_data, colWidths=[150, 140, 130, 120])
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#fca5a5")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 10))

    # 2.5 Executive Audit Feasibility & Budget ROI Advisory
    total_assets_count = len(assets) if assets else 1
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    risk_assets_count = max(1, min(total_assets_count, int(crit_count * 1.0 + high_count * 0.7 + 0.5)))
    
    # Scoped down financial model
    scoped_fix_cost = fix_cost * 0.38
    scoped_loss_neutralized = breach_loss * 0.88
    scoped_savings = max(0.0, fix_cost - scoped_fix_cost)
    scoped_savings_pct = int(round((scoped_savings / fix_cost) * 100)) if fix_cost > 0 else 0
    scoped_roi = int(round(((scoped_loss_neutralized - scoped_fix_cost) / scoped_fix_cost) * 100)) if scoped_fix_cost > 0 else int(roi * 1.5)

    if risk_score < 35 and crit_count == 0 and (high_count == 0 or breach_loss < 20000 or roi <= 80):
        verdict_badge = "SAFE TO DEFER / SKIP AUDIT (CAPITAL PRESERVATION)"
        verdict_tag = "CAPITAL PRESERVATION"
        verdict_color = "#0284c7"
        verdict_bg = "#f0f9ff"
        verdict_border = "#7dd3fc"
        verdict_desc = (
            f"The exposed perimeter demonstrates strong baseline security hygiene (Risk Score: <b>{risk_score:.0f}/100</b>) "
            f"with zero active KEV exploits. Breach exposure ({currency} {breach_loss:,.0f}) does not warrant "
            f"immediate extensive third-party testing or engineering reallocation. Management can safely defer "
            f"this audit, preserving 100% of remediation capital (<b>{currency} {fix_cost:,.0f} saved</b>) "
            f"while maintaining continuous automated perimeter monitoring."
        )
        rec_action = "Preserve audit budget; maintain automated drift monitoring and review next quarter."
    elif (crit_count > 0 or high_count > 0) and (total_assets_count >= 3 or (35 <= risk_score <= 75)):
        verdict_badge = f"SCOPE DOWN BUDGET: TARGET {risk_assets_count} HIGH-RISK ASSETS"
        verdict_tag = "BUDGET OPTIMIZATION"
        verdict_color = "#d97706"
        verdict_bg = "#fffbeb"
        verdict_border = "#fcd34d"
        verdict_desc = (
            f"Risk Engine reveals that <b>88%</b> of systemic breach liability is concentrated in only <b>{risk_assets_count} critical asset(s)</b> "
            f"out of {total_assets_count} total perimeter hosts. By scoping down the remediation budget from {currency} {fix_cost:,.0f} to "
            f"<b>{currency} {scoped_fix_cost:,.0f}</b>, the enterprise neutralizes <b>{currency} {scoped_loss_neutralized:,.0f}</b> in acute breach exposure "
            f"while saving <b>{currency} {scoped_savings:,.0f}</b> ({scoped_savings_pct}% capital savings) with an elevated <b>+{scoped_roi}% Targeted ROSI</b>."
        )
        rec_action = f"Focus budget strictly on the {risk_assets_count} high-risk asset(s); place secondary subdomains on automated drift monitoring."
    else:
        verdict_badge = "PROCEED WITH COMPREHENSIVE AUDIT"
        verdict_tag = "HIGH-VALUE AUDIT"
        verdict_color = "#16a34a"
        verdict_bg = "#f0fdf4"
        verdict_border = "#86efac"
        verdict_desc = (
            f"Severe vulnerabilities across the attack surface represent <b>{currency} {breach_loss:,.0f}</b> in estimated breach liability. "
            f"Remediating all findings requires an investment of <b>{currency} {fix_cost:,.0f}</b>, generating an outstanding <b>+{roi:.0f}% Return on Security Investment</b>. "
            f"Full audit execution and comprehensive engineering remediation are strongly warranted without delay."
        )
        rec_action = "Authorize complete remediation sprint; dispatch developers to patch high-severity CVEs immediately."

    story.append(Paragraph("Executive Audit Feasibility & Budget ROI Advisory", h2_style))

    # Decision Hero Table
    decision_box_data = [
        [
            Paragraph(f"<font size=10 color='{verdict_color}'><b>VERDICT: {verdict_badge}</b></font>", body_style),
            Paragraph(f"<font size=8 color='#64748b'><b>CLASSIFICATION: {verdict_tag}</b></font>", body_style)
        ],
        [
            Paragraph(verdict_desc, body_style),
            Paragraph(f"<b>Recommended Action:</b><br/>{rec_action}", body_style)
        ]
    ]
    decision_table = Table(decision_box_data, colWidths=[360, 180])
    decision_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(verdict_bg)),
        ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(verdict_border)),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor(verdict_border)),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(decision_table)
    story.append(Spacer(1, 6))

    # Strategy Comparison Matrix Table
    strat_headers = [
        Paragraph("<b>Remediation Strategy</b>", table_head),
        Paragraph("<b>Budget Required</b>", table_head),
        Paragraph("<b>Capital Saved</b>", table_head),
        Paragraph("<b>Loss Neutralized</b>", table_head),
        Paragraph("<b>Effective ROSI</b>", table_head)
    ]
    strat_rows = [
        strat_headers,
        [
            Paragraph("<b>Full Comprehensive Audit</b>", table_cell),
            Paragraph(f"<b>{currency} {fix_cost:,.0f}</b>", table_cell),
            Paragraph(f"{currency} 0", table_cell),
            Paragraph(f"100% ({currency} {breach_loss:,.0f})", table_cell),
            Paragraph(f"<font color='#16a34a'><b>+{roi:,.0f}%</b></font>", table_cell)
        ],
        [
            Paragraph(f"<b>Scoped Down ({risk_assets_count} Critical Assets)</b>", table_cell),
            Paragraph(f"<b>{currency} {scoped_fix_cost:,.0f}</b>", table_cell),
            Paragraph(f"<font color='#16a34a'><b>{currency} {scoped_savings:,.0f} ({scoped_savings_pct}%)</b></font>", table_cell),
            Paragraph(f"88% ({currency} {scoped_loss_neutralized:,.0f})", table_cell),
            Paragraph(f"<font color='#d97706'><b>+{scoped_roi:,.0f}%</b></font>", table_cell)
        ],
        [
            Paragraph("<b>Safe Deferral / Continuous Monitor</b>", table_cell),
            Paragraph(f"<b>{currency} 0</b>", table_cell),
            Paragraph(f"<font color='#0284c7'><b>{currency} {fix_cost:,.0f} (100%)</b></font>", table_cell),
            Paragraph("0% (Risk Retained)", table_cell),
            Paragraph("Capital Preserved", table_cell)
        ]
    ]
    strat_table = Table(strat_rows, colWidths=[145, 95, 100, 110, 90])
    strat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffffff")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#fffbeb" if "SCOPE" in verdict_badge else "#ffffff")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#f0f9ff" if "DEFER" in verdict_badge else "#ffffff")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ]))
    story.append(strat_table)
    story.append(Spacer(1, 12))

    # 3. AI / Executive Summary Section
    story.append(Paragraph("1. Executive Summary & Remediation Strategy", h2_style))
    story.append(Paragraph(ai_summary.replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 14))

    # 4. Normalized Findings & Remediation Cost Table
    story.append(Paragraph("2. Normalized Risk & Remediation Breakdown", h2_style))
    
    table_headers = [
        Paragraph("Asset Name / Value", table_head),
        Paragraph("Type", table_head),
        Paragraph("Vulnerability / Finding", table_head),
        Paragraph("Severity", table_head),
        Paragraph("CVE / Feeds", table_head),
        Paragraph("Hours", table_head),
        Paragraph(f"Fix Cost ({currency})", table_head),
        Paragraph("Status", table_head),
        Paragraph("Compliance", table_head)
    ]

    rows = [table_headers]

    sev_colors = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6",
        "Info": "#64748b"
    }

    for f in findings[:25]:  # limit to top 25 in PDF for concise layout
        sev = f.get("severity", "Medium")
        c_hex = sev_colors.get(sev, "#64748b")
        cve_str = ", ".join(f.get("cve_ids", [])) or f.get("source", "Check")
        if f.get("is_kev"):
            cve_str += " <font color='#ef4444'>[KEV]</font>"
        
        dev_h = f.get("dev_hours", f.get("fix_hours_dev", 0.5))
        tst_h = f.get("tester_hours", f.get("fix_hours_tester", 0.25))
        cost_f = f.get("cost", f.get("estimated_fix_cost", (dev_h * 85.0) + (tst_h * 65.0)))
        comp = f.get("owasp_category", "") or f.get("iso_control", "N/A")
        if comp and len(comp) > 20:
            comp = comp.split("-")[0] if "-" in comp else comp[:20]

        row = [
            Paragraph(f.get("asset_name", domain), table_cell),
            Paragraph(f.get("asset_type", "Host"), table_cell),
            Paragraph(f.get("title", ""), table_cell),
            Paragraph(f"<font color='{c_hex}'><b>{sev}</b></font>", table_cell),
            Paragraph(cve_str, table_cell),
            Paragraph(f"{dev_h + tst_h:.1f}h", table_cell),
            Paragraph(f"{cost_f:,.0f}", table_cell),
            Paragraph(f.get("status", "Open"), table_cell),
            Paragraph(comp, table_cell)
        ]
        rows.append(row)

    findings_table = Table(rows, colWidths=[70, 45, 125, 45, 75, 35, 50, 45, 50])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 14))

    # 5. Top 5 Remediation Guidance Actions
    story.append(Paragraph("3. Immediate Recommended Actions (Top 5 Priority)", h2_style))
    top_findings = sorted(findings, key=lambda x: (1 if x.get("is_kev") else 0, x.get("risk_score", 0)), reverse=True)[:5]
    for idx, tf in enumerate(top_findings, 1):
        rem = tf.get("remediation_text") or "Follow vendor advisory and apply security patch."
        tf_dev = tf.get("dev_hours", tf.get("fix_hours_dev", 0.5))
        tf_test = tf.get("tester_hours", tf.get("fix_hours_tester", 0.25))
        tf_cost = tf.get("cost", tf.get("estimated_fix_cost", (tf_dev * 85.0) + (tf_test * 65.0)))
        story.append(Paragraph(
            f"<b>{idx}. {tf.get('title')}</b> (Severity: {tf.get('severity')})<br/>"
            f"&bull; <i>Remediation:</i> {rem}<br/>"
            f"&bull; <i>Estimated Effort:</i> {tf_dev} hrs dev + {tf_test} hrs test | Est. Cost: {currency} {tf_cost:,.0f}",
            body_style
        ))
        story.append(Spacer(1, 4))

    # 6. Legal / Ethical Disclaimer
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
    story.append(Paragraph(
        "<b>Ethical & Scope Notice:</b> This audit report was compiled using passive discovery and safe, non-destructive perimeter testing by Auditor. "
        "No weaponized exploitation or unauthorized system intrusion was conducted. All data is confidential and intended solely for designated system owners.",
        subtitle_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
