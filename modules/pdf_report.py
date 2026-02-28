"""Professional PDF Security Report Generator for Snakebite v2.0.
Uses HTML template converted to PDF via built-in webbrowser or reportlab."""

import json
import os
from datetime import datetime
from modules.core import console

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Image as RLImage
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False


DARK_BG = HexColor('#1a1a2e') if _REPORTLAB_AVAILABLE else None
DARK_CARD = HexColor('#16213e') if _REPORTLAB_AVAILABLE else None
ACCENT_RED = HexColor('#e94560') if _REPORTLAB_AVAILABLE else None
ACCENT_GREEN = HexColor('#0f3460') if _REPORTLAB_AVAILABLE else None
TEXT_WHITE = HexColor('#eaeaea') if _REPORTLAB_AVAILABLE else None
TEXT_DIM = HexColor('#888888') if _REPORTLAB_AVAILABLE else None

SEVERITY_COLORS_HEX = {
    "Critical": '#FF0000',
    "High": '#FF6600',
    "Medium": '#FFCC00',
    "Low": '#00CCFF',
    "Info": '#808080',
}


def _get_styles():
    """Create custom PDF styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='CoverTitle',
        fontSize=32,
        textColor=HexColor('#e94560'),
        spaceAfter=20,
        fontName='Helvetica-Bold',
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        name='CoverSubtitle',
        fontSize=14,
        textColor=HexColor('#888888'),
        spaceAfter=10,
        fontName='Helvetica',
        alignment=1,
    ))
    styles.add(ParagraphStyle(
        name='SectionHeader',
        fontSize=18,
        textColor=HexColor('#e94560'),
        spaceAfter=12,
        spaceBefore=20,
        fontName='Helvetica-Bold',
    ))
    styles.add(ParagraphStyle(
        name='SubHeader',
        fontSize=13,
        textColor=HexColor('#0f3460'),
        spaceAfter=8,
        spaceBefore=12,
        fontName='Helvetica-Bold',
    ))
    styles.add(ParagraphStyle(
        name='BodyDark',
        fontSize=10,
        textColor=HexColor('#333333'),
        spaceAfter=4,
        fontName='Helvetica',
    ))
    styles.add(ParagraphStyle(
        name='FindingTitle',
        fontSize=11,
        textColor=HexColor('#FF0000'),
        spaceAfter=4,
        fontName='Helvetica-Bold',
    ))

    return styles


def generate_pdf_report(report_data, output_path):
    """Generate a professional PDF security report."""
    if not _REPORTLAB_AVAILABLE:
        console.print("[yellow][!] reportlab not installed. Run: pip install reportlab[/yellow]")
        console.print("[yellow]    Falling back to HTML report only.[/yellow]")
        return False

    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50,
        )

        styles = _get_styles()
        story = []

        story.append(Spacer(1, 2 * inch))
        story.append(Paragraph("🐍 SNAKEBITE v2.0", styles['CoverTitle']))
        story.append(Paragraph("Advanced Web Security Assessment Report", styles['CoverSubtitle']))
        story.append(Spacer(1, 0.5 * inch))

        target = report_data.get('target', 'N/A')
        scan_date = report_data.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        duration = report_data.get('duration', 'N/A')

        cover_data = [
            ['Target', target],
            ['Scan Date', scan_date],
            ['Duration', str(duration)],
            ['Scanner', 'Snakebite v2.0'],
        ]
        cover_table = Table(cover_data, colWidths=[120, 350])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#eaeaea')),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor('#333333')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ]))
        story.append(cover_table)
        story.append(PageBreak())

        story.append(Paragraph("Executive Summary", styles['SectionHeader']))

        all_findings = report_data.get('findings', [])
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in all_findings:
            sev = f.get('severity', 'Info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_vulns = len(all_findings)
        risk_level = "CRITICAL" if severity_counts['Critical'] > 0 else "HIGH" if severity_counts['High'] > 0 else "MEDIUM" if severity_counts['Medium'] > 0 else "LOW"

        story.append(Paragraph(
            f"This security assessment identified <b>{total_vulns}</b> vulnerabilities "
            f"with an overall risk rating of <b>{risk_level}</b>.",
            styles['BodyDark']
        ))
        story.append(Spacer(1, 12))

        summary_data = [
            ['Severity', 'Count'],
            ['🔴 Critical', str(severity_counts.get('Critical', 0))],
            ['🟠 High', str(severity_counts.get('High', 0))],
            ['🟡 Medium', str(severity_counts.get('Medium', 0))],
            ['🔵 Low', str(severity_counts.get('Low', 0))],
            ['⚪ Info', str(severity_counts.get('Info', 0))],
            ['TOTAL', str(total_vulns)],
        ]
        summary_table = Table(summary_data, colWidths=[200, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#eaeaea')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ('BACKGROUND', (0, -1), (-1, -1), HexColor('#e94560')),
            ('TEXTCOLOR', (0, -1), (-1, -1), HexColor('#ffffff')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ]))
        story.append(summary_table)
        story.append(PageBreak())

        if all_findings:
            story.append(Paragraph("Detailed Findings", styles['SectionHeader']))

            for i, finding in enumerate(all_findings, 1):
                severity = finding.get('severity', 'Info')
                vuln_type = finding.get('type', finding.get('vulnerability', 'Unknown'))
                url = finding.get('url', 'N/A')
                payload = finding.get('payload', '')
                evidence = finding.get('evidence', '')
                cve = finding.get('cve', '')
                cvss = finding.get('cvss', '')

                sev_color = SEVERITY_COLORS_HEX.get(severity, '#808080')
                story.append(Paragraph(
                    f'<font color="{sev_color}">#{i} [{severity}]</font> {vuln_type}',
                    styles['FindingTitle']
                ))
                story.append(Paragraph(f"<b>URL:</b> {url[:120]}", styles['BodyDark']))
                if cve:
                    story.append(Paragraph(f"<b>CVE:</b> {cve} (CVSS: {cvss})", styles['BodyDark']))
                if payload:
                    story.append(Paragraph(f"<b>Payload:</b> <font face='Courier'>{payload[:150]}</font>", styles['BodyDark']))
                if evidence:
                    story.append(Paragraph(f"<b>Evidence:</b> {evidence[:200]}", styles['BodyDark']))

                exploit_suggestions = finding.get('exploit_suggestions', [])
                if exploit_suggestions:
                    story.append(Paragraph("<b>⚡ Exploit Suggestions:</b>", styles['BodyDark']))
                    for es in exploit_suggestions[:3]:
                        story.append(Paragraph(
                            f"  • <b>{es['tool']}:</b> {es['description']}",
                            styles['BodyDark']
                        ))
                        story.append(Paragraph(
                            f"    <font face='Courier' size='8'>{es['command'][:120]}</font>",
                            styles['BodyDark']
                        ))

                story.append(Spacer(1, 12))

        recon_data = report_data.get('recon', {})
        if recon_data:
            story.append(PageBreak())
            story.append(Paragraph("Reconnaissance Intelligence", styles['SectionHeader']))

            whois = recon_data.get('whois', {})
            if whois and 'error' not in whois:
                story.append(Paragraph("WHOIS Information", styles['SubHeader']))
                whois_items = [
                    ['Domain', str(whois.get('domain_name', 'N/A'))],
                    ['Registrar', str(whois.get('registrar', 'N/A'))],
                    ['Created', str(whois.get('created', 'N/A'))],
                    ['Expires', str(whois.get('expires', 'N/A'))],
                    ['Country', str(whois.get('country', 'N/A'))],
                    ['Organization', str(whois.get('org', 'N/A'))],
                ]
                whois_table = Table(whois_items, colWidths=[120, 350])
                whois_table.setStyle(TableStyle([
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ]))
                story.append(whois_table)
                story.append(Spacer(1, 12))

            geo = recon_data.get('geolocation', {})
            if geo:
                story.append(Paragraph("IP Intelligence", styles['SubHeader']))
                geo_items = [
                    ['IP', str(geo.get('ip', 'N/A'))],
                    ['Country', str(geo.get('country', 'N/A'))],
                    ['City', str(geo.get('city', 'N/A'))],
                    ['ISP', str(geo.get('isp', 'N/A'))],
                    ['ASN', str(geo.get('asn', 'N/A'))],
                ]
                geo_table = Table(geo_items, colWidths=[120, 350])
                geo_table.setStyle(TableStyle([
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('PADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ]))
                story.append(geo_table)

        ports = report_data.get('ports', [])
        if ports:
            story.append(Paragraph("Open Ports", styles['SubHeader']))
            port_header = [['Port', 'Service', 'Status']]
            for p in ports[:30]:
                port_header.append([
                    str(p.get('port', '')),
                    str(p.get('service', '')),
                    str(p.get('status', 'Open'))
                ])
            port_table = Table(port_header, colWidths=[80, 200, 100])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#eaeaea')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
            ]))
            story.append(port_table)

        story.append(PageBreak())
        story.append(Spacer(1, 2 * inch))
        story.append(Paragraph("— End of Report —", styles['CoverSubtitle']))
        story.append(Paragraph("Generated by Snakebite v2.0 Advanced Web Security Scanner", styles['CoverSubtitle']))
        story.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['CoverSubtitle']))

        doc.build(story)
        console.print(f"  [bold green]📄 PDF Report saved:[/bold green] {output_path}")
        return True

    except Exception as e:
        console.print(f"[red][!] PDF generation failed: {e}[/red]")
        return False
