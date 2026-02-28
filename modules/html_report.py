"""Interactive HTML Dashboard Report — generates beautiful HTML scan report."""

import json
import os
from datetime import datetime
from modules.core import console

def _severity_color(severity):
    colors = {
        'Critical': '#e74c3c', 'High': '#e67e22', 'Medium': '#f39c12',
        'Low': '#3498db', 'Info': '#95a5a6'
    }
    return colors.get(severity, '#95a5a6')

def _generate_html(report_data, owasp_data=None):
    """Generate the full HTML dashboard."""
    target = report_data.get('target', 'Unknown')
    timestamp = report_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    all_findings = []

    skip_keys = {'target', 'timestamp', 'recon', 'cms', 'cms_details',
                 'speed', 'ports', 'subdomains', 'crawl', 'scan_date',
                 'duration', 'wayback', 'dns_zone', 'vhosts', 'session_tokens',
                 'param_discovery', 'google_dorks', 'shodan', 'virustotal',
                 'github_leaks'}

    for module_name, module_data in report_data.items():
        if module_name in skip_keys:
            continue
        if isinstance(module_data, list):
            for item in module_data:
                if isinstance(item, dict):
                    sev = item.get('severity', 'Info')
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    all_findings.append({**item, 'module': module_name})

    total = sum(severity_counts.values())
    grade = owasp_data.get('grade', 'N/A') if owasp_data else 'N/A'
    grade_color = {'A+': '#27ae60', 'A': '#27ae60', 'B': '#2980b9',
                   'C': '#f39c12', 'D': '#e67e22', 'F': '#e74c3c'}.get(grade, '#95a5a6')

    recon = report_data.get('recon', {})
    ports = report_data.get('ports', [])

    findings_rows = ''
    for f in sorted(all_findings, key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}.get(x.get('severity', 'Info'), 5)):
        sev = f.get('severity', 'Info')
        findings_rows += f'''
        <tr>
            <td><span class="badge" style="background:{_severity_color(sev)}">{sev}</span></td>
            <td>{f.get('module', '')}</td>
            <td>{f.get('type', f.get('vulnerability', ''))}</td>
            <td class="url-cell">{f.get('url', '')[:80]}</td>
            <td>{f.get('cve', '')}</td>
        </tr>'''

    owasp_rows = ''
    if owasp_data:
        try:
            from modules.owasp_check import OWASP_TOP_10
            cats = owasp_data.get('categories', {})
            for oid in sorted(OWASP_TOP_10.keys()):
                count = cats.get(oid, 0)
                status = f'<span class="badge" style="background:#e74c3c">FAIL ({count})</span>' if count > 0 else '<span class="badge" style="background:#27ae60">PASS</span>'
                owasp_rows += f'<tr><td>{oid}</td><td>{OWASP_TOP_10[oid]["name"]}</td><td>{status}</td></tr>'
        except Exception:
            pass

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Snakebite Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    border-radius: 16px; padding: 30px; margin-bottom: 20px; border: 1px solid #333; }}
  .header h1 {{ font-size: 28px; color: #00d4ff; margin-bottom: 8px; }}
  .header .meta {{ color: #888; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }}
  .card {{ background: #1a1a2e; border-radius: 12px; padding: 20px; text-align: center; border: 1px solid #333; }}
  .card:hover {{ transform: translateY(-3px); border-color: #00d4ff; transition: 0.2s; }}
  .card .number {{ font-size: 36px; font-weight: bold; }}
  .card .label {{ font-size: 13px; color: #888; margin-top: 4px; }}
  .grade-card .number {{ font-size: 48px; color: {grade_color}; }}
  .section {{ background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #333; }}
  .section h2 {{ color: #00d4ff; font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #16213e; color: #00d4ff; padding: 12px 8px; text-align: left; font-size: 13px; }}
  td {{ padding: 10px 8px; border-bottom: 1px solid #222; font-size: 13px; }}
  tr:hover {{ background: #16213e40; }}
  .badge {{ padding: 4px 10px; border-radius: 20px; color: white; font-size: 11px; font-weight: 600; }}
  .url-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #7ec8e3; }}
  .filter-bar {{ margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .filter-btn {{ padding: 6px 16px; border-radius: 20px; border: 1px solid #333; background: transparent;
    color: #e0e0e0; cursor: pointer; font-size: 13px; }}
  .filter-btn:hover, .filter-btn.active {{ background: #00d4ff; color: #000; border-color: #00d4ff; }}
  .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px; }}
  .info-item .key {{ color: #00d4ff; font-size: 12px; text-transform: uppercase; }}
  .info-item .val {{ font-size: 15px; margin-top: 2px; }}
  .footer {{ text-align: center; padding: 20px; color: #555; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Snakebite Security Report</h1>
    <div class="meta">Target: <strong>{target}</strong> | {timestamp}</div>
  </div>
  <div class="cards">
    <div class="card grade-card"><div class="number">{grade}</div><div class="label">Security Grade</div></div>
    <div class="card"><div class="number" style="color:#e74c3c">{severity_counts["Critical"]}</div><div class="label">Critical</div></div>
    <div class="card"><div class="number" style="color:#e67e22">{severity_counts["High"]}</div><div class="label">High</div></div>
    <div class="card"><div class="number" style="color:#f39c12">{severity_counts["Medium"]}</div><div class="label">Medium</div></div>
    <div class="card"><div class="number" style="color:#3498db">{severity_counts["Low"]}</div><div class="label">Low</div></div>
    <div class="card"><div class="number" style="color:#27ae60">{total}</div><div class="label">Total</div></div>
  </div>
  <div class="section">
    <h2>Reconnaissance</h2>
    <div class="info-grid">
      <div class="info-item"><div class="key">IP</div><div class="val">{recon.get('ip', 'N/A')}</div></div>
      <div class="info-item"><div class="key">Server</div><div class="val">{recon.get('server', 'N/A')}</div></div>
      <div class="info-item"><div class="key">WAF</div><div class="val">{recon.get('waf', 'N/A')}</div></div>
      <div class="info-item"><div class="key">Open Ports</div><div class="val">{len(ports) if isinstance(ports, list) else 0}</div></div>
    </div>
  </div>
  {"<div class='section'><h2>OWASP Top 10</h2><table><tr><th>ID</th><th>Category</th><th>Status</th></tr>" + owasp_rows + "</table></div>" if owasp_rows else ""}
  <div class="section">
    <h2>Vulnerabilities ({total})</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterTable('all')">All</button>
      <button class="filter-btn" onclick="filterTable('Critical')">Critical</button>
      <button class="filter-btn" onclick="filterTable('High')">High</button>
      <button class="filter-btn" onclick="filterTable('Medium')">Medium</button>
      <button class="filter-btn" onclick="filterTable('Low')">Low</button>
    </div>
    <table id="ft"><tr><th>Severity</th><th>Module</th><th>Type</th><th>URL</th><th>CVE</th></tr>{findings_rows}</table>
  </div>
  <div class="footer">Generated by Snakebite Security Scanner</div>
</div>
<script>
function filterTable(s){{var r=document.querySelectorAll('#ft tr:not(:first-child)');document.querySelectorAll('.filter-btn').forEach(function(b){{b.classList.remove('active')}});event.target.classList.add('active');r.forEach(function(row){{row.style.display=s==='all'?'':row.cells[0].textContent.trim()===s?'':'none'}})}}
</script>
</body>
</html>'''
    return html


def generate_html_report(report_data, output_path=None, owasp_data=None):
    """Generate interactive HTML dashboard report."""
    console.print(f"\n[bold cyan]--- HTML Dashboard Report ---[/bold cyan]")

    if not output_path:
        target = report_data.get('target', 'scan')
        from urllib.parse import urlparse
        domain = urlparse(target).netloc.replace(':', '_') if target.startswith('http') else 'scan'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"snakebite_report_{domain}_{timestamp}.html"

    html = _generate_html(report_data, owasp_data)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    file_size = os.path.getsize(output_path)
    console.print(f"  [bold green]HTML report saved: {output_path} ({file_size:,} bytes)[/bold green]")
    return output_path
