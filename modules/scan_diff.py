"""Scan Comparison — diff two JSON reports to show new/resolved vulnerabilities."""

import json
import os
from modules.core import console

def _extract_findings(report):
    """Extract all findings from a scan report as a normalized set."""
    findings = []

    vulns = report.get('vulnerabilities', {})
    for mod_name, mod_results in vulns.items():
        if isinstance(mod_results, list):
            for item in mod_results:
                if isinstance(item, dict):
                    finding = {
                        'module': mod_name,
                        'type': item.get('type', item.get('vulnerability', mod_name)),
                        'url': item.get('url', ''),
                        'severity': item.get('severity', 'Medium'),
                        'payload': item.get('payload', ''),
                        'cve': item.get('cve', ''),
                    }
                    findings.append(finding)

    for key in report:
        if key in ('target', 'timestamp', 'recon', 'cms', 'cms_details', 'speed',
                    'ports', 'subdomains', 'crawl', 'vulnerabilities', 'findings',
                    'secrets', 'scan_date', 'duration'):
            continue
        data = report[key]
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and ('vulnerability' in item or 'type' in item or 'url' in item):
                    finding = {
                        'module': key,
                        'type': item.get('type', item.get('vulnerability', key)),
                        'url': item.get('url', ''),
                        'severity': item.get('severity', 'Medium'),
                        'payload': item.get('payload', ''),
                        'cve': item.get('cve', ''),
                    }
                    findings.append(finding)

    return findings


def _finding_key(finding):
    """Create a unique key for a finding to enable comparison."""
    return f"{finding['module']}|{finding['type']}|{finding['url']}"


def compare_scans(report1_path, report2_path):
    """Compare two scan reports and show differences."""
    console.print(f"\n[bold cyan]--- Scan Comparison ---[/bold cyan]")
    console.print(f"  [dim]Old: {os.path.basename(report1_path)}[/dim]")
    console.print(f"  [dim]New: {os.path.basename(report2_path)}[/dim]\n")

    try:
        with open(report1_path, 'r', encoding='utf-8') as f:
            report1 = json.load(f)
        with open(report2_path, 'r', encoding='utf-8') as f:
            report2 = json.load(f)
    except FileNotFoundError as e:
        console.print(f"  [red]File not found: {e}[/red]")
        return {}
    except json.JSONDecodeError as e:
        console.print(f"  [red]Invalid JSON: {e}[/red]")
        return {}

    findings1 = _extract_findings(report1)
    findings2 = _extract_findings(report2)

    keys1 = {_finding_key(f): f for f in findings1}
    keys2 = {_finding_key(f): f for f in findings2}

    new_vulns = [keys2[k] for k in keys2 if k not in keys1]
    resolved_vulns = [keys1[k] for k in keys1 if k not in keys2]
    persistent_vulns = [keys2[k] for k in keys2 if k in keys1]

    severity_changes = []
    for k in keys2:
        if k in keys1 and keys1[k]['severity'] != keys2[k]['severity']:
            severity_changes.append({
                'finding': keys2[k],
                'old_severity': keys1[k]['severity'],
                'new_severity': keys2[k]['severity'],
            })

    results = {
        'old_report': report1_path,
        'new_report': report2_path,
        'old_count': len(findings1),
        'new_count': len(findings2),
        'new_vulns': new_vulns,
        'resolved_vulns': resolved_vulns,
        'persistent_vulns': persistent_vulns,
        'severity_changes': severity_changes,
    }

    console.print(f"  [bold]Summary:[/bold]")
    console.print(f"    Old scan: {len(findings1)} findings")
    console.print(f"    New scan: {len(findings2)} findings")
    console.print(f"    Δ Change: {len(findings2) - len(findings1):+d}\n")

    if new_vulns:
        console.print(f"  [bold red]🆕 NEW Vulnerabilities ({len(new_vulns)}):[/bold red]")
        sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        new_vulns.sort(key=lambda x: sev_order.get(x['severity'], 5))
        for v in new_vulns[:20]:
            sev_color = {'Critical': 'red', 'High': 'red', 'Medium': 'yellow', 'Low': 'blue', 'Info': 'dim'}.get(v['severity'], 'dim')
            console.print(f"    [{sev_color}][{v['severity']}][/{sev_color}] {v['type']} — {v['url'][:80]}")

    if resolved_vulns:
        console.print(f"\n  [bold green]✅ RESOLVED Vulnerabilities ({len(resolved_vulns)}):[/bold green]")
        for v in resolved_vulns[:20]:
            console.print(f"    [green]✓ [{v['severity']}] {v['type']} — {v['url'][:80]}[/green]")

    if severity_changes:
        console.print(f"\n  [bold yellow]⚠ Severity Changes ({len(severity_changes)}):[/bold yellow]")
        for sc in severity_changes[:10]:
            console.print(f"    {sc['finding']['type']}: {sc['old_severity']} → {sc['new_severity']}")

    if persistent_vulns:
        console.print(f"\n  [dim]Persistent (unchanged): {len(persistent_vulns)} findings[/dim]")

    if not new_vulns and not resolved_vulns:
        console.print(f"  [green]✓ No changes between scans[/green]")

    return results
