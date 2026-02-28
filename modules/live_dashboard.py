"""Live Dashboard Server — real-time web dashboard with scan results viewer."""

import json, os
from datetime import datetime
from modules.core import console

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Snakebite Dashboard</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0a0a1a;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:20px;border-bottom:2px solid #0f3460;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:24px;color:#e94560}.header .meta{color:#888;font-size:13px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:15px;padding:20px}
.stat{background:#16213e;border-radius:10px;padding:20px;text-align:center;border:1px solid #0f3460}
.stat .n{font-size:36px;font-weight:bold}.stat .l{font-size:12px;color:#888;margin-top:5px}
.stat.c .n{color:#f44}.stat.h .n{color:#f80}.stat.m .n{color:#fc0}.stat.lo .n{color:#4af}.stat.t .n{color:#e94560}
.findings{padding:20px}.finding{background:#16213e;border-radius:8px;padding:15px;margin-bottom:10px;border-left:4px solid #0f3460;transition:.2s}
.finding:hover{background:#1a2940;transform:translateX(5px)}
.finding.critical{border-color:#f44}.finding.high{border-color:#f80}.finding.medium{border-color:#fc0}.finding.low{border-color:#4af}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-right:8px}
.badge.critical{background:#f44;color:#fff}.badge.high{background:#f80;color:#fff}.badge.medium{background:#fc0;color:#000}.badge.low{background:#4af;color:#fff}
.section{margin:20px;background:#16213e;border-radius:10px;padding:20px;border:1px solid #0f3460}
.section h2{font-size:18px;color:#e94560;margin-bottom:15px}
input{width:100%;padding:10px;background:#0a0a1a;border:1px solid #0f3460;border-radius:6px;color:#e0e0e0;font-size:14px}
.filter{padding:10px 20px;display:flex;gap:10px;flex-wrap:wrap}
.filter button{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:13px;background:#0f3460;color:#e0e0e0;transition:.2s}
.filter button:hover,.filter button.active{background:#e94560;color:#fff}
</style></head><body>
<div class="header"><h1>SNAKEBITE Dashboard</h1><div class="meta" id="meta"></div></div>
<div class="stats" id="stats"></div>
<div class="filter" id="filter"></div>
<div class="section"><h2>Search</h2><input id="search" placeholder="Search..." oninput="render()"></div>
<div class="findings" id="findings"></div>
<script>let D={},F='all';
function init(d){D=d;renderS();renderF();render();document.getElementById('meta').innerHTML='Target: '+(d.target||'?')+' | '+(d.timestamp||'')}
function renderS(){const s=D.stats||{};document.getElementById('stats').innerHTML=
'<div class="stat t"><div class="n">'+(s.total||0)+'</div><div class="l">TOTAL</div></div>'+
'<div class="stat c"><div class="n">'+(s.critical||0)+'</div><div class="l">CRITICAL</div></div>'+
'<div class="stat h"><div class="n">'+(s.high||0)+'</div><div class="l">HIGH</div></div>'+
'<div class="stat m"><div class="n">'+(s.medium||0)+'</div><div class="l">MEDIUM</div></div>'+
'<div class="stat lo"><div class="n">'+(s.low||0)+'</div><div class="l">LOW</div></div>'}
function renderF(){const c=[...new Set((D.findings||[]).map(f=>f.module||'?'))];
let h='<button class="active" onclick="sf(this,\\'all\\')">All</button>';
c.forEach(x=>{h+='<button onclick="sf(this,\\''+x+'\\')">'+x+'</button>'});document.getElementById('filter').innerHTML=h}
function sf(e,f){F=f;document.querySelectorAll('.filter button').forEach(b=>b.classList.remove('active'));e.classList.add('active');render()}
function render(){const q=(document.getElementById('search').value||'').toLowerCase();
let ff=(D.findings||[]).filter(f=>{if(F!=='all'&&f.module!==F)return false;if(q&&!JSON.stringify(f).toLowerCase().includes(q))return false;return true});
ff.sort((a,b)=>{const o={Critical:0,High:1,Medium:2,Low:3};return(o[a.severity]||4)-(o[b.severity]||4)});
let h='';ff.forEach(f=>{const s=(f.severity||'medium').toLowerCase();
h+='<div class="finding '+s+'"><div><span class="badge '+s+'">'+(f.severity||'?')+'</span><b>'+(f.type||'?')+'</b></div><div style="font-size:12px;color:#888;margin-top:4px">'+(f.detail||f.evidence||'')+'</div></div>'});
document.getElementById('findings').innerHTML=h||'<p style="text-align:center;color:#666">No findings</p>'}
</script></body></html>'''


def _collect(report):
    findings = []
    if not report:
        return findings
    for mod, data in report.items():
        if isinstance(data, dict):
            for f in data.get('findings', []):
                if isinstance(f, dict):
                    f['module'] = mod
                    findings.append(f)
    return findings


async def generate_dashboard(session, url, full_report=None, output_dir='.'):
    console.print(f"\n[bold cyan]--- Live Dashboard Generator ---[/bold cyan]")
    findings = _collect(full_report)
    stats = {'total': len(findings),
             'critical': len([f for f in findings if f.get('severity') == 'Critical']),
             'high': len([f for f in findings if f.get('severity') == 'High']),
             'medium': len([f for f in findings if f.get('severity') == 'Medium']),
             'low': len([f for f in findings if f.get('severity') == 'Low'])}
    data = {'target': url, 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'stats': stats, 'findings': findings}
    html = DASHBOARD_HTML.replace('</script>', f'\ninit({json.dumps(data, default=str)});\n</script>')
    from urllib.parse import urlparse
    fn = f'dashboard_{urlparse(url).hostname}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
    fp = os.path.join(output_dir, fn)
    try:
        with open(fp, 'w', encoding='utf-8') as f:
            f.write(html)
        console.print(f"  [green]Dashboard: {fn}[/green]")
    except Exception as e:
        console.print(f"  [red]{e}[/red]")
    console.print(f"  [red]Critical: {stats['critical']}[/red] | [yellow]High: {stats['high']}[/yellow] | [blue]Med: {stats['medium']}[/blue] | [dim]Low: {stats['low']}[/dim]")
    return {'file': fp, 'stats': stats}
