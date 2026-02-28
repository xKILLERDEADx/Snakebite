import asyncio
from modules.core import console

# CSP Bypass Scanner (Policy Audit)
# Vulnerability: Content-Security-Policy is meant to prevent XSS, but weak configurations allow bypass.
# We check for: 'unsafe-inline', 'unsafe-eval', wildcards '*', data: URIs, missing object-src.

async def check_csp_weakness(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            headers = resp.headers
            csp = headers.get("Content-Security-Policy", "")
            
            if not csp:
                # Missing CSP is bad, but we are looking for *Bypassable* CSP.
                # Only report if user requested deep security audit, otherwise it's noise.
                # Let's return a "Missing" finding but marked Low.
                return {
                    "url": url,
                    "type": "CSP Missing",
                    "evidence": "No Content-Security-Policy header found."
                }
                
            findings = []
            
            # 1. Unsafe Inline
            if "'unsafe-inline'" in csp:
                findings.append("'unsafe-inline' enabled (XSS possible)")
                
            # 2. Unsafe Eval
            if "'unsafe-eval'" in csp:
                findings.append("'unsafe-eval' enabled (DOM XSS possible)")
                
            # 3. Wildcards
            if "script-src *" in csp or "default-src *" in csp:
                findings.append("Wildcard '*' in script source")
                
            # 4. Data URI
            if "data:" in csp:
                findings.append("data: URI allowed (Phishing/XSS)")
                
            # 5. Missing Object-Src (Flash/Plugin XSS)
            if "object-src" not in csp and "default-src" not in csp:
                 findings.append("Missing object-src (Flash XSS risk)")
                 
            if findings:
                 return {
                    "url": url,
                    "type": "Weak CSP Configuration",
                    "evidence": ", ".join(findings),
                    "full_csp": csp
                }

    except Exception:
        pass
    return None

async def scan_csp_bypass(session, url):
    """
    Scan for CSP Weaknesses (Policy Bypass).
    """
    console.print(f"\n[bold cyan]--- CSP Security Audit ---[/bold cyan]")
    
    results = []
    res = await check_csp_weakness(session, url)
    
    if res:
        if res['type'] == "CSP Missing":
             console.print(f"  [yellow][-] CSP Missing on {url}[/yellow]")
        else:
             console.print(f"  [bold red][!] WEAK CSP DETECTED: {res['url']}[/bold red]")
             console.print(f"      Issues: {res['evidence']}")
             results.append(res)
    else:
        console.print("[dim][+] Strong CSP found (or no obvious weaknesses).[/dim]")
        
    return results
