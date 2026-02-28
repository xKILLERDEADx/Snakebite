import asyncio
import re
from modules.core import console

# DOM XSS Scanner
# Vulnerability: Processing data from an untrusted "source" (URL, hash) in an unsafe "sink" (innerHTML, eval).
# Engine: Static Analysis of Response Body/Scripts.

SOURCES = [
    r"location\.search", r"location\.hash", r"location\.href", 
    r"document\.URL", r"document\.referrer", r"window\.name"
]

SINKS = [
    r"innerHTML", r"outerHTML", r"document\.write", r"document\.writeln", 
    r"eval\(", r"setTimeout\(", r"setInterval\(", r"\$\("
]

async def check_dom_xss(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Simple Static Analysis: Look for Source AND Sink near each other locally?
            # Or just presence of both in same script block.
            
            # Extract script blocks
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL)
            
            findings = []
            
            for script in scripts:
                found_source = None
                found_sink = None
                
                for source in SOURCES:
                    if re.search(source, script):
                        found_source = source
                        break
                        
                for sink in SINKS:
                    if re.search(sink, script):
                        found_sink = sink
                        break
                        
                if found_source and found_sink:
                    # We found a script using a dangerous source and a dangerous sink.
                    # This is a HIGH PROBABILITY DOM XSS candidate.
                    findings.append(f"Source: {found_source} -> Sink: {found_sink}")
            
            if findings:
                 return {
                    "url": url,
                    "type": "DOM XSS (Static Analysis)",
                    "evidence": " | ".join(findings)
                }

    except Exception:
        pass
    return None

async def scan_dom_xss(session, url):
    """
    Scan for DOM-based XSS (Client-Side).
    """
    console.print(f"\n[bold cyan]--- DOM XSS Scanner ---[/bold cyan]")
    
    results = []
    res = await check_dom_xss(session, url)
    
    if res:
         console.print(f"  [bold red][!] DOM XSS CANDIDATE FOUND: {res['url']}[/bold red]")
         console.print(f"      Pairs: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No obvious DOM XSS patterns found in inline scripts.[/dim]")
        
    return results
