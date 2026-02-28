import asyncio
from modules.core import console

# XSLT Payloads
# Simple check: Try to inject a value that breaks syntax or executes a math function
XSLT_PAYLOADS = [
    '<xsl:value-of select="system-property(\'xsl:vendor\')"/>',
    '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">',
]

async def check_xslt(session, url, param):
    try:
        # We try to inject a vendor property check which usually returns "Microsoft" or "Libxslt" etc.
        payload = '1"]<xsl:value-of select="system-property(\'xsl:vendor\')"/>'
        # Note: XSLT injection context varies wildly (inside value-of, inside template, etc).
        # We use a polyglot-ish approach or simple error induction.
        
        target = f"{url}?{param}={payload}"
        if "?" in url: target = f"{url}&{param}={payload}"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Indicators
            if "libxslt" in text.lower() or "sax" in text.lower() or "xalan" in text.lower():
                 return {
                    "url": target,
                    "param": param,
                    "type": "XSLT Injection (Vendor Leak)",
                    "evidence": "XSLT Engine Name Revealed"
                }
            
            if "xsltparse" in text.lower() or "xml parse error" in text.lower():
                 return {
                    "url": target,
                    "param": param,
                    "type": "XSLT Injection (Error)",
                    "evidence": "XML/XSLT Error Message"
                }
    except Exception:
        pass
    return None

async def scan_xslt(session, url):
    """
    Scan for XSLT Injection.
    """
    console.print(f"\n[bold cyan]--- XSLT Injection Scanner ---[/bold cyan]")
    
    # Check XML related params
    params = ["xml", "xsl", "template", "style", "doc", "report"]
    
    tasks = [check_xslt(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] XSLT INJECTION INDICATED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No XSLT injection indicators found.[/dim]")
        
    return found
