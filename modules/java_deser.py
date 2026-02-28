import asyncio
import re
from modules.core import console

# Magic bytes detection
JAVA_MAGIC = ["rO0", "H4s"] # rO0 (Java Ser), H4s (Gzip usually wraps it)

async def check_java_deser(session, url):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            vulns = []
            
            # Check Set-Cookie headers
            for k, v in resp.headers.items():
                if k == "Set-Cookie":
                    for magic in JAVA_MAGIC:
                        if magic in v:
                             vulns.append({
                                 "url": url,
                                 "location": "Header (Set-Cookie)",
                                 "evidence": v[:20] + "...",
                                 "type": "Java Deserialization (Likely)"
                             })
                             
            # Check Body (Hidden fields, ViewState-like params)
            text = await resp.text()
            # Simple regex for base64 strings starting with magic
            # H4sIA... is common for Gzipped objects
            found = re.findall(r'(H4sIA[a-zA-Z0-9+/=]+)', text)
            for f in found:
                 vulns.append({
                     "url": url,
                     "location": "Body (Base64)",
                     "evidence": f[:20] + "...",
                     "type": "Java Deserialization (Potential)"
                 })
                 
            # rO0... is raw Java serialization
            found_raw = re.findall(r'(rO0[a-zA-Z0-9+/=]+)', text)
            for f in found_raw:
                 vulns.append({
                     "url": url,
                     "location": "Body (Base64)",
                     "evidence": f[:20] + "...",
                     "type": "Java Deserialization (Critical)"
                 })
                 
            return vulns
            
    except Exception:
        pass
    return []

async def scan_java_deser(session, urls):
    """
    Scan for Java Deserialization Signatures.
    """
    console.print(f"\n[bold cyan]--- Java Deserialization Scanner ---[/bold cyan]")
    
    targets = urls[:30]
    if not targets:
         console.print("[yellow][!] No URLs to scan.[/yellow]")
         return []
         
    console.print(f"[dim]Inspecting {len(targets)} pages for Serialized Objects...[/dim]")
    
    tasks = [check_java_deser(session, u) for u in targets]
    results_list = await asyncio.gather(*tasks)
    
    # Flatten
    all_vulns = []
    for r in results_list:
        if r:
            all_vulns.extend(r)
            
    for v in all_vulns:
         console.print(f"  [bold red][!] JAVA DESERIALIZATION SIGNATURE FOUND![/bold red]")
         console.print(f"      URL: {v['url']}")
         console.print(f"      Loc: {v['location']}")
         console.print(f"      Data: {v['evidence']}")
         
    if not all_vulns:
        console.print("[green][+] No Java serialized objects detected.[/green]")
        
    return all_vulns
