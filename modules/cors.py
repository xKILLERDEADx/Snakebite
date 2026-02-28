import asyncio
from modules.core import console

async def check_cors(session, url, origin_payload):
    headers = {
        'Origin': origin_payload,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        async with session.get(url, headers=headers, timeout=5, ssl=False) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao:
                # Vulnerability: Reflection of Origin + Credentials=True
                if (acao == origin_payload and acac == 'true'):
                     return {
                         "url": url,
                         "type": "CORS Misconfiguration (Trusts Arbitrary Origin + Creds)",
                         "origin": origin_payload,
                         "severity": "CRITICAL"
                     }
                # Vulnerability: Wildcard + Credentials (rare but invalid spec, usually ignoring creds)
                elif (acao == "*" and acac == 'true'):
                     return {
                         "url": url,
                         "type": "CORS Misconfiguration (Wildcard + Creds)",
                         "origin": "*",
                         "severity": "HIGH"
                     }
                # Vulnerability: Null Origin reflection
                elif (origin_payload == "null" and acao == "null" and acac == "true"):
                     return {
                         "url": url,
                         "type": "CORS Misconfiguration (Trusts Null Origin)",
                         "origin": "null",
                         "severity": "HIGH"
                     }
    except Exception:
        pass
    return None

async def scan_cors(session, url):
    """
    Test for CORS flaws.
    """
    console.print(f"\n[bold cyan]--- CORS Misconfiguration Scanner ---[/bold cyan]")
    
    payloads = [
        "https://evil.com",
        "null",
        f"{url}.evil.com"
    ]
    
    console.print(f"[dim]Testing CORS against {len(payloads)} logic patterns...[/dim]")
    
    tasks = [check_cors(session, url, p) for p in payloads]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] {res['type']}[/bold red]")
             console.print(f"      Reflected Origin: {res['origin']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No CORS vulnerabilities detected.[/green]")
        
    return vulns
