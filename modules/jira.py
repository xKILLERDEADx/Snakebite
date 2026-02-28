import asyncio
from modules.core import console

# Atlassian Jira Scanner (Issue Tracker RCE)
# Focus: CVE-2019-11581 (Template Injection RCE).
# Endpoint: /secure/ContactAdministrators!default.jspa

async def check_jira(session, url):
    try:
        # Check if it's Jira
        # Header: X-Atlassian-Token: no-check
        # Body: jira.webresources
        
        target = f"{url.rstrip('/')}/secure/ContactAdministrators!default.jspa"
        
        async with session.get(target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                if "Contact Administrators" in text:
                    # Endpoint exists.
                    # This CVE requires the 'Contact Administrators' form to be enabled and configured.
                    # It's hard to verify RCE safely without sending emails or causing side effects.
                    # We flag the EXPOSURE of the form on a potentially vulnerable version.
                    
                    # We can check version in meta tags: <meta name="application-name" content="JIRA" data-name="jira" data-version="8.2.0">
                    version = "Unknown"
                    if 'data-version="' in text:
                        try:
                            version = text.split('data-version="')[1].split('"')[0]
                        except Exception:
                            pass
                    
                    return {
                        "url": target,
                        "type": "Jira Contact Admin Form Exposed",
                        "evidence": f"Potential CVE-2019-11581 vector. Version: {version}"
                    }

    except Exception:
        pass
    return None

async def scan_jira(session, url):
    """
    Scan for Atlassian Jira Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Jira Scanner ---[/bold cyan]")
    
    results = []
    res = await check_jira(session, url)
    if res:
         console.print(f"  [bold red][!] JIRA EXPOSED: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Jira critical vectors found.[/dim]")
        
    return results
