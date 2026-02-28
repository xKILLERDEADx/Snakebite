import asyncio
from modules.core import console

# ENV Extraction / Sensitive File Dump
# Targets: .env, web.config, settings.py, config.js
# Goal: Find hardcoded secrets.

SENSITIVE_FILES = [
    ".env",
    ".env.dev",
    ".env.prod",
    ".env.local",
    "config.json",
    "config.js",
    "web.config",
    "settings.py",
    "database.yml",
    "secrets.json"
]

async def check_env(session, url, file):
    try:
        # Construct path
        if url.endswith("/"):
            target = f"{url}{file}"
        else:
            target = f"{url}/{file}"
            
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # Verification: Look for KEY=VALUE format or specific keywords
            if resp.status == 200:
                if "APP_KEY" in text or "DB_PASSWORD" in text or "AWS_ACCESS_KEY" in text or "API_KEY" in text:
                     return {
                        "url": target,
                        "file": file,
                        "type": "Sensitive File Exposure",
                        "evidence": "Credentials/Keys found in file"
                    }
                # For JSON/YAML
                if (file.endswith("json") or file.endswith("js")) and ("password" in text or "secret" in text):
                     return {
                        "url": target,
                        "file": file,
                        "type": "Sensitive File Exposure",
                        "evidence": "Secrets found in config file"
                    }

    except Exception:
        pass
    return None

async def scan_env_dump(session, url):
    """
    Scan for ENV/Config File Exposure (Credential Theft).
    """
    console.print(f"\n[bold cyan]--- ENV/Config Dump Scanner ---[/bold cyan]")
    
    # Check Root
    tasks = [check_env(session, url, f) for f in SENSITIVE_FILES]
    
    # Also Check common subdirs if they exist in URL context? 
    # For now, just root.
    
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] SENSITIVE FILE EXPOSED: {res['url']}[/bold red]")
             console.print(f"      Evidence: {res['evidence']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No accessible ENV/Config files found.[/dim]")
        
    return found
