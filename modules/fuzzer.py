import asyncio
from modules.core import console

# Common high-value targets
SENSITIVE_FILES = [
    ".env",
    ".git/HEAD",
    ".svn/entries",
    ".ds_store",
    ".vscode/sftp.json",
    "web.config",
    "docker-compose.yml",
    "package.json",
    "backup.sql",
    "database.sql",
    "backup.zip",
    "www.zip",
    "site.tar.gz",
    "id_rsa",
    "id_rsa.pub",
    ".bash_history",
    "wp-config.php.bak",
    "config.php.bak",
    ".htaccess"
]

async def check_file(session, url, filename):
    target = f"{url.rstrip('/')}/{filename}"
    try:
        async with session.get(target, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                # Basic False Positive Check (Ensure not a custom 404 page returning 200)
                if len(await resp.read()) > 0:
                    return {"url": target, "file": filename}
    except Exception:
        pass
    return None

async def run_fuzzer(session, url):
    """
    Fuzz for sensitive backup and config files.
    """
    console.print(f"\n[bold cyan]--- Sensitive File Fuzzer ---[/bold cyan]")
    console.print(f"[dim]Checking for {len(SENSITIVE_FILES)} high-risk files...[/dim]")
    
    found_files = []
    tasks = [check_file(session, url, f) for f in SENSITIVE_FILES]
    
    results = await asyncio.gather(*tasks)
    
    for res in results:
        if res:
             console.print(f"  [bold red][!] FOUND SENSITIVE FILE: {res['url']}[/bold red]")
             found_files.append(res)
             
    if not found_files:
        console.print("[green][+] No sensitive files found.[/green]")
        
    return found_files
