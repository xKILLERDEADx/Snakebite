import asyncio
from urllib.parse import urlparse
from modules.core import console

# Common bucket suffixes
BUCKET_SUFFIXES = [
    "-dev", "-prod", "-backup", "-assets", "-static", "-public",
    "-staging", "-test", "-logs", "-media", "-images", "-files"
]

async def check_bucket(session, bucket_name):
    # AWS S3 standard URL format
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        async with session.get(url, timeout=3, ssl=False) as resp:
            # 200 = Public and listable
            # 403 = Protected but exists
            if resp.status == 200:
                return {
                    "bucket": bucket_name,
                    "url": url,
                    "status": "OPEN (200 OK)",
                    "access": "Public Listable"
                }
            elif resp.status == 403:
                 return {
                    "bucket": bucket_name,
                    "url": url,
                    "status": "PROTECTED (403)",
                    "access": "Exists but Private"
                }
    except Exception:
        pass
    return None

async def scan_s3_brute(session, url):
    """
    Scan for S3 Buckets via Active Bruteforce.
    """
    console.print(f"\n[bold cyan]--- S3 Bucket Bruteforcer ---[/bold cyan]")
    
    # Extract domain name: https://www.example.com -> example
    try:
        domain = urlparse(url).netloc
        if "www." in domain: domain = domain.replace("www.", "")
        name = domain.split(".")[0] # 'example' from 'example.com'
    except Exception:
        console.print("[red][!] Invalid URL for S3 guessing.[/red]")
        return []

    # Generate guesses
    guesses = [name, f"{name}.com", f"www.{name}"]
    for s in BUCKET_SUFFIXES:
        guesses.append(f"{name}{s}")
        guesses.append(f"{name}.{s}") # e.g. example.dev (less common for buckets but possible)
        
    console.print(f"[dim]Bruteforcing {len(guesses)} possible bucket names...[/dim]")
    
    tasks = [check_bucket(session, b) for b in guesses]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             color = "red" if "OPEN" in res['status'] else "yellow"
             console.print(f"  [bold {color}][+] S3 BUCKET FOUND: {res['bucket']}[/bold {color}]")
             console.print(f"      Status: {res['status']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No valid buckets found via guessing.[/dim]")
        
    return found
