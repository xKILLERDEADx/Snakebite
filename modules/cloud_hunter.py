import asyncio
import re
from modules.core import console

CLOUD_PATTERNS = {
    "AWS S3": r'[a-z0-9.-]+\.s3\.amazonaws\.com',
    "Google Cloud": r'storage\.googleapis\.com/[a-z0-9.-]+',
    "Azure Blob": r'[a-z0-9.-]+\.blob\.core\.windows\.net'
}

async def scan_cloud_hunter(session, urls):
    """
    Search for Cloud Storage Buckets in page source.
    """
    console.print(f"\n[bold cyan]--- Cloud Storage Hunter ---[/bold cyan]")
    
    # Analyze first 20 pages for speed
    targets = urls[:20] 
    if not targets:
         console.print("[yellow][!] No URLs to search.[/yellow]")
         return []
         
    console.print(f"[dim]Hunting for cloud buckets in {len(targets)} pages...[/dim]")
    
    found = set()
    results = []
    
    for url in targets:
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                text = await resp.text()
                for provider, pattern in CLOUD_PATTERNS.items():
                    matches = re.finditer(pattern, text)
                    for m in matches:
                        bucket = m.group()
                        if bucket not in found:
                            found.add(bucket)
                            results.append({
                                "provider": provider,
                                "bucket": bucket,
                                "source_url": url
                            })
        except Exception:
            pass
            
    for res in results:
        console.print(f"  [bold red][!] CLOUD BUCKET FOUND![/bold red]")
        console.print(f"      Provider: {res['provider']}")
        console.print(f"      Bucket: {res['bucket']}")
        console.print(f"      Source: {res['source_url']}")
        
    if not results:
        console.print("[green][+] No exposed cloud buckets found.[/green]")
        
    return results
