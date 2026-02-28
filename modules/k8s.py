import asyncio
from modules.core import console

# Kubernetes Scanner (Cloud Infrastructure)
# Focus: Exposed APIs, Dashboards, Kubelet ports.
# Common Ports: 6443 (API), 10250 (Kubelet HTTPS), 8001 (Proxy), 30000+ (NodePort).

K8S_PATHS = [
    "/api/v1/pods", 
    "/api/v1/namespaces", 
    "/api/v1/secrets", 
    "/ui/", 
    "/kubernetes-dashboard/"
]

async def check_k8s(session, url, port=None):
    try:
        target = url
        if port:
            # Reconstruct URL with specific port
            # Assuming url is http[s]://domain
            parts = url.split("://")
            target = f"{parts[0]}://{parts[1].split('/')[0]}:{port}"

        # 1. Check Root API
        async with session.get(f"{target}/version", timeout=4, ssl=False) as resp:
            text = await resp.text()
            if "gitVersion" in text and "kubernetes" in text.lower():
                 return {
                    "url": target,
                    "type": "K8s API Exposed",
                    "evidence": "Version info found at /version"
                }

        # 2. Check Specific Sensitive Paths
        for path in K8S_PATHS:
             async with session.get(f"{target}{path}", timeout=4, ssl=False) as resp:
                text = await resp.text()
                if resp.status == 200 and ("items" in text or "kind" in text):
                     return {
                        "url": f"{target}{path}",
                        "type": "K8s Sensitive Data (Unauth)",
                        "evidence": f"Accessible K8s endpoint: {path}"
                    }

    except Exception:
        pass
    return None

async def scan_k8s(session, url):
    """
    Scan for Kubernetes Infrastructure Exposure.
    """
    console.print(f"\n[bold cyan]--- Kubernetes Scanner ---[/bold cyan]")
    
    # We strip path to get base domain
    base_url = url
    if "/" in url.replace("://", ""):
        base_url = "/".join(url.split("/")[:3]) # http://site.com
    
    # Ports to check
    # Note: Scanning ports might be slow if we do it here, so we stick to the provided URL 
    # OR we try a few known alternate ports quickly.
    
    ports = [None, 6443, 8001, 10250] 
    
    tasks = [check_k8s(session, base_url, p) for p in ports]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] KUBERNETES EXPOSURE: {res['url']}[/bold red]")
             console.print(f"      Type: {res['type']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No open K8s API endpoints found.[/dim]")
        
    return found
