import aiohttp
import asyncio
from modules.core import console

# Known CNAMEs for takeover
TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "bitbucket.org": "Bitbucket",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "wordpress.com": "WordPress",
    "tumblr.com": "Tumblr"
}

CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "xmlrpc.php"],
    "Joomla": ["/templates/", "/media/system/js/", "Joomla!"],
    "Drupal": ["sites/default", "drupal.js"],
    "Magento": ["Mage.Cookies", "skin/frontend"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"]
}

async def check_takeover(session, subdomain):
    """Check if subdomain CNAME points to unclaimed service"""
    # Note: Requires DNS resolution which is complex in pure async without aiodns for CNAME
    # We will use HTTP response characteristic fingerpriting as fallback
    try:
        async with session.get(f"http://{subdomain}", timeout=5) as resp:
            text = await resp.text()
            if resp.status == 404:
                for fingerprint, service in TAKEOVER_FINGERPRINTS.items():
                    # This logic is simplified; real takeover checks CNAME
                    # But often 404 pages of services have distinct text
                    if "There is no app configured at that hostname" in text:
                        return {"subdomain": subdomain, "service": "Heroku", "status": "VULNERABLE"}
                    if "NoSuchBucket" in text:
                        return {"subdomain": subdomain, "service": "AWS S3", "status": "VULNERABLE"}
            return None
    except Exception:
        return None

async def detect_cms(session, url, html_content=None):
    """Detect CMS based on signatures"""
    if not html_content:
        try:
            async with session.get(url, timeout=5) as resp:
                html_content = await resp.text()
        except Exception:
            return None
            
    detected = []
    
    for cms, sigs in CMS_SIGNATURES.items():
        for sig in sigs:
            if sig in html_content:
                detected.append(cms)
                break
                
    if detected:
        console.print(f"[bold magenta]  CMS Detected: {', '.join(detected)}[/bold magenta]")
    
    return detected
