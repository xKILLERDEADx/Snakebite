"""Example Snakebite Plugin — copy and modify this template."""

__author__ = "Your Name"
__version__ = "1.0"


async def scan_example(session, url):
    """Your custom scan logic here."""
    # session = aiohttp.ClientSession
    # url = target URL string
    results = []
    
    # Example: check for a specific endpoint
    # async with session.get(f"{url}/custom-endpoint") as resp:
    #     if resp.status == 200:
    #         results.append({"url": url, "finding": "Custom endpoint exposed"})
    
    return results
