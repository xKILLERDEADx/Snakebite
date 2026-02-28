import asyncio
from modules.core import console

# Basic Heuristic: If we send conflicting headers, does the server hang (timeout) or error?
# This is a specialized check. True smuggling detection requires sending a follow-up request to see if it got poisoned.
# For this tool, we will use a Time-Based heuristic (less accurate but safer than poisoning).

TIMEOUT_THRESHOLD = 8 # If request takes > 8s, might be suspicious if baseline is fast.

async def check_smuggling(session, url, type_):
    headers = {}
    data = ""
    
    if type_ == "CL.TE":
        # Front-end uses Content-Length, Back-end uses Transfer-Encoding
        headers = {
            "Content-Length": "4",
            "Transfer-Encoding": "chunked"
        }
        # The body '1\r\nZ\r\nQ\r\n\r\n' should be processed differently
        # If backend waits for more data (TE), it might hang.
        data = "1\r\nZ\r\nQ\r\n\r\n" # Junk
        
    elif type_ == "TE.CL":
         # Front-end uses TE, Back-end uses CL
         headers = {
             "Content-Length": "6",
             "Transfer-Encoding": "chunked"
         }
         data = "0\r\n\r\nX" 
         
    try:
        # We manually use lower level request if possible, but aiohttp abstracts it.
        # We try to inject headers. 
        # Note: aiohttp might normalize headers preventing malformed requests needed for smuggling.
        # We will try standard valid headers that might cause logic errors.
        start = asyncio.get_event_loop().time()
        try:
             async with session.post(url, headers=headers, data=data, timeout=10, ssl=False) as resp:
                 pass
        except asyncio.TimeoutError:
             duration = asyncio.get_event_loop().time() - start
             if duration >= TIMEOUT_THRESHOLD:
                  return {
                      "url": url,
                      "type": f"{type_} (Heuristic - Timeout)",
                      "details": f"Server hung for {duration:.2f}s with conflicting headers."
                  }
        except Exception as e:
             # sometimes 500 error is a sign
             if "500" in str(e):
                  return {
                      "url": url,
                      "type": f"{type_} (Potential - Error)",
                      "details": "Server returned 500 Error."
                  }
    except Exception:
        pass
    return None

async def scan_smuggling(session, url):
    """
    Scan for HTTP Request Smuggling (CL.TE / TE.CL).
    """
    console.print(f"\n[bold cyan]--- HTTP Request Smuggling Scanner ---[/bold cyan]")
    
    tasks = [
        check_smuggling(session, url, "CL.TE"),
        check_smuggling(session, url, "TE.CL")
    ]
    
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] SMUGGLING INDICATOR DETECTED![/bold red]")
             console.print(f"      Type: {res['type']}")
             console.print(f"      Details: {res['details']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No smuggling indicators (timeout/errors) detected.[/green]")
        
    return vulns
