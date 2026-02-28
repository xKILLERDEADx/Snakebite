import asyncio
import base64
import re
import json
from modules.core import console

JWT_REGEX = r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'

def decode_segment(segment):
    padding = '=' * (4 - len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding).decode('utf-8')

async def analyze_jwt(token, url):
    try:
        parts = token.split('.')
        header = json.loads(decode_segment(parts[0]))
        payload = json.loads(decode_segment(parts[1]))
        
        alg = header.get('alg', 'unknown')
        vulns = []
        
        # Check 1: None Algorithm
        if alg.lower() == 'none':
            vulns.append("CRITICAL: 'None' Algorithm Allowed (Bypass)")
            
        # Check 2: Weak Algorithm (HS256 is common but if key is weak it's breakable. "None" is the main quick check)
        if alg == 'HS256':
             # Just an informational note, requires brute force to prove vuln
             pass
             
        # Check 3: Sensitive Info in Payload
        if 'password' in payload or 'secret' in payload:
            vulns.append("HIGH: Sensitive Data in Token Payload")

        return {
            "token": token[:20] + "...",
            "url": url,
            "alg": alg,
            "vulns": vulns,
            "payload": payload
        }
    except Exception:
        return None

async def scan_jwt(session, urls):
    """
    Search for JWTs in page content and analyze them.
    """
    console.print(f"\n[bold cyan]--- JWT Security Analyzer ---[/bold cyan]")
    
    if not urls:
        console.print("[yellow][!] No URLs to search for tokens.[/yellow]")
        return []

    console.print(f"[dim]Searching {len(urls)} URLs for JWT tokens...[/dim]")
    
    tokens_found = set()
    results = []
    
    # Analyze a subset of URLs (e.g. main page and finding pages)
    # Since we are mostly a crawler, we look in response bodies
    for url in urls[:20]: # Limit scan to first 20 for speed
        try:
             async with session.get(url, timeout=5, ssl=False) as resp:
                 text = await resp.text()
                 # Search in body
                 matches = re.finditer(JWT_REGEX, text)
                 for match in matches:
                     tokens_found.add((match.group(), url))
                 
                 # Search in headers (Set-Cookie or Auth headers if reflected? unlikely for Auth but possible in JS files)
                 for k, v in resp.headers.items():
                     matches = re.finditer(JWT_REGEX, str(v))
                     for match in matches:
                         tokens_found.add((match.group(), url))
        except Exception:
            pass

    if not tokens_found:
         console.print("[green][+] No JWT tokens identified in public content.[/green]")
         return []
         
    for token, url in tokens_found:
        analysis = await analyze_jwt(token, url)
        if analysis:
             color = "red" if analysis['vulns'] else "green"
             console.print(f"  [bold {color}][*] JWT Found on {url}[/bold {color}]")
             console.print(f"      Alg: {analysis['alg']}")
             if analysis['vulns']:
                 for v in analysis['vulns']:
                     console.print(f"      [bold red]! {v}[/bold red]")
             results.append(analysis)
             
    return results
