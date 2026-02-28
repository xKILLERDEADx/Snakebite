import asyncio
from modules.core import console

# Race Condition Logic:
# Send N requests EXACTLY at the same time.
# Best for: Coupons, Transfers, Invitations.
# Since we are indiscriminate, we test any URL with parameters (POST/GET).
# Hard to detect automatically without context (e.g. did balance go negative?).
# We look for "Anomalies": 
# - 10 requests sent.
# - Ideally 1 should succeed (200 OK) and 9 fail (400/409).
# - If multiple succeed with same response, MIGHT be a race.

# Note: This is noisy.

async def attempt_race(session, url, count=5):
    # Prepare tasks
    tasks = []
    # Force query param caching bypass if needed, but for race we want exact same collision.
    for _ in range(count):
        tasks.append(session.get(url, ssl=False))
        
    # Send all
    try:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_codes = []
        for r in responses:
            if not isinstance(r, Exception):
                status_codes.append(r.status)
        
        # Heuristic:
        # If we got multiple 200 OKs on a state-changing endpoint (hard to know if state changing on GET)
        # This module assumes user manually specified targets or we rely on lucky hits.
        # For a generic scanner, finding race conditions on GET is rare unless it's a redeem URL.
        
        # Reporting logic: Just report status distribution for interest.
        count_200 = status_codes.count(200)
        if count_200 > 1 and len(set(status_codes)) > 1:
             # e.g. some 200, some 429/403/500
             return {
                 "url": url,
                 "success_count": count_200,
                 "total": count,
                 "codes": status_codes,
                 "type": "Race Condition (Potential)"
             }
    except Exception:
        pass
    return None

async def scan_race_condition(session, urls):
    """
    Scan for Race Conditions (Logic Flaws).
    """
    console.print(f"\n[bold cyan]--- Race Condition Tester ---[/bold cyan]")
    
    # Only test URLs with parameters
    targets = [u for u in urls if "?" in u or "=" in u][:10] # Limit to 10 endpoints
    
    if not targets:
         console.print("[dim]No parameterized endpoints found to race.[/dim]")
         return []
         
    console.print(f"[dim]Racing {len(targets)} endpoints with parallel requests...[/dim]")
    
    tasks = [attempt_race(session, u) for u in targets]
    results = await asyncio.gather(*tasks)
    
    vulns = []
    for res in results:
        if res:
             console.print(f"  [bold red][!] RACE ANOMALY DETECTED![/bold red]")
             console.print(f"      URL: {res['url']}")
             console.print(f"      Successes: {res['success_count']} / {res['total']}")
             vulns.append(res)
             
    if not vulns:
        console.print("[green][+] No race anomalies detected.[/green]")
        
    return vulns
