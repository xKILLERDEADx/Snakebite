#!/usr/bin/env python3
"""
DARK WEB QUANTUM ADMIN HUNTER 2027 - TEST SCRIPT
🌑 NEURAL AI | 🔮 QUANTUM ALGORITHMS | 🕷️ DARK WEB PATTERNS
"""

import asyncio
import aiohttp
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.admin_hunt import scan_admin_hunt
from modules.core import console

async def test_dark_web_hunter():
    """Test the Dark Web Quantum Admin Hunter"""
    
    console.print("""
[bold red]🌑 DARK WEB QUANTUM ADMIN HUNTER 2027 🌑[/bold red]
[bold magenta]⚡ NEURAL NETWORKS | 🔮 QUANTUM ALGORITHMS | 🕷️ DARK WEB PATTERNS ⚡[/bold magenta]

[bold yellow]🎯 TARGET SELECTION:[/bold yellow]
[cyan]1. GitHub.com (Safe Testing)[/cyan]
[cyan]2. Custom Target[/cyan]
""")
    
    choice = input("Enter choice (1-2): ").strip()
    
    if choice == "1":
        target = "https://destinationroyale.ae"
        console.print(f"[bold green]🎯 Selected Target: {target}[/bold green]")
    elif choice == "2":
        target = input("Enter target URL: ").strip()
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
    else:
        target = "https://destinationroyale.ae"
    
    console.print(f"\n[bold cyan]🚀 Initializing Dark Web Quantum Hunter...[/bold cyan]")
    console.print(f"[bold red]⚠️  ADVANCED THREAT SIMULATION ACTIVE ⚠️[/bold red]")
    
    # Initialize session
    timeout = aiohttp.ClientTimeout(total=30)
    conn = aiohttp.TCPConnector(ssl=False, limit=100)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
        # Run the Dark Web Quantum Hunter
        results = await scan_admin_hunt(session, target)
        
        # Display final results
        console.print(f"\n[bold green]🌟 DARK WEB QUANTUM SCAN COMPLETE 🌟[/bold green]")
        
        if results:
            console.print(f"[bold cyan]📊 QUANTUM INTELLIGENCE REPORT:[/bold cyan]")
            console.print(f"  🎯 Total Admin Panels Discovered: {len(results)}")
            
            # Categorize by confidence
            critical = [r for r in results if r['confidence'] >= 90]
            high = [r for r in results if 80 <= r['confidence'] < 90]
            medium = [r for r in results if 60 <= r['confidence'] < 80]
            
            console.print(f"  🚨 CRITICAL (90%+): {len(critical)}")
            console.print(f"  ⚠️  HIGH (80-89%): {len(high)}")
            console.print(f"  💡 MEDIUM (60-79%): {len(medium)}")
            
            # Show top 5 results
            console.print(f"\n[bold yellow]🏆 TOP QUANTUM DISCOVERIES:[/bold yellow]")
            for i, result in enumerate(results[:5], 1):
                status_emoji = "🔓" if result['status'] == 200 else "🔒" if result['status'] in [401, 403] else "🔄"
                console.print(f"  {i}. {status_emoji} [{result['confidence']}%] {result['url']}")
        else:
            console.print(f"[bold yellow]🛡️ Target appears to be quantum-secured against admin discovery[/bold yellow]")
        
        console.print(f"\n[bold magenta]🔮 QUANTUM HUNTER MISSION COMPLETE 🔮[/bold magenta]")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(test_dark_web_hunter())
    except KeyboardInterrupt:
        console.print("\n[bold red]🛑 Quantum scan interrupted by user[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]💥 Quantum error: {e}[/bold red]")