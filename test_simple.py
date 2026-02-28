#!/usr/bin/env python3
import asyncio
import aiohttp
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.admin_hunt import scan_admin_hunt
from modules.core import console

async def test_destinationroyale():
    """Test Dark Web Hunter on destinationroyale.ae"""
    
    target = "https://destinationroyale.ae"
    console.print(f"\n[bold red]DARK WEB QUANTUM ADMIN HUNTER 2027[/bold red]")
    console.print(f"[bold green]Target: {target}[/bold green]")
    console.print(f"[bold cyan]Initializing quantum scan...[/bold cyan]")
    
    # Initialize session
    timeout = aiohttp.ClientTimeout(total=30)
    conn = aiohttp.TCPConnector(ssl=False, limit=100)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
        # Run the scan
        results = await scan_admin_hunt(session, target)
        
        # Display results
        console.print(f"\n[bold green]QUANTUM SCAN COMPLETE[/bold green]")
        
        if results:
            console.print(f"[bold cyan]ADMIN PANELS DISCOVERED: {len(results)}[/bold cyan]")
            
            # Show top 10 results
            console.print(f"\n[bold yellow]TOP DISCOVERIES:[/bold yellow]")
            for i, result in enumerate(results[:10], 1):
                status_color = "green" if result['status'] == 200 else "red" if result['status'] in [401, 403] else "yellow"
                console.print(f"  {i:2d}. [{status_color}][{result['confidence']}%][/{status_color}] {result['url']}")
                console.print(f"      Status: {result['status']} | Framework: {result['framework']}")
        else:
            console.print(f"[bold yellow]No admin panels found - target is well secured[/bold yellow]")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(test_destinationroyale())
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")