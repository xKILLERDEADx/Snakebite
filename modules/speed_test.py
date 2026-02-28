import aiohttp
import asyncio
import time
from modules.core import console

async def run_speed_test(session, url):
    """
    Run a real-time speed test measuring:
    - DNS Lookup Time
    - TCP Handshake Time
    - Time to First Byte (TTFB)
    - Content Download Time
    - Total Request Time
    """
    console.print(f"\n[bold cyan]--- Real-Time Website Speed Test ---[/bold cyan]")
    console.print(f"Target: [underline]{url}[/underline]\n")

    # Metrics storage
    timings = {
        "dns_start": None, "dns_end": None,
        "conn_start": None, "conn_end": None,
        "req_start": None, "res_start": None, "res_end": None
    }
    
    # Trace Config for low-level metrics
    trace_config = aiohttp.TraceConfig()

    async def on_dns_resolvehost_start(session, trace_config_ctx, params):
        timings["dns_start"] = time.monotonic()

    async def on_dns_resolvehost_end(session, trace_config_ctx, params):
        timings["dns_end"] = time.monotonic()

    async def on_connection_create_start(session, trace_config_ctx, params):
        timings["conn_start"] = time.monotonic()

    async def on_connection_create_end(session, trace_config_ctx, params):
        timings["conn_end"] = time.monotonic()

    async def on_request_start(session, trace_config_ctx, params):
        timings["req_start"] = time.monotonic()

    async def on_response_chunk_received(session, trace_config_ctx, params):
        if timings["res_start"] is None:
            timings["res_start"] = time.monotonic()

    trace_config.on_dns_resolvehost_start.append(on_dns_resolvehost_start)
    trace_config.on_dns_resolvehost_end.append(on_dns_resolvehost_end)
    trace_config.on_connection_create_start.append(on_connection_create_start)
    trace_config.on_connection_create_end.append(on_connection_create_end)
    trace_config.on_request_start.append(on_request_start)
    trace_config.on_response_chunk_received.append(on_response_chunk_received)

    # dedicated session for accurate tracing without interference
    async with aiohttp.ClientSession(trace_configs=[trace_config]) as local_session:
        try:
            start_global = time.monotonic()
            async with local_session.get(url, timeout=10) as resp:
                await resp.read()
            end_global = time.monotonic()
            timings["res_end"] = end_global
            
            # Calculate Deltas
            dns_time = 0
            if timings["dns_end"] and timings["dns_start"]:
                dns_time = (timings["dns_end"] - timings["dns_start"]) * 1000

            tcp_time = 0
            if timings["conn_end"] and timings["conn_start"]:
                tcp_time = (timings["conn_end"] - timings["conn_start"]) * 1000
                
            ttfb_time = 0
            if timings["res_start"] and timings["req_start"]:
                ttfb_time = (timings["res_start"] - timings["req_start"]) * 1000
                
            total_time = (end_global - start_global) * 1000
            download_time = total_time - (ttfb_time + tcp_time + dns_time)
            
            # Safe display if download time calc goes negative due to overlap/monotonic granularity
            if download_time < 0: download_time = 0

            # Display Results
            console.print(f"  [bold yellow]DNS Lookup:[/bold yellow]        {dns_time:.2f} ms")
            console.print(f"  [bold yellow]TCP Connection:[/bold yellow]    {tcp_time:.2f} ms")
            console.print(f"  [bold green]TTFB (Server):[/bold green]     {ttfb_time:.2f} ms")
            console.print(f"  [bold blue]Download Time:[/bold blue]     {download_time:.2f} ms")
            console.print(f"  ------------------------------")
            console.print(f"  [bold white]Total Duration:[/bold white]     {total_time:.2f} ms")
            
            # Rating
            rating = "Excellent [FAST]"
            if total_time > 500: rating = "Good [OK]"
            if total_time > 1500: rating = "Average [AVG]"
            if total_time > 3000: rating = "Slow [SLOW]"
            
            console.print(f"\n  [bold]Performance Rating:[/bold] {rating}")
            
            return {
                "dns": f"{dns_time:.2f} ms",
                "tcp": f"{tcp_time:.2f} ms",
                "ttfb": f"{ttfb_time:.2f} ms",
                "total": f"{total_time:.2f} ms",
                "rating": rating
            }

        except Exception as e:
            console.print(f"[red]Error during speed test: {e}[/red]")
            return {"error": str(e)}
