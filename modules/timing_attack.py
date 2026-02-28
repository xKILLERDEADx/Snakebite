"""Timing Attack Scanner — side-channel timing analysis for auth bypass."""

import aiohttp
import asyncio
import time
import statistics
from modules.core import console

async def _measure_response(session, url, data, method='POST', samples=5):
    """Measure average response time for a request."""
    times = []
    for _ in range(samples):
        start = time.time()
        try:
            if method == 'POST':
                async with session.post(url, data=data,
                                        timeout=aiohttp.ClientTimeout(total=10),
                                        ssl=False) as resp:
                    await resp.text()
            else:
                async with session.get(url, params=data,
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    await resp.text()
        except Exception:
            pass
        elapsed = time.time() - start
        times.append(elapsed)
        await asyncio.sleep(0.05)

    if len(times) >= 3:
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'samples': times,
        }
    return None


async def _test_username_timing(session, url):
    """Test if valid vs invalid usernames have different response times."""
    findings = []
    login_paths = ['/login', '/api/login', '/api/auth', '/auth/login',
                   '/signin', '/api/signin', '/user/login']

    for path in login_paths:
        test_url = url.rstrip('/') + path
        try:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5),
                                   ssl=False, allow_redirects=False) as resp:
                if resp.status in [404, 500]:
                    continue
        except Exception:
            continue

        existing_user = {'username': 'admin', 'password': 'wrongpassword123'}
        nonexist_user = {'username': 'xyznonexist999', 'password': 'wrongpassword123'}

        timing_exist = await _measure_response(session, test_url, existing_user)
        timing_nonexist = await _measure_response(session, test_url, nonexist_user)

        if timing_exist and timing_nonexist:
            diff = abs(timing_exist['mean'] - timing_nonexist['mean'])
            if diff > 0.1 and diff > timing_exist['stdev'] * 2:
                findings.append({
                    'type': 'Username Enumeration (Timing)',
                    'path': path,
                    'existing_time': round(timing_exist['mean'], 4),
                    'nonexist_time': round(timing_nonexist['mean'], 4),
                    'diff': round(diff, 4),
                    'severity': 'Medium',
                })

    return findings


async def _test_password_timing(session, url):
    """Test if password comparison is timing-safe."""
    findings = []
    login_paths = ['/login', '/api/login', '/api/auth']

    for path in login_paths:
        test_url = url.rstrip('/') + path

        short_pwd = {'username': 'admin', 'password': 'a'}
        long_pwd = {'username': 'admin', 'password': 'a' * 100}
        very_long = {'username': 'admin', 'password': 'a' * 10000}

        timing_short = await _measure_response(session, test_url, short_pwd, samples=3)
        timing_long = await _measure_response(session, test_url, long_pwd, samples=3)
        timing_vlong = await _measure_response(session, test_url, very_long, samples=3)

        if timing_short and timing_long and timing_vlong:
            if timing_vlong['mean'] > timing_short['mean'] * 1.5:
                findings.append({
                    'type': 'Password Length Timing Leak',
                    'path': path,
                    'short_time': round(timing_short['mean'], 4),
                    'long_time': round(timing_vlong['mean'], 4),
                    'severity': 'Medium',
                })

    return findings


async def _test_token_timing(session, url):
    """Test if token/API key comparison has timing differences."""
    findings = []
    paths = ['/api/', '/api/v1/', '/api/v2/']

    for path in paths:
        test_url = url.rstrip('/') + path

        almost_right = 'Bearer ' + 'A' * 32
        wrong_start = 'Bearer ' + 'Z' * 32
        no_token = ''

        t1 = await _measure_response(session, test_url,
                                      {}, method='GET', samples=3)
        headers_ar = {'Authorization': almost_right}
        headers_ws = {'Authorization': wrong_start}

        times_ar = []
        times_ws = []

        for _ in range(3):
            start = time.time()
            try:
                async with session.get(test_url, headers=headers_ar,
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    await resp.text()
            except Exception:
                pass
            times_ar.append(time.time() - start)

            start = time.time()
            try:
                async with session.get(test_url, headers=headers_ws,
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=False) as resp:
                    await resp.text()
            except Exception:
                pass
            times_ws.append(time.time() - start)

        if times_ar and times_ws:
            mean_ar = statistics.mean(times_ar)
            mean_ws = statistics.mean(times_ws)
            if abs(mean_ar - mean_ws) > 0.05:
                findings.append({
                    'type': 'Token Comparison Timing Leak',
                    'path': path,
                    'severity': 'High',
                })

    return findings


async def scan_timing_attack(session, url):
    """Scan for timing-based side-channel vulnerabilities."""
    console.print(f"\n[bold cyan]--- Timing Attack Scanner ---[/bold cyan]")

    all_findings = []

    console.print(f"  [cyan]Testing username enumeration timing...[/cyan]")
    user_findings = await _test_username_timing(session, url)
    all_findings.extend(user_findings)
    for f in user_findings:
        console.print(f"  [yellow]⚠ {f['type']}: {f['path']} (diff: {f['diff']}s)[/yellow]")

    console.print(f"  [cyan]Testing password comparison timing...[/cyan]")
    pwd_findings = await _test_password_timing(session, url)
    all_findings.extend(pwd_findings)
    for f in pwd_findings:
        console.print(f"  [yellow]{f['type']}: {f['path']}[/yellow]")

    console.print(f"  [cyan]Testing token comparison timing...[/cyan]")
    token_findings = await _test_token_timing(session, url)
    all_findings.extend(token_findings)
    for f in token_findings:
        console.print(f"  [red]{f['type']}: {f['path']}[/red]")

    if all_findings:
        console.print(f"\n  [bold red]{len(all_findings)} timing side-channels found![/bold red]")
    else:
        console.print(f"\n  [green]✓ No timing attack vectors detected[/green]")

    return {'findings': all_findings}
