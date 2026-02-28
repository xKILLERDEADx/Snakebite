import aiohttp
import asyncio
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from modules.core import console

class Crawler:
    def __init__(self, start_url, max_depth=2, max_pages=50):
        self.start_url = start_url
        parsed = urlparse(start_url)
        self.domain = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.fuzzable_urls = set()
        self.js_files = set()
        self.forms = []
        self.all_found_links = set() 

    async def fetch(self, session, url):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as response:
                ctype = response.headers.get('Content-Type', '')
                if 'text/html' in ctype or 'javascript' in ctype or 'application/json' in ctype:
                    try:
                        return await response.text(errors='replace'), response.url, response.status
                    except Exception:
                        return None, response.url, response.status
                return None, response.url, response.status
        except asyncio.TimeoutError:
            return None, url, None
        except Exception:
            return None, url, None

    def _extract_js_links(self, js_text, base_url):
        """Extract URLs referenced inside JavaScript source."""
        found = set()
        patterns = [
            r"""(?:['"`])(/[^'"`\s]{2,200})(?:['"`])""",
            r"""(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(\s*['"`]([^'"`]+)['"`]""",
        ]
        for pat in patterns:
            for match in re.finditer(pat, js_text):
                path = match.group(1)
                if path.startswith('/'):
                    full = urljoin(base_url, path)
                    parsed = urlparse(full)
                    if parsed.netloc == self.domain:
                        found.add(full)
        return found

    async def _parse_robots(self, session):
        """Fetch and parse robots.txt for Disallow entries."""
        robots_url = f"{self.base_url}/robots.txt"
        try:
            html, _, status = await self.fetch(session, robots_url)
            if html and status == 200:
                disallowed = []
                for line in html.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != '/':
                            full = urljoin(self.base_url, path)
                            disallowed.append(full)
                if disallowed:
                    console.print(f"  [yellow][+] robots.txt: {len(disallowed)} Disallow paths found[/yellow]")
                    for u in disallowed[:20]:
                        self.all_found_links.add(u)
                        if '?' in u:
                            self.fuzzable_urls.add(u)
        except Exception:
            pass

    async def _parse_sitemap(self, session):
        """Fetch and parse sitemap.xml for URLs."""
        sitemap_url = f"{self.base_url}/sitemap.xml"
        try:
            html, _, status = await self.fetch(session, sitemap_url)
            if html and status == 200:
                urls = re.findall(r'<loc>(.*?)</loc>', html)
                count = 0
                for u in urls:
                    u = u.strip()
                    parsed = urlparse(u)
                    if parsed.netloc == self.domain:
                        self.all_found_links.add(u)
                        if parsed.query:
                            self.fuzzable_urls.add(u)
                        count += 1
                if count:
                    console.print(f"  [yellow][+] sitemap.xml: {count} URLs discovered[/yellow]")
        except Exception:
            pass

    async def crawl(self, session, url, depth):
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        self.visited.add(url)
        self.all_found_links.add(url)

        console.print(f"[dim]Crawling ({len(self.visited)}/{self.max_pages}): {url}[/dim]")

        html, current_url, _ = await self.fetch(session, url)
        if not html:
            return

        if str(current_url).endswith('.js') or str(url).endswith('.js'):
            js_links = self._extract_js_links(html, self.base_url)
            for jl in js_links:
                if jl not in self.visited:
                    self.all_found_links.add(jl)
                    if '?' in jl:
                        self.fuzzable_urls.add(jl)
            return

        soup = BeautifulSoup(html, 'html.parser')
        tasks = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(str(current_url), href)
            self.all_found_links.add(full_url)
            parsed = urlparse(full_url)
            if parsed.netloc == self.domain:
                clean = full_url.split('#')[0]
                if parsed.query:
                    if clean not in self.fuzzable_urls:
                        console.print(f"  [cyan][*] Param URL: {clean}[/cyan]")
                        self.fuzzable_urls.add(clean)
                if clean not in self.visited and len(self.visited) < self.max_pages:
                    tasks.append(self.crawl(session, clean, depth + 1))
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(str(current_url), src)
            parsed = urlparse(full_url)
            if full_url.endswith('.js'):
                self.js_files.add(full_url)
                if parsed.netloc == self.domain and full_url not in self.visited and len(self.visited) < self.max_pages:
                    tasks.append(self.crawl(session, full_url, depth + 1))
        for script in soup.find_all('script', src=False):
            if script.string:
                js_links = self._extract_js_links(script.string, self.base_url)
                for jl in js_links:
                    self.all_found_links.add(jl)
                    if '?' in jl:
                        self.fuzzable_urls.add(jl)
        for form in soup.find_all('form'):
            action = form.get('action') or str(current_url)
            method = form.get('method', 'get').lower()
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                val = inp.get('value', 'test')
                if name:
                    inputs.append({'name': name, 'value': val})

            if inputs:
                action_url = urljoin(str(current_url), action)
                form_details = {
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                    "url": str(current_url)
                }
                if form_details not in self.forms:
                    self.forms.append(form_details)
                    console.print(f"  [yellow][+] Form Found: {action_url} [{method.upper()}] ({len(inputs)} inputs)[/yellow]")
                    parsed_action = urlparse(action_url)
                    if parsed_action.netloc == self.domain and parsed_action.query:
                        self.fuzzable_urls.add(action_url)

        if tasks:
            await asyncio.gather(*tasks)

async def run_crawler(session, url, deep=False):
    if deep:
        console.print("\n[bold red][*] Starting Deep Intelligent Crawler (Extreme Mode)...[/bold red]")
        console.print("[dim]    - Max Depth: 6\n    - Max Pages: 500\n    - Sitemap + Robots parsing enabled\n    - This may take a while...[/dim]")
        spider = Crawler(url, max_depth=6, max_pages=500)
    else:
        console.print("\n[bold][*] Starting Intelligent Crawler...[/bold]")
        console.print("[dim]    - Max Depth: 3\n    - Max Pages: 100\n    - Sitemap + Robots parsing enabled[/dim]")
        spider = Crawler(url, max_depth=3, max_pages=100)

    await asyncio.gather(
        spider._parse_robots(session),
        spider._parse_sitemap(session)
    )

    await spider.crawl(session, url, 0)

    console.print(
        f"  [green][+] Crawl Complete:[/green] "
        f"{len(spider.visited)} pages visited, "
        f"{len(spider.fuzzable_urls)} param URLs, "
        f"{len(spider.js_files)} JS files, "
        f"{len(spider.forms)} forms found"
    )

    return {
        "urls": list(spider.fuzzable_urls),
        "all_links": list(spider.all_found_links),
        "js_files": list(spider.js_files),
        "forms": spider.forms
    }
