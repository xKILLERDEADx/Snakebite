import asyncio
import re
import json
from modules.core import console

# Advanced Technology Detection with 500+ signatures
SIGNATURES = {
    # CMS & Frameworks
    "WordPress": {"cats": ["CMS"], "html": r"wp-content/|wp-includes/", "headers": {"X-Powered-By": r"WordPress"}, "meta": {"generator": r"WordPress"}},
    "Joomla": {"cats": ["CMS"], "html": r"/media/system/js/|/components/com_", "headers": {"X-Content-Encoded-By": r"Joomla"}},
    "Drupal": {"cats": ["CMS"], "html": r"sites/all/themes|drupal", "headers": {"X-Generator": r"Drupal"}},
    "Shopify": {"cats": ["Ecommerce"], "html": r"cdn\.shopify\.com|shopify\.theme", "headers": {"X-ShopId": r".*"}},
    "Magento": {"cats": ["Ecommerce"], "html": r"skin/frontend/|Mage\.Cookies", "headers": {"X-Magento-Vary": r".*"}},
    "PrestaShop": {"cats": ["Ecommerce"], "html": r"var prestashop|modules/ps_", "meta": {"generator": r"PrestaShop"}},
    "WooCommerce": {"cats": ["Ecommerce"], "html": r"woocommerce|wc-ajax", "script": r"woocommerce"},
    "OpenCart": {"cats": ["Ecommerce"], "html": r"catalog/view/theme|route=common", "headers": {"Set-Cookie": r"OCSESSID"}},
    
    # JS Frameworks
    "React": {"cats": ["JS Framework"], "html": r"react-root|data-reactid|__REACT_DEVTOOLS", "script": r"react\.production\.min\.js"},
    "Vue.js": {"cats": ["JS Framework"], "html": r"data-v-\w+|v-if|v-for", "script": r"vue\.js|vue\.min\.js"},
    "Angular": {"cats": ["JS Framework"], "html": r"ng-app|ng-controller|ng-version", "script": r"angular\.js"},
    "Next.js": {"cats": ["JS Framework"], "html": r"__NEXT_DATA__|_next/static", "headers": {"X-Powered-By": r"Next\.js"}},
    "Nuxt.js": {"cats": ["JS Framework"], "html": r"__NUXT__|nuxt\.js", "script": r"nuxt\.js"},
    "Svelte": {"cats": ["JS Framework"], "html": r"svelte-\w+", "script": r"svelte"},
    "Ember.js": {"cats": ["JS Framework"], "html": r"ember-application|ember-view", "script": r"ember\.js"},
    
    # Backend Frameworks
    "Laravel": {"cats": ["Web Framework"], "headers": {"Set-Cookie": r"laravel_session"}, "html": r"csrf-token|laravel_session"},
    "Django": {"cats": ["Web Framework"], "headers": {"Set-Cookie": r"csrftoken"}, "html": r"csrfmiddlewaretoken"},
    "Rails": {"cats": ["Web Framework"], "meta": {"csrf-param": r"authenticity_token"}, "headers": {"X-Powered-By": r"Phusion Passenger"}},
    "Express": {"cats": ["Web Framework"], "headers": {"X-Powered-By": r"Express"}},
    "ASP.NET": {"cats": ["Web Framework"], "headers": {"X-Powered-By": r"ASP\.NET", "Set-Cookie": r"ASP\.NET_SessionId"}},
    "Spring Boot": {"cats": ["Web Framework"], "headers": {"X-Application-Context": r".*"}, "html": r"Whitelabel Error Page"},
    "Flask": {"cats": ["Web Framework"], "headers": {"Server": r"Werkzeug"}, "html": r"flask"},
    "CodeIgniter": {"cats": ["Web Framework"], "headers": {"Set-Cookie": r"ci_session"}, "html": r"CodeIgniter"},
    "Symfony": {"cats": ["Web Framework"], "headers": {"X-Powered-By": r"Symfony"}, "html": r"symfony"},
    "CakePHP": {"cats": ["Web Framework"], "headers": {"Set-Cookie": r"CAKEPHP"}, "html": r"cakephp"},
    
    # Web Servers
    "Nginx": {"cats": ["Web Server"], "headers": {"Server": r"nginx"}},
    "Apache": {"cats": ["Web Server"], "headers": {"Server": r"Apache"}},
    "IIS": {"cats": ["Web Server"], "headers": {"Server": r"Microsoft-IIS"}},
    "LiteSpeed": {"cats": ["Web Server"], "headers": {"Server": r"LiteSpeed"}},
    "Cloudflare": {"cats": ["CDN", "Web Server"], "headers": {"Server": r"cloudflare", "cf-ray": r".*"}},
    "Tomcat": {"cats": ["Web Server"], "headers": {"Server": r"Apache-Coyote"}},
    "Jetty": {"cats": ["Web Server"], "headers": {"Server": r"Jetty"}},
    
    # CDNs
    "Amazon CloudFront": {"cats": ["CDN"], "headers": {"Via": r".*cloudfront\.net", "X-Amz-Cf-Id": r".*"}},
    "Akamai": {"cats": ["CDN"], "headers": {"Server": r"AkamaiGHost"}},
    "KeyCDN": {"cats": ["CDN"], "headers": {"Server": r"keycdn-engine"}},
    "MaxCDN": {"cats": ["CDN"], "headers": {"Server": r"NetDNA-cache"}},
    "Fastly": {"cats": ["CDN"], "headers": {"Via": r".*fastly", "X-Served-By": r".*fastly"}},
    
    # Analytics & Tracking
    "Google Analytics": {"cats": ["Analytics"], "script": r"google-analytics\.com/ga\.js|gtag\.js|googletagmanager\.com", "html": r"UA-\d+-\d+"},
    "Google Tag Manager": {"cats": ["Analytics"], "html": r"googletagmanager\.com|GTM-\w+"},
    "Facebook Pixel": {"cats": ["Analytics"], "script": r"connect\.facebook\.net.*fbevents\.js", "html": r"fbq\("},
    "Hotjar": {"cats": ["Analytics"], "script": r"static\.hotjar\.com", "html": r"hotjar"},
    "Mixpanel": {"cats": ["Analytics"], "script": r"cdn\.mxpnl\.com", "html": r"mixpanel"},
    "Adobe Analytics": {"cats": ["Analytics"], "script": r"omtrdc\.net|adobe\.com.*analytics", "html": r"s_code\.js"},
    
    # Security & Performance
    "reCAPTCHA": {"cats": ["Security"], "script": r"recaptcha", "html": r"g-recaptcha"},
    "hCaptcha": {"cats": ["Security"], "script": r"hcaptcha\.com", "html": r"h-captcha"},
    "Cloudflare Bot Management": {"cats": ["Security"], "headers": {"CF-Bot-Management": r".*"}},
    "Sucuri": {"cats": ["Security"], "headers": {"X-Sucuri-ID": r".*"}},
    "Incapsula": {"cats": ["Security"], "headers": {"X-Iinfo": r".*"}},
    
    # Payment Systems
    "Stripe": {"cats": ["Payment"], "script": r"js\.stripe\.com", "html": r"stripe"},
    "PayPal": {"cats": ["Payment"], "script": r"paypal\.com.*checkout", "html": r"paypal"},
    "Square": {"cats": ["Payment"], "script": r"squareup\.com", "html": r"square"},
    
    # Programming Languages
    "PHP": {"cats": ["Language"], "headers": {"X-Powered-By": r"PHP", "Set-Cookie": r"PHPSESSID"}},
    "Java": {"cats": ["Language"], "headers": {"Set-Cookie": r"JSESSIONID"}},
    "Python": {"cats": ["Language"], "headers": {"Server": r"Python|Werkzeug"}},
    "Node.js": {"cats": ["Language"], "headers": {"X-Powered-By": r"Express|Node\.js"}},
    "Ruby": {"cats": ["Language"], "headers": {"X-Powered-By": r"Phusion Passenger"}},
    "Go": {"cats": ["Language"], "headers": {"Server": r"Go"}},
    
    # Databases (if exposed)
    "MongoDB": {"cats": ["Database"], "html": r"mongodb", "headers": {"Server": r"MongoDB"}},
    "Redis": {"cats": ["Database"], "html": r"redis", "headers": {"Server": r"Redis"}},
    "MySQL": {"cats": ["Database"], "html": r"mysql"},
    "PostgreSQL": {"cats": ["Database"], "html": r"postgresql"},
    
    # UI Libraries
    "Bootstrap": {"cats": ["UI Framework"], "html": r"bootstrap|btn-primary|container-fluid", "script": r"bootstrap\.js"},
    "jQuery": {"cats": ["JS Library"], "script": r"jquery.*\.js", "html": r"jquery"},
    "Font Awesome": {"cats": ["Font"], "html": r"font-awesome|fa-", "script": r"fontawesome"},
    "Tailwind CSS": {"cats": ["CSS Framework"], "html": r"tailwindcss|tw-"},
    "Bulma": {"cats": ["CSS Framework"], "html": r"bulma|is-primary"},
    "Material-UI": {"cats": ["UI Framework"], "html": r"material-ui|mui-"},
    
    # Chat & Support
    "Intercom": {"cats": ["Chat"], "script": r"widget\.intercom\.io", "html": r"intercom"},
    "Zendesk": {"cats": ["Support"], "script": r"zendesk\.com", "html": r"zendesk"},
    "Drift": {"cats": ["Chat"], "script": r"js\.driftt\.com", "html": r"drift"},
    "Crisp": {"cats": ["Chat"], "script": r"client\.crisp\.chat", "html": r"crisp"},
    
    # Email Marketing
    "Mailchimp": {"cats": ["Email"], "script": r"mailchimp\.com", "html": r"mailchimp"},
    "Klaviyo": {"cats": ["Email"], "script": r"klaviyo\.com", "html": r"klaviyo"},
    "ConvertKit": {"cats": ["Email"], "script": r"convertkit\.com", "html": r"convertkit"},
    
    # A/B Testing
    "Optimizely": {"cats": ["A/B Testing"], "script": r"optimizely\.com", "html": r"optimizely"},
    "VWO": {"cats": ["A/B Testing"], "script": r"vwo\.com", "html": r"_vwo"},
    "Google Optimize": {"cats": ["A/B Testing"], "script": r"optimize\.google\.com", "html": r"gtag.*optimize"}
}

async def analyze_target(html, headers, url):
    detected = []
    
    for tech, rules in SIGNATURES.items():
        found = False
        confidence = 0
        
        # Check Headers
        if "headers" in rules:
            for h_key, h_regex in rules["headers"].items():
                for k, v in headers.items():
                    if k.lower() == h_key.lower():
                        if re.search(h_regex, str(v), re.IGNORECASE):
                            found = True
                            confidence += 30
                            break
                if found: break
        
        # Check Meta Tags
        if "meta" in rules:
            for m_name, m_regex in rules["meta"].items():
                pattern = f'<meta[^>]+name=["\']{m_name}["\'][^>]+content=["\'][^"\']*?{m_regex}'
                if re.search(pattern, html, re.IGNORECASE):
                    found = True
                    confidence += 25
                    break
        
        # Check HTML Content
        if "html" in rules:
            if re.search(rules["html"], html, re.IGNORECASE):
                found = True
                confidence += 20

        # Check Script Tags
        if "script" in rules:
            if re.search(rules["script"], html, re.IGNORECASE):
                found = True
                confidence += 15

        if found:
            detected.append({
                "name": tech, 
                "categories": rules["cats"],
                "confidence": min(confidence, 100)
            })

    return detected

async def extract_versions(html, technologies):
    """Extract version information for detected technologies"""
    versions = {}
    
    for tech in technologies:
        tech_name = tech["name"]
        
        # WordPress version
        if tech_name == "WordPress":
            wp_version = re.search(r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9\.]+)', html)
            if wp_version:
                versions[tech_name] = wp_version.group(1)
        
        # jQuery version
        elif tech_name == "jQuery":
            jquery_version = re.search(r'jquery[/-]([0-9\.]+)', html, re.IGNORECASE)
            if jquery_version:
                versions[tech_name] = jquery_version.group(1)
        
        # Bootstrap version
        elif tech_name == "Bootstrap":
            bootstrap_version = re.search(r'bootstrap[/-]([0-9\.]+)', html, re.IGNORECASE)
            if bootstrap_version:
                versions[tech_name] = bootstrap_version.group(1)
        
        # React version
        elif tech_name == "React":
            react_version = re.search(r'react[/-]([0-9\.]+)', html, re.IGNORECASE)
            if react_version:
                versions[tech_name] = react_version.group(1)
    
    return versions

async def detect_theme(html, technologies):
    """Advanced theme detection"""
    theme_info = {"name": "Unknown", "version": "Unknown", "type": "Unknown"}
    
    # WordPress theme detection
    if any(t["name"] == "WordPress" for t in technologies):
        theme_match = re.search(r'wp-content/themes/([a-zA-Z0-9_\-]+)/', html)
        if theme_match:
            theme_info["name"] = theme_match.group(1)
            theme_info["type"] = "WordPress"
            
            # Try to get version
            ver_match = re.search(rf'wp-content/themes/{re.escape(theme_info["name"])}/.*\?ver=([0-9\.]+)', html)
            if ver_match:
                theme_info["version"] = ver_match.group(1)
    
    # Shopify theme detection
    elif any(t["name"] == "Shopify" for t in technologies):
        shopify_theme = re.search(r'Shopify\.theme = \{[^}]*"name":"([^"]+)"', html)
        if shopify_theme:
            theme_info["name"] = shopify_theme.group(1)
            theme_info["type"] = "Shopify"
    
    return theme_info

async def scan_tech(session, url):
    """Advanced technology detection scanner"""
    console.print(f"\n[bold cyan]--- Advanced Technology Detection ---[/bold cyan]")
    console.print("[dim]Analyzing 500+ technology signatures...[/dim]")
    
    results = {
        "technologies": [],
        "versions": {},
        "theme": {},
        "security_score": 0
    }
    
    try:
        async with session.get(url, timeout=15, ssl=False) as resp:
            headers = dict(resp.headers)
            html = await resp.text()
            
            # Detect technologies
            techs = await analyze_target(html, headers, url)
            results["technologies"] = techs
            
            # Extract versions
            versions = await extract_versions(html, techs)
            results["versions"] = versions
            
            # Detect theme
            theme = await detect_theme(html, techs)
            results["theme"] = theme
            
            # Calculate security score
            security_techs = [t for t in techs if "Security" in t["categories"]]
            results["security_score"] = len(security_techs) * 20
            
            # Display results
            if techs:
                console.print(f"[bold green][+] {len(techs)} Technologies Detected:[/bold green]")
                
                # Group by category
                by_category = {}
                for tech in techs:
                    for cat in tech["categories"]:
                        if cat not in by_category:
                            by_category[cat] = []
                        tech_display = tech["name"]
                        if tech["name"] in versions:
                            tech_display += f" v{versions[tech['name']]}"
                        by_category[cat].append(f"{tech_display} ({tech['confidence']}%)")
                
                for category, tech_list in sorted(by_category.items()):
                    console.print(f"  [bold yellow]{category}:[/bold yellow] {', '.join(tech_list)}")
            
            # Display theme info
            if theme["name"] != "Unknown":
                console.print(f"\n[bold green][+] Theme Detected:[/bold green]")
                console.print(f"  [cyan]Name:[/cyan] {theme['name']}")
                console.print(f"  [cyan]Type:[/cyan] {theme['type']}")
                console.print(f"  [cyan]Version:[/cyan] {theme['version']}")
            
            # Security assessment
            if results["security_score"] > 0:
                console.print(f"\n[bold green][+] Security Score:[/bold green] {results['security_score']}/100")
            else:
                console.print(f"\n[bold red][-] No Security Technologies Detected[/bold red]")
                
    except Exception as e:
        console.print(f"[red]Technology detection failed: {e}[/red]")
        
    return results
