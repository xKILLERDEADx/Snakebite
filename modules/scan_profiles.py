"""Smart Scan Profiles — pre-built scan configurations for different use cases."""

from modules.core import console

SCAN_PROFILES = {
    'stealth': {
        'name': 'Stealth Mode',
        'description': 'Minimal footprint — passive recon only, no active scanning',
        'scans': ['recon'],
        'settings': {
            'delay': 2.0,
            'threads': 2,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'follow_redirects': False,
        },
        'modules': ['recon', 'tech_detect', 'ssl_check', 'whois_history', 'ct_logs',
                     'email_security', 'dns_zone', 'wayback'],
    },
    'aggressive': {
        'name': 'Aggressive Scan',
        'description': 'Full attack surface — all modules, maximum coverage',
        'scans': ['recon', 'injection', 'brute', 'fuzzing', 'waf', 'http2', 'ssrf'],
        'settings': {
            'delay': 0.1,
            'threads': 20,
            'follow_redirects': True,
        },
        'modules': 'all',
    },
    'bugbounty': {
        'name': 'Bug Bounty Hunter',
        'description': 'Focus on high-impact vulns — SQLi, XSS, SSRF, IDOR, RCE',
        'scans': ['recon', 'injection', 'ssrf'],
        'settings': {
            'delay': 0.5,
            'threads': 10,
        },
        'modules': ['recon', 'sqli', 'xss', 'ssrf_port', 'idor', 'ssti', 'rce',
                     'lfi', 'redirect', 'cors', 'js_analyzer', 'param_fuzzer',
                     'subdomain_takeover', 'cloud_metadata', 'graphql_deep',
                     'oauth_scanner', 'cache_poisoning', 'nuclei_engine'],
    },
    'pentest': {
        'name': 'Full Pentest',
        'description': 'Professional pentest — comprehensive assessment with OWASP mapping',
        'scans': ['recon', 'injection', 'brute', 'fuzzing', 'waf', 'http2'],
        'settings': {
            'delay': 0.3,
            'threads': 15,
        },
        'modules': ['recon', 'sqli', 'xss', 'lfi', 'rce', 'ssti', 'ssrf_port',
                     'xxe', 'nosql', 'idor', 'race', 'cors', 'clickjacking',
                     'host_header', 'smuggling', 'jwt_scan', 'brute_force',
                     'waf_bypass', 'owasp_check', 'ssl_check', 'session_analysis',
                     'api_key_validator', 'oauth_scanner', 'nuclei_engine',
                     'protocol_fuzzer', 'network_mapper', 'dark_web_monitor'],
    },
    'api': {
        'name': 'API Security',
        'description': 'API-focused — GraphQL, REST, authentication, rate limiting',
        'scans': ['recon', 'injection'],
        'settings': {
            'delay': 0.5,
            'threads': 8,
        },
        'modules': ['recon', 'graphql', 'graphql_deep', 'swagger', 'jwt_scan',
                     'cors', 'rate_limiter', 'idor', 'sqli', 'nosql',
                     'api_key_validator', 'oauth_scanner', 'param_fuzzer',
                     'websocket_scanner'],
    },
    'recon_only': {
        'name': 'Recon Only',
        'description': 'Intelligence gathering — no active exploitation',
        'scans': ['recon'],
        'settings': {
            'delay': 1.0,
            'threads': 5,
        },
        'modules': ['recon', 'subdomains', 'ct_logs', 'dns_zone', 'wayback',
                     'google_dorker', 'email_harvester', 'tech_fingerprint',
                     'social_recon', 'whois_history', 'network_mapper',
                     'js_analyzer', 'email_security', 'dark_web_monitor'],
    },
    'cms': {
        'name': 'CMS Security',
        'description': 'WordPress, Drupal, Joomla — CMS-specific vulnerabilities',
        'scans': ['recon', 'injection'],
        'settings': {
            'delay': 0.5,
            'threads': 10,
        },
        'modules': ['recon', 'cms', 'wordpress', 'drupal', 'general_cms',
                     'admin_hunt', 'brute_force', 'nuclei_engine',
                     'sqli', 'xss', 'lfi', 'cicd_detector'],
    },
    'cloud': {
        'name': 'Cloud Security',
        'description': 'Cloud infrastructure — S3, metadata, Docker, K8s',
        'scans': ['recon', 'injection', 'ssrf'],
        'settings': {
            'delay': 0.5,
            'threads': 8,
        },
        'modules': ['recon', 'cloud_hunter', 'cloud_metadata', 's3_brute',
                     'firebase', 'k8s', 'docker_api', 'cicd_detector',
                     'ssrf_port', 'metadata_ssrf'],
    },
}


def get_profile(name):
    """Get a scan profile by name."""
    return SCAN_PROFILES.get(name.lower(), None)


def list_profiles():
    """List all available scan profiles."""
    console.print(f"\n[bold cyan]--- Available Scan Profiles ---[/bold cyan]")
    for key, profile in SCAN_PROFILES.items():
        modules = profile['modules'] if isinstance(profile['modules'], str) else f"{len(profile['modules'])} modules"
        console.print(f"  [green]{key}[/green] — {profile['name']}")
        console.print(f"    [dim]{profile['description']}[/dim]")
        console.print(f"    [dim]Modules: {modules}[/dim]")
    return SCAN_PROFILES


def apply_profile(config, profile_name):
    """Apply a scan profile to config."""
    profile = get_profile(profile_name)
    if not profile:
        console.print(f"  [red]Unknown profile: {profile_name}[/red]")
        console.print(f"  [dim]Available: {', '.join(SCAN_PROFILES.keys())}[/dim]")
        return config

    console.print(f"\n  [bold green]Profile: {profile['name']}[/bold green]")
    console.print(f"  [dim]{profile['description']}[/dim]")

    settings = profile.get('settings', {})
    if 'delay' in settings:
        config.delay = settings['delay']
    if 'threads' in settings:
        config.threads = settings['threads']

    return config, profile
