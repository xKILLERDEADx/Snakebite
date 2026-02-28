import asyncio
import argparse
import sys
import time as _time
import aiohttp
from rich.prompt import Prompt
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from modules.notifications import alert_vulnerability, send_scan_summary
from modules.exploit_suggest import enrich_findings_with_exploits, format_suggestions_console
from modules.cve_mapper import enrich_findings_list, print_cve_summary
from modules.pdf_report import generate_pdf_report
from modules.wayback import scan_wayback
from modules.dns_zone import scan_dns_zone
from modules.vhost_finder import scan_vhost
from modules.session_analysis import scan_session
from modules.param_fuzzer import scan_param_fuzzer
from modules.google_dorker import scan_google_dorks
from modules.shodan_check import scan_shodan, scan_virustotal
from modules.github_leaks import scan_github_leaks
from modules.scan_diff import compare_scans
from modules.owasp_check import assess_owasp_compliance
from modules.waf_bypass import scan_waf_bypass
from modules.rate_limiter import detect_rate_limit
from modules.api_key_validator import validate_api_keys
from modules.brute_force import scan_brute_force
from modules.plugin_system import run_plugins
from modules.html_report import generate_html_report
from modules.http2_scanner import scan_http2
from modules.js_analyzer import scan_js_files
from modules.ct_logs import scan_ct_logs
from modules.subdomain_takeover import scan_subdomain_takeover
from modules.cloud_metadata import scan_cloud_metadata
from modules.websocket_scanner import scan_websocket
from modules.graphql_deep import scan_graphql_deep
from modules.nuclei_engine import scan_nuclei_templates
from modules.proxy_chain import setup_proxy_chain
from modules.scan_resume import save_checkpoint, load_checkpoint, clear_checkpoint
from modules.network_mapper import scan_network_topology
from modules.dark_web_monitor import scan_dark_web
from modules.exploit_generator import generate_all_exploits
from modules.protocol_fuzzer import scan_protocol_fuzzer
from modules.oauth_scanner import scan_oauth_saml
from modules.dns_rebinding import scan_dns_rebinding
from modules.cache_poisoning import scan_cache_poisoning
from modules.cicd_detector import scan_cicd_pipelines
from modules.email_harvester import scan_email_harvester
from modules.whois_history import scan_whois_history
from modules.tech_fingerprint import scan_tech_fingerprint
from modules.social_recon import scan_social_recon
from modules.cve_exploiter import scan_cve_exploits
from modules.scan_profiles import list_profiles, apply_profile
from modules.live_dashboard import generate_dashboard
from modules.vuln_classifier import classify_all_findings
from modules.blind_xss import scan_blind_xss
from modules.api_discovery import scan_api_discovery
from modules.sensitive_files import scan_sensitive_files
from modules.log4shell import scan_log4shell
from modules.mass_assignment import scan_mass_assignment
from modules.broken_access import scan_broken_access
from modules.security_scorecard import generate_scorecard
from modules.threat_intel import scan_threat_intel
from modules.http_desync import scan_http_desync
from modules.subdomain_brute import scan_subdomain_brute
from modules.redos import scan_redos
from modules.timing_attack import scan_timing_attack
from modules.content_discovery import scan_content_discovery
from modules.dependency_confusion import scan_dependency_confusion
from modules.bola import scan_bola
from modules.deserialization import scan_deserialization
from modules.server_misconfig import scan_server_misconfig
from modules.zero_day_detect import scan_zero_day
from modules.payload_encoder import scan_with_encoded_payloads
from modules.compliance import scan_compliance
from modules.race_condition import scan_race_condition
from modules.wasm_scanner import scan_wasm
from modules.proto_pollution_deep import scan_proto_pollution
from modules.ssrf_chain import scan_ssrf_chain
from modules.business_logic import scan_business_logic
from modules.jwt_forge import scan_jwt_forge
from modules.multi_target import scan_multi_target
from modules.attack_surface import scan_attack_surface
from modules.graphql_deep import scan_graphql_deep
from modules.ai_vuln_predictor import scan_ai_predict
from modules.dns_exfil import scan_dns_exfil
from modules.oauth2_chain import scan_oauth2_chain
from modules.rate_bypass import scan_rate_bypass
from modules.memory_leak import scan_memory_leak
from modules.client_attack import scan_client_attack
from modules.supply_chain import scan_supply_chain
from modules.exploit_reporter import scan_exploit_report
from modules.http_smuggle import scan_http_smuggle
from modules.websocket_hijack import scan_websocket_hijack
from modules.cloud_metadata import scan_cloud_metadata
from modules.cache_deception import scan_cache_deception
from modules.api_reconstruct import scan_api_reconstruct
from modules.blind_ssrf import scan_blind_ssrf
from modules.session_fixation import scan_session_fixation
from modules.cors_chain import scan_cors_chain
from modules.header_injection import scan_header_injection
from modules.iot_scanner import scan_iot
from modules.zeroday_detect import scan_zeroday_detect
from modules.waf_bypass import scan_waf_bypass
from modules.subdomain_takeover import scan_subdomain_takeover
from modules.dep_confusion import scan_dep_confusion
from modules.secrets_engine import scan_secrets_engine
from modules.hpp_scanner import scan_hpp
from modules.email_deep import scan_email_deep
from modules.js_deobfuscate import scan_js_deobfuscate
from modules.report_pro import scan_report_pro
from modules.live_dashboard import generate_dashboard
from modules.webshell_detect import scan_webshell_detect
from modules.backdoor_finder import scan_backdoor_finder
from modules.malware_scanner import scan_malware
from modules.hidden_admin import scan_hidden_admin
from modules.phishing_detect import scan_phishing_detect
from modules.rootkit_web import scan_rootkit_web
from modules.defacement_monitor import scan_defacement
from modules.c2_detect import scan_c2_detect
from modules.forensic_analyzer import scan_forensic
from banner import show_banner
from modules.core import Config, Logger, console, get_timestamp, format_duration, get_random_ua
from modules.recon import run_recon
from modules.scanner import run_active_scan
from modules.ports import scan_ports
from modules.subdomains import enumerate_subdomains
from modules.report import save_scan_report
from modules.crawler import run_crawler
from modules.sqli import run_sqli_scan
from modules.xss import run_xss_scan
from modules.cms import detect_cms
from modules.wordpress import scan_wordpress
from modules.general_cms import scan_general
from modules.speed_test import run_speed_test
from modules.js_secrets import scan_js_secrets
from modules.takeover import scan_takeover
from modules.ssl_check import analyze_ssl
from modules.lfi import scan_lfi
from modules.redirect import scan_redirect
from modules.fuzzer import run_fuzzer
from modules.cors import scan_cors
from modules.email_security import scan_email_security
from modules.clickjacking import scan_clickjacking
from modules.rce import scan_rce
from modules.ssti import scan_ssti
from modules.jwt_scan import scan_jwt
from modules.graphql import scan_graphql
from modules.prototype import scan_prototype
from modules.waf_bypass import scan_waf_bypass
from modules.xxe import scan_xxe
from modules.idor import scan_idor
from modules.cloud_hunter import scan_cloud_hunter
from modules.spring_boot import scan_spring_boot
from modules.crlf import scan_crlf
from modules.shellshock import scan_shellshock
from modules.host_header import scan_host_header
from modules.bypass_403 import scan_403_bypass
from modules.java_deser import scan_java_deser
from modules.broken_links import scan_broken_links
from modules.smuggling import scan_smuggling
from modules.cache_deception import scan_cache_deception
from modules.git_scan import scan_git_exposure
from modules.swagger import scan_swagger
from modules.race import scan_race_condition
from modules.websocket_scan import scan_websocket
from modules.tabnabbing import scan_tabnabbing
from modules.dependencies import scan_dependencies
from modules.admin_hunt import scan_admin_hunt
from modules.s3_brute import scan_s3_brute
from modules.param_miner import scan_param_miner
from modules.webdav import scan_webdav
from modules.iis_shortname import scan_iis_shortname
from modules.key_validator import scan_key_validator
from modules.ssi import scan_ssi
from modules.xslt import scan_xslt
from modules.nosql import scan_nosql
from modules.blind_rce import scan_blind_rce
from modules.blind_sqli import scan_blind_sqli
from modules.metadata_ssrf import scan_metadata_ssrf
from modules.h2c_smuggler import scan_h2c_smuggler
from modules.php_object import scan_php_object
from modules.graphql_batch import scan_graphql_batch
from modules.ldap import scan_ldap
from modules.xpath import scan_xpath
from modules.latex import scan_latex
from modules.pickle import scan_pickle
from modules.ssrf_port import scan_ssrf_port
from modules.env_dump import scan_env_dump
from modules.csv_injection import scan_csv_injection
from modules.rpo import scan_rpo
from modules.xssi import scan_xssi
from modules.esi import scan_esi
from modules.dangling import scan_dangling
from modules.csp_bypass import scan_csp_bypass
from modules.hpp import scan_hpp
from modules.dom_xss import scan_dom_xss
from modules.proto_client import scan_proto_client
from modules.log4shell import scan_log4shell
from modules.spring4shell import scan_spring4shell
from modules.proto_server import scan_proto_server
from modules.k8s import scan_k8s
from modules.firebase import scan_firebase
from modules.jenkins import scan_jenkins
from modules.elastic import scan_elastic
from modules.drupal import scan_drupal
from modules.tomcat import scan_tomcat
from modules.ultra_admin import scan_ultra_admin
from modules.citrix import scan_citrix
from modules.thinkphp import scan_thinkphp
from modules.rails import scan_rails
from modules.weblogic import scan_weblogic
from modules.sap import scan_sap
from modules.exchange import scan_exchange
from modules.vmware import scan_vmware
from modules.f5 import scan_f5
from modules.jira import scan_jira
from modules.confluence import scan_confluence
from modules.pulse import scan_pulse
from modules.struts import scan_struts
from modules.coldfusion import scan_coldfusion
from modules.solr import scan_solr
from modules.nginx import scan_nginx
from modules.sonarqube import scan_sonarqube
from modules.grafana import scan_grafana
from modules.tech_detect import scan_tech
from modules.redis_scan import scan_redis
from modules.docker_api import scan_docker
from modules.memcached import scan_memcached
from modules.gitea import scan_gitea
from modules.minio import scan_minio
from modules.zabbix import scan_zabbix
from modules.jboss import scan_jboss
from modules.glassfish import scan_glassfish
from modules.hadoop import scan_hadoop
from modules.resource_discovery import run_resource_discovery

log = Logger.setup()
def parse_args():
    parser = argparse.ArgumentParser(
        description="Snakebite v2.0 — Professional Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Max concurrent connections (default: 50)")
    parser.add_argument("-o", "--output", help="Output file base name (auto-generated if not set)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--rate-limit", type=float, default=0.0, dest="rate_limit",
                        help="Delay between requests in seconds (default: 0 = no limit)")
    parser.add_argument("--profile", choices=["light", "standard", "full", "stealth"],
                        default="standard", help="Scan profile (default: standard)")
    parser.add_argument("--output-format", choices=["json", "txt", "html", "all"],
                        default="all", dest="output_format",
                        help="Report output format (default: all)")
    parser.add_argument("--webhook", help="Webhook URL for blind XSS/SSRF callbacks (optional)")
    parser.add_argument("--no-color", action="store_true", dest="no_color",
                        help="Disable colored output")
    parser.add_argument("--list", dest="target_list",
                        help="File containing list of target URLs (one per line)")
    parser.add_argument("--cookie", help="Auth cookie to include in requests (e.g. 'session=abc123')")
    parser.add_argument("--header", dest="custom_header",
                        help="Custom header (e.g. 'Authorization: Bearer TOKEN')")
    parser.add_argument("--wordlist", help="Custom wordlist file for fuzzing/directory brute")
    parser.add_argument("--exclude", dest="exclude_patterns",
                        help="Exclude URL patterns (comma-separated, e.g. '*.pdf,*.jpg,/logout')")
    parser.add_argument("--include", dest="include_patterns",
                        help="Include only these URL patterns (comma-separated, e.g. '/api/*,/admin/*')")
    parser.add_argument("--telegram-token", dest="telegram_token",
                        help="Telegram Bot token for vuln alerts")
    parser.add_argument("--telegram-chat", dest="telegram_chat",
                        help="Telegram Chat ID for vuln alerts")
    parser.add_argument("--discord-webhook", dest="discord_webhook",
                        help="Discord Webhook URL for vuln alerts")
    parser.add_argument("--shodan-key", dest="shodan_key",
                        help="Shodan API key for host intelligence")
    parser.add_argument("--vt-key", dest="vt_key",
                        help="VirusTotal API key for domain reputation")
    parser.add_argument("--github-token", dest="github_token",
                        help="GitHub token for leak scanning")
    parser.add_argument("--diff", nargs=2, dest="diff_files", metavar=('OLD', 'NEW'),
                        help="Compare two scan reports (JSON files)")
    return parser.parse_args()

async def validate_target(session, url):
    try:
        async with session.get(url, timeout=15, ssl=False) as response:
            return response.status
    except Exception as e:
        console.print(f"[red]Debug: Connection error: {e}[/red]")
        return None

async def main():
    show_banner()
    args = parse_args()

    # Handle --diff shortcut
    if args.diff_files:
        compare_scans(args.diff_files[0], args.diff_files[1])
        return

    scan_start_time = _time.time()
    _vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    def _count_vulns(results):
        """Count severity from a result list and update global counter."""
        if not isinstance(results, list):
            return
        for item in results:
            if isinstance(item, dict):
                sev = item.get("severity", "Medium")
                if sev in _vuln_counts:
                    _vuln_counts[sev] += 1
                else:
                    _vuln_counts["Medium"] += 1

    def _print_vuln_status():
        parts = []
        if _vuln_counts["Critical"]: parts.append(f"[bold red]Critical:{_vuln_counts['Critical']}[/bold red]")
        if _vuln_counts["High"]: parts.append(f"[bold orange3]High:{_vuln_counts['High']}[/bold orange3]")
        if _vuln_counts["Medium"]: parts.append(f"[bold yellow]Medium:{_vuln_counts['Medium']}[/bold yellow]")
        if _vuln_counts["Low"]: parts.append(f"[bold green]Low:{_vuln_counts['Low']}[/bold green]")
        if parts:
            console.print(f"  [dim]→ Running totals:[/dim] {'  '.join(parts)}")

    target_url = args.url
    if not target_url:
        target_url = Prompt.ask("[bold cyan]Enter target URL[/bold cyan]")
        if not target_url:
            console.print("[bold red][!] No target provided. Exiting...[/bold red]")
            sys.exit(1)
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    config = Config(
        url=target_url,
        threads=args.threads,
        verbose=args.verbose,
        output_file=args.output,
        proxy=args.proxy,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        profile=args.profile,
        output_format=args.output_format,
        webhook_url=getattr(args, 'webhook', None),
        cookie=getattr(args, 'cookie', None),
        custom_header=getattr(args, 'custom_header', None),
        wordlist=getattr(args, 'wordlist', None),
        exclude_patterns=getattr(args, 'exclude_patterns', None),
        include_patterns=getattr(args, 'include_patterns', None),
        telegram_token=getattr(args, 'telegram_token', None),
        telegram_chat=getattr(args, 'telegram_chat', None),
        discord_webhook=getattr(args, 'discord_webhook', None),
        target_list=getattr(args, 'target_list', None),
        shodan_key=getattr(args, 'shodan_key', None),
        vt_key=getattr(args, 'vt_key', None),
        github_token=getattr(args, 'github_token', None),
    )

    deep_scan = False
    selected_scans = []
    if not args.url:
        from rich.table import Table
        
        console.print(f"[bold cyan]Target:[/bold cyan] {target_url}\n")
        table = Table(title="Select Scan Modules", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Module Name", style="bold white")
        table.add_column("Description", style="dim")
        table.add_row("1", "Full Scan", "Run All Modules (Recommended)")
        table.add_row("2", "DEEP FULL SCAN", "Extreme Crawl + All Modules")
        table.add_row("3", "Recon Only", "Headers, WAF, CMS Detect")
        table.add_row("4", "Port Scanner", "Scan Top 25 Common Ports")
        table.add_row("5", "Subdomains", "Enumerate Subdomains")
        table.add_row("6", "Crawler", "Map Website Structure (Spider)")
        table.add_row("7", "Injection Scan", "Test for SQLi & XSS (Real-Time)")
        table.add_row("8", "Advanced Resource Discovery", "Real-time DNS, Subdomains, Directories, Files, APIs")
        table.add_row("9", "CMS / WP Scan", "WordPress & CMS Specific Module")
        table.add_row("10", "Speed Test", "Real-Time Performance Analysis")
        table.add_row("11", "JS Secrets", "Find Leaked API Keys in JS Files")
        table.add_row("12", "Takeover", "Subdomain Takeover Check")
        table.add_row("13", "SSL Security", "Analyze SSL/TLS Configuration")
        table.add_row("14", "LFI Scan", "Local File Inclusion Fuzzing")
        table.add_row("15", "Open Redirect", "Test for Unsafe Redirects")
        table.add_row("16", "Backup Fuzzer", "Find Hidden Config/Backup Files")
        table.add_row("17", "CORS Scan", "Test Cross-Origin Resource Sharing")
        table.add_row("18", "Email Security", "Check SPF/DMARC Records")
        table.add_row("19", "Clickjacking", "Test UI Redress Protection")
        table.add_row("20", "RCE Scan", "Remote Code Execution Injection")
        table.add_row("21", "SSTI Scan", "Server-Side Template Injection")
        table.add_row("22", "JWT Analysis", "JSON Web Token Security")
        table.add_row("23", "GraphQL Scan", "API Introspection Check")
        table.add_row("24", "Proto Pollution", "NodeJS Prototype Injection")
        table.add_row("25", "WAF Bypass", "Firewall Evasion Testing")
        table.add_row("26", "XXE Scan", "XML External Entity Injection")
        table.add_row("27", "IDOR Scan", "Insecure Direct Object Reference")
        table.add_row("28", "Cloud Hunter", "Find Leaked S3/Azure Buckets")
        table.add_row("29", "Spring Boot", "Actuator RCE & Leaks")
        table.add_row("30", "CRLF Scan", "HTTP Response Splitting")
        table.add_row("31", "Shellshock", "Bash RCE (CVE-2014-6271)")
        table.add_row("32", "Host Header", "Poisoning & Redirection")
        table.add_row("33", "403 Bypass", "Path Fuzzing / ACL Bypass")
        table.add_row("34", "Java Deserialization", "Serialized Object RCE")
        table.add_row("35", "Broken Link Hijack", "Social Media Hijacking")
        table.add_row("36", "HTTP Smuggling", "Request Smuggling (CL.TE)")
        table.add_row("37", "Cache Deception", "Web Cache Poisoning")
        table.add_row("38", "Git Exposure", "Source Code Leak (.git)")
        table.add_row("39", "API Swagger", "Hidden API Docs")
        table.add_row("40", "Race Condition", "Logic Flaw Testing")
        table.add_row("41", "WebSocket Hijack", "CSWSH Scanner")
        table.add_row("42", "Reverse Tabnabbing", "Phishing via Links")
        table.add_row("43", "Dependency Confusion", "Supply Chain Risk")
        table.add_row("44", "Admin Panel Hunter", "Brute-force Login Pages")
        table.add_row("45", "S3 Bucket Brute", "Active Cloud Recon")
        table.add_row("46", "Param Miner", "Hidden Debug Params")
        table.add_row("47", "WebDAV Scanner", "Dangerous HTTP Methods")
        table.add_row("48", "IIS Shortname", "Hidden Files (Windows)")
        table.add_row("49", "API Key Validator", "Active Secret Testing")
        table.add_row("50", "SSI Injection", "Server-Side Include RCE")
        table.add_row("51", "XSLT Injection", "XML Transform RCE")
        table.add_row("52", "NoSQL Injection", "MongoDB Auth Bypass")
        table.add_row("53", "Ghost RCE", "Blind Time-Based RCE")
        table.add_row("54", "Silent SQLi", "Blind Database Injection")
        table.add_row("55", "Metadata SSRF", "Cloud Instance Takeover")
        table.add_row("56", "H2C Smuggling", "HTTP/2 Protocol Bypass")
        table.add_row("57", "PHP Object Inj", "Deserialization RCE")
        table.add_row("58", "GraphQL Batching", "Rate Limit Bypass")
        table.add_row("59", "LDAP Injection", "Active Directory Bypass")
        table.add_row("60", "XPath Injection", "XML Database Theft")
        table.add_row("61", "LaTeX Injection", "PDF Generator RCE")
        table.add_row("62", "Pickle Injection", "Python RCE")
        table.add_row("63", "SSRF Port Scan", "Internal Network Map")
        table.add_row("64", "ENV Extraction", "Sensitive Config Dump")
        table.add_row("65", "CSV Injection", "Formula Injection")
        table.add_row("66", "RPO Scanner", "CSS Hijacking")
        table.add_row("67", "XSSI Scanner", "JSON Data Theft")
        table.add_row("68", "ESI Injection", "CDN/Edge RCE")
        table.add_row("69", "Dangling Markup", "CSP Bypass (Data Theft)")
        table.add_row("70", "CSP Scanner", "Policy Weakness Audit")
        table.add_row("71", "HPP Scanner", "Param Pollution")
        table.add_row("72", "DOM XSS", "Client-Side Sinks")
        table.add_row("73", "Proto Pollution", "Client-Side Gadgets")
        table.add_row("74", "Log4Shell", "JNDI Injection (CVE-2021-44228)")
        table.add_row("75", "Spring4Shell", "Spring RCE (CVE-2022-22965)")
        table.add_row("76", "Server Proto", "NodeJS Object Injection")
        table.add_row("77", "Kubernetes", "K8s API & Dashboard Exposure")
        table.add_row("78", "Firebase", "Open Realtime Database")
        table.add_row("79", "Jenkins", "CI/CD RCE & Auth Bypass")
        table.add_row("80", "Elasticsearch", "Big Data Leak (Port 9200)")
        table.add_row("81", "Drupal", "CMS RCE (Drupalgeddon2)")
        table.add_row("82", "Tomcat", "App Server Manager RCE")
        table.add_row("83", "Ultra Admin", "Advanced Panel Hunter")
        table.add_row("84", "Citrix Gateway", "Enterprise RCE (CVE-2019-19781)")
        table.add_row("85", "ThinkPHP", "Framework RCE")
        table.add_row("86", "Ruby on Rails", "File Disclosure (CVE-2019-5418)")
        table.add_row("87", "WebLogic", "Enterprise T3/WSAT RCE")
        table.add_row("88", "SAP NetWeaver", "ERP Info Leak & Recon")
        table.add_row("89", "Microsoft Exchange", "ProxyLogon/Shell RCE")
        table.add_row("90", "VMware vCenter", "Infra RCE (CVE-2021-21972)")
        table.add_row("91", "F5 BIG-IP", "Gateway RCE (CVE-2020-5902)")
        table.add_row("92", "Atlassian Jira", "Template Injection RCE")
        table.add_row("93", "Atlassian Confluence", "OGNL Injection RCE")
        table.add_row("94", "Pulse Secure VPN", "Arbitrary File Read")
        table.add_row("95", "Apache Struts", "OGNL Injection RCE")
        table.add_row("96", "Adobe ColdFusion", "LFI & Serialization RCE")
        table.add_row("97", "Apache Solr", "Config API RCE")
        table.add_row("98", "Nginx", "Alias Traversal / Off-by-slash")
        table.add_row("99", "SonarQube", "Source Code Disclosure")
        table.add_row("100", "Grafana", "LFI (CVE-2021-43798)")
        table.add_row("101", "Tech Detective", "CMS, Theme & Stack Finder")
        table.add_row("102", "Redis Scanner", "Unauth RCE (Port 6379)")
        table.add_row("103", "Docker API", "Container Takeover (Port 2375)")
        table.add_row("104", "Memcached", "Cache Dump (Port 11211)")
        table.add_row("105", "Gitea Scanner", "RCE (CVE-2022-30781)")
        table.add_row("106", "MinIO Scanner", "Info Leak (CVE-2023-28432)")
        table.add_row("107", "Zabbix Scanner", "Auth Bypass (CVE-2022-23131)")
        table.add_row("108", "JBoss/WildFly", "JMX RCE (Unauth Access)")
        table.add_row("109", "GlassFish", "LFI / Admin (CVE-2017-1000028)")
        table.add_row("110", "Hadoop YARN", "Cluster RCE (Unauth API)")
        table.add_row("0", "Exit", "Close Application")
        console.print(table)
        console.print("[bold yellow]Enter module number (0-110), default=1:[/bold yellow] ", end="")
        choice = input().strip() or "1"
        if not choice.isdigit() or int(choice) < 0 or int(choice) > 110:
            console.print("[red]Invalid choice. Using default: Full Scan (1)[/red]")
            choice = "1"
        
        if choice == "0":
            sys.exit(0)
        elif choice == "1":
            selected_scans = ["recon", "cms", "ports", "subdomains", "crawler", "injection", "resources", "speed", "secrets", "takeover", "ssl", "lfi", "redirect", "fuzzer", "cors", "email", "clickjacking", "rce", "ssti", "jwt", "graphql", "prototype", "waf", "xxe", "idor", "cloud", "spring", "crlf", "shellshock", "host", "bypass_403", "java", "links", "smuggling", "cache", "git", "swagger", "race", "websocket", "tabnabbing", "deps", "admin", "s3", "miner", "webdav", "iis", "keys", "ssi", "xslt", "nosql", "blind_rce", "blind_sqli", "metadata", "h2c", "php_obj", "ql_batch", "ldap", "xpath", "latex", "pickle", "ssrf_port", "env_dump", "csv", "rpo", "xssi", "esi", "dangling", "csp_bypass", "hpp", "dom_xss", "proto_client", "log4shell", "spring4shell", "proto_server", "k8s", "firebase", "jenkins", "elastic", "drupal", "tomcat", "ultra_admin", "citrix", "thinkphp", "rails", "weblogic", "sap", "exchange", "vmware", "f5", "jira", "confluence", "pulse", "struts", "coldfusion", "solr", "nginx", "sonarqube", "grafana", "tech", "redis", "docker", "memcached", "gitea", "minio", "zabbix", "jboss", "glassfish", "hadoop", "advanced_resources", "scan"]
        elif choice == "2":
            selected_scans = ["recon", "ports", "subdomains", "crawler", "injection", "resources", "speed", "secrets", "takeover", "ssl", "lfi", "redirect", "fuzzer", "cors", "email", "clickjacking", "rce", "ssti", "jwt", "graphql", "prototype", "waf", "xxe", "idor", "cloud", "spring", "crlf", "shellshock", "host", "bypass_403", "java", "links", "smuggling", "cache", "git", "swagger", "race", "websocket", "tabnabbing", "deps", "admin", "s3", "miner", "webdav", "iis", "keys", "ssi", "xslt", "nosql", "blind_rce", "blind_sqli", "metadata", "h2c", "php_obj", "ql_batch", "ldap", "xpath", "latex", "pickle", "ssrf_port", "env_dump", "csv", "rpo", "xssi", "esi", "dangling", "csp_bypass", "hpp", "dom_xss", "proto_client", "log4shell", "spring4shell", "proto_server", "k8s", "firebase", "jenkins", "elastic", "drupal", "tomcat", "ultra_admin", "citrix", "thinkphp", "rails", "weblogic", "sap", "exchange", "vmware", "f5", "jira", "confluence", "pulse", "struts", "coldfusion", "solr", "nginx", "sonarqube", "grafana", "tech", "redis", "docker", "memcached", "gitea", "minio", "zabbix", "jboss", "glassfish", "hadoop"]
            deep_scan = True
        elif choice == "3":
            selected_scans = ["recon"]
        elif choice == "4":
            selected_scans = ["ports"]
        elif choice == "5":
            selected_scans = ["subdomains"]
        elif choice == "6":
            selected_scans = ["crawler"]
        elif choice == "7":
            selected_scans = ["injection"]
        elif choice == "8":
            selected_scans = ["advanced_resources"]
        elif choice == "9":
            selected_scans = ["cms"]
        elif choice == "10":
            selected_scans = ["speed"]
        elif choice == "11":
            selected_scans = ["secrets", "crawler"]
        elif choice == "12":
            selected_scans = ["takeover", "subdomains"]
        elif choice == "13":
            selected_scans = ["ssl"]
        elif choice == "14":
            selected_scans = ["lfi", "crawler"]
        elif choice == "15":
            selected_scans = ["redirect", "crawler"]
        elif choice == "16":
            selected_scans = ["fuzzer"]
        elif choice == "17":
            selected_scans = ["cors"]
        elif choice == "18":
            selected_scans = ["email"]
        elif choice == "19":
            selected_scans = ["clickjacking"]
        elif choice == "20":
            selected_scans = ["rce", "crawler"]
        elif choice == "21":
            selected_scans = ["ssti", "crawler"]
        elif choice == "22":
            selected_scans = ["jwt", "crawler"]
        elif choice == "23":
            selected_scans = ["graphql"]
        elif choice == "24":
            selected_scans = ["prototype", "crawler"]
        elif choice == "25":
            selected_scans = ["waf"]
        elif choice == "26":
            selected_scans = ["xxe", "crawler"]
        elif choice == "27":
            selected_scans = ["idor", "crawler"]
        elif choice == "28":
            selected_scans = ["cloud", "crawler"]
        elif choice == "29":
            selected_scans = ["spring"]
        elif choice == "30":
            selected_scans = ["crlf", "crawler"]
        elif choice == "31":
            selected_scans = ["shellshock", "crawler"]
        elif choice == "32":
            selected_scans = ["host"]
        elif choice == "33":
            selected_scans = ["bypass_403", "crawler"]
        elif choice == "34":
            selected_scans = ["java"]
        elif choice == "35":
            selected_scans = ["links", "crawler"]
        elif choice == "36":
            selected_scans = ["smuggling"]
        elif choice == "37":
            selected_scans = ["cache", "crawler"]
        elif choice == "38":
            selected_scans = ["git"]
        elif choice == "39":
            selected_scans = ["swagger"]
        elif choice == "40":
            selected_scans = ["race"]
        elif choice == "41":
            selected_scans = ["websocket"]
        elif choice == "42":
            selected_scans = ["tabnabbing", "crawler"]
        elif choice == "43":
            selected_scans = ["deps"]
        elif choice == "44":
            selected_scans = ["admin"]
        elif choice == "45":
            selected_scans = ["s3"]
        elif choice == "46":
            selected_scans = ["miner"]
        elif choice == "47":
            selected_scans = ["webdav"]
        elif choice == "48":
            selected_scans = ["iis"]
        elif choice == "49":
            selected_scans = ["keys"]
        elif choice == "50":
            selected_scans = ["ssi"]
        elif choice == "51":
            selected_scans = ["xslt"]
        elif choice == "52":
            selected_scans = ["nosql"]
        elif choice == "53":
            selected_scans = ["blind_rce"]
        elif choice == "54":
            selected_scans = ["blind_sqli"]
        elif choice == "55":
            selected_scans = ["metadata"]
        elif choice == "56":
            selected_scans = ["h2c"]
        elif choice == "57":
            selected_scans = ["php_obj"]
        elif choice == "58":
            selected_scans = ["ql_batch"]
        elif choice == "59":
            selected_scans = ["ldap"]
        elif choice == "60":
            selected_scans = ["xpath"]
        elif choice == "61":
            selected_scans = ["latex"]
        elif choice == "62":
            selected_scans = ["pickle"]
        elif choice == "63":
            selected_scans = ["ssrf_port"]
        elif choice == "64":
            selected_scans = ["env_dump"]
        elif choice == "65":
            selected_scans = ["csv"]
        elif choice == "66":
            selected_scans = ["rpo"]
        elif choice == "67":
            selected_scans = ["xssi"]
        elif choice == "68":
            selected_scans = ["esi"]
        elif choice == "69":
            selected_scans = ["dangling"]
        elif choice == "70":
            selected_scans = ["csp_bypass"]
        elif choice == "71":
            selected_scans = ["hpp"]
        elif choice == "72":
            selected_scans = ["dom_xss"]
        elif choice == "73":
            selected_scans = ["proto_client"]
        elif choice == "74":
            selected_scans = ["log4shell"]
        elif choice == "75":
            selected_scans = ["spring4shell"]
        elif choice == "76":
            selected_scans = ["proto_server"]
        elif choice == "77":
            selected_scans = ["k8s"]
        elif choice == "78":
            selected_scans = ["firebase"]
        elif choice == "79":
            selected_scans = ["jenkins"]
        elif choice == "80":
            selected_scans = ["elastic"]
        elif choice == "81":
            selected_scans = ["drupal"]
        elif choice == "82":
            selected_scans = ["tomcat"]
        elif choice == "83":
            selected_scans = ["ultra_admin"]
        elif choice == "84":
            selected_scans = ["citrix"]
        elif choice == "85":
            selected_scans = ["thinkphp"]
        elif choice == "86":
            selected_scans = ["rails"]
        elif choice == "87":
            selected_scans = ["weblogic"]
        elif choice == "88":
            selected_scans = ["sap"]
        elif choice == "89":
            selected_scans = ["exchange"]
        elif choice == "90":
            selected_scans = ["vmware"]
        elif choice == "91":
            selected_scans = ["f5"]
        elif choice == "92":
            selected_scans = ["jira"]
        elif choice == "93":
            selected_scans = ["confluence"]
        elif choice == "94":
            selected_scans = ["pulse"]
        elif choice == "95":
            selected_scans = ["struts"]
        elif choice == "96":
            selected_scans = ["coldfusion"]
        elif choice == "97":
            selected_scans = ["solr"]
        elif choice == "98":
            selected_scans = ["nginx"]
        elif choice == "99":
            selected_scans = ["sonarqube"]
        elif choice == "100":
            selected_scans = ["grafana"]
        elif choice == "101":
            selected_scans = ["tech"]
        elif choice == "102":
            selected_scans = ["redis"]
        elif choice == "103":
            selected_scans = ["docker"]
        elif choice == "104":
            selected_scans = ["memcached"]
        elif choice == "105":
            selected_scans = ["gitea"]
        elif choice == "106":
            selected_scans = ["minio"]
        elif choice == "107":
            selected_scans = ["zabbix"]
        elif choice == "108":
            selected_scans = ["jboss"]
        elif choice == "109":
            selected_scans = ["glassfish"]
        elif choice == "110":
            selected_scans = ["hadoop"]
    else:
        selected_scans = ["recon", "ports", "subdomains", "crawler", "injection", "resources", "speed", "secrets", "takeover", "ssl", "lfi", "redirect", "fuzzer", "cors", "email", "clickjacking", "rce", "ssti", "jwt", "graphql", "prototype", "waf", "xxe", "idor", "cloud", "spring", "crlf", "shellshock", "host", "bypass_403", "java", "links", "smuggling", "cache", "git", "swagger", "race", "websocket", "tabnabbing", "deps", "admin", "s3", "miner", "webdav", "iis", "keys", "ssi", "xslt", "nosql", "blind_rce", "blind_sqli", "metadata", "h2c", "php_obj", "ql_batch", "ldap", "xpath", "latex", "pickle", "ssrf_port", "env_dump", "csv", "rpo", "xssi", "esi", "dangling", "csp_bypass", "hpp", "dom_xss", "proto_client", "log4shell", "spring4shell", "proto_server", "k8s", "firebase", "jenkins", "elastic", "drupal", "tomcat", "ultra_admin", "citrix", "thinkphp", "rails", "weblogic", "sap", "exchange", "vmware", "f5", "jira", "confluence", "pulse", "struts", "coldfusion", "solr", "nginx", "sonarqube", "grafana", "tech", "redis", "docker", "memcached", "gitea", "minio", "zabbix", "jboss", "glassfish", "hadoop"]
    if config.verbose:
        log.setLevel("DEBUG")
    _total_modules = len(selected_scans)
    _module_counter = [0]
    def _next_module(name):
        _module_counter[0] += 1
        console.rule(f"[bold magenta][{_module_counter[0]}/{_total_modules}] {name}[/bold magenta]")
    console.print(Panel(f"[bold green]Target:[/bold green] {config.url}\n[bold green]Mode:[/bold green] {', '.join(selected_scans).upper()}\n[bold green]Threads:[/bold green] {config.threads}\n[bold green]Modules:[/bold green] {_total_modules} selected", title="Scan Configuration", border_style="blue"))
    timeout = aiohttp.ClientTimeout(total=config.timeout)
    conn = aiohttp.TCPConnector(ssl=False, limit=config.threads)
    headers = {'User-Agent': config.user_agent}
    if config.cookie:
        headers['Cookie'] = config.cookie
    if config.custom_header:
        try:
            h_key, h_val = config.custom_header.split(':', 1)
            headers[h_key.strip()] = h_val.strip()
        except ValueError:
            console.print(f"[yellow][!] Invalid header format. Use 'Key: Value'[/yellow]")
    async with aiohttp.ClientSession(connector=conn, timeout=timeout, headers=headers) as session:
        with console.status("[bold yellow]Validating target availability...[/bold yellow]"):
            status = await validate_target(session, config.url)
            if not status:
                console.print(f"[bold red][!] Target {config.url} is unreachable.[/bold red]")
                console.print("[yellow]Tip: Try adding http:// or https:// explicitly, or check your internet connection.[/yellow]")
                return
            console.print(f"[bold green][+] Target is UP (Status: {status})[/bold green]")
        recon_results = {}
        port_results = []
        subdomain_results = []
        scan_results = {}
        crawl_results = {}
        sqli_results = []
        xss_results = []
        cms_results = []
        cms_scan_data = {}
        if "recon" in selected_scans or "cms" in selected_scans:
            _next_module("Reconnaissance & CMS")
            if "recon" in selected_scans:
                try:
                    recon_results = await run_recon(session, config.url)
                except Exception as e:
                    console.print(f"[red][!] Recon module error: {e}[/red]")
            try:
                cms_results = await detect_cms(session, config.url)
                cms_scan_data = {}
                if "WordPress" in cms_results:
                    cms_scan_data = await scan_wordpress(session, config.url)
                else:
                    cms_scan_data = await scan_general(session, config.url)
            except Exception as e:
                console.print(f"[red][!] CMS module error: {e}[/red]")
        speed_results = {}
        if "speed" in selected_scans:
             _next_module("Performance Analysis")
             try:
                 speed_results = await run_speed_test(session, config.url)
             except Exception as e:
                 console.print(f"[red][!] Speed test error: {e}[/red]")
        if "ports" in selected_scans or "subdomains" in selected_scans:
            _next_module("Network & Subdomain Scan")
            if "ports" in selected_scans:
                try:
                    port_results = await scan_ports(config.url)
                except Exception as e:
                    console.print(f"[red][!] Port scanner error: {e}[/red]")
            if "subdomains" in selected_scans:
                try:
                    subdomain_results = await enumerate_subdomains(session, config.url)
                except Exception as e:
                    console.print(f"[red][!] Subdomain enum error: {e}[/red]")
        if "active" in selected_scans:
            pass
        if "crawler" in selected_scans or "injection" in selected_scans:
            _next_module("Deep Spider & Crawl")
            try:
                crawl_results = await run_crawler(session, config.url, deep=deep_scan)
            except Exception as e:
                console.print(f"[red][!] Crawler error: {e}[/red]")
        if "injection" in selected_scans:
            _next_module("Vulnerability Injection (SQLi + XSS)")
            urls_to_test = crawl_results.get('urls', [])
            forms_to_test = crawl_results.get('forms', [])
            if not urls_to_test and not forms_to_test:
                 console.print("[yellow]! No parameters or forms found to test injections. Try a deeper crawl?[/yellow]")
            else:
                try:
                    sqli_results = await run_sqli_scan(session, urls_to_test, forms=forms_to_test)
                    _count_vulns(sqli_results)
                except Exception as e:
                    console.print(f"[red][!] SQLi scanner error: {e}[/red]")
                try:
                    xss_results = await run_xss_scan(session, urls_to_test, forms=forms_to_test,
                                                     webhook_url=config.webhook_url)
                    _count_vulns(xss_results)
                except Exception as e:
                    console.print(f"[red][!] XSS scanner error: {e}[/red]")
                _print_vuln_status()
        advanced_resource_results = {}
        if "advanced_resources" in selected_scans:
            _next_module("Advanced Resource Discovery")
            try:
                advanced_resource_results = await run_resource_discovery(session, config.url)
            except Exception as e:
                console.print(f"[red][!] Resource discovery error: {e}[/red]")
        if "resources" in selected_scans:
            _next_module("Resource Discovery")
            try:
                scan_results = await run_active_scan(session, config.url)
            except Exception as e:
                console.print(f"[red][!] Active scan error: {e}[/red]")
        js_secrets_results = []
        takeover_results = []
        ssl_results = {}
        lfi_results = []
        redirect_results = []
        fuzzer_results = []
        cors_results = []
        email_results = {}
        clickjacking_results = {}
        rce_results = []
        ssti_results = []
        jwt_results = []
        graphql_results = []
        prototype_results = []
        waf_results = []
        xxe_results = []
        idor_results = []
        cloud_results = []
        spring_results = []
        crlf_results = []
        shellshock_results = []
        host_results = []
        bypass_403_results = []
        java_results = []
        links_results = []
        smuggling_results = []
        cache_results = []
        git_results = []
        swagger_results = []
        race_results = []
        websocket_results = []
        tabnabbing_results = []
        deps_results = []
        admin_results = []
        s3_results = []
        miner_results = []
        webdav_results = []
        iis_results = []
        keys_results = []
        ssi_results = []
        xslt_results = []
        nosql_results = []
        blind_rce_results = []
        blind_sqli_results = []
        metadata_results = []
        h2c_results = []
        php_obj_results = []
        ql_batch_results = []
        ldap_results = []
        xpath_results = []
        latex_results = []
        pickle_results = []
        ssrf_port_results = []
        env_dump_results = []
        csv_results = []
        rpo_results = []
        xssi_results = []
        esi_results = []
        dangling_results = []
        csp_bypass_results = []
        hpp_results = []
        dom_xss_results = []
        proto_client_results = []
        log4shell_results = []
        spring4shell_results = []
        proto_server_results = []
        k8s_results = []
        firebase_results = []
        jenkins_results = []
        elastic_results = []
        drupal_results = []
        tomcat_results = []
        ultra_admin_results = []
        citrix_results = []
        thinkphp_results = []
        rails_results = []
        weblogic_results = []
        sap_results = []
        exchange_results = []
        vmware_results = []
        f5_results = []
        jira_results = []
        confluence_results = []
        pulse_results = []
        struts_results = []
        coldfusion_results = []
        solr_results = []
        nginx_results = []
        sonarqube_results = []
        grafana_results = []
        tech_results = {}
        redis_results = []
        docker_results = []
        memcached_results = []
        gitea_results = []
        minio_results = []
        zabbix_results = []
        jboss_results = []
        glassfish_results = []
        hadoop_results = []
        
        if "ssl" in selected_scans:
            console.rule("[bold magenta]SSL Security Analysis[/bold magenta]")
            ssl_results = analyze_ssl(config.url)
            
        if "secrets" in selected_scans:
            console.rule("[bold magenta]JS Secrets Scan[/bold magenta]")
            js_files = crawl_results.get('js_files', [])
            if not js_files and "crawler" not in selected_scans:
                 console.print("[yellow][!] JS Scan requires Crawler. Crawling JS files now...[/yellow]")
                 crawler_temp = await run_crawler(session, config.url, deep=deep_scan)
                 js_files = crawler_temp.get('js_files', [])
            
            if js_files:
                js_secrets_results = await scan_js_secrets(session, js_files)
            else:
                console.print("[yellow][!] No JS files found to scan.[/yellow]")
                
        if "takeover" in selected_scans:
             console.rule("[bold magenta]Subdomain Takeover Scan[/bold magenta]")
             subs = subdomain_results if subdomain_results else []
             if not subs and "subdomains" not in selected_scans:
                  subs = [config.url]
             takeover_results = await scan_takeover(session, subs)
             
        if "lfi" in selected_scans:
             console.rule("[bold magenta]LFI Vulnerability Scan[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  lfi_results = await scan_lfi(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for LFI.[/yellow]")
                  
        if "redirect" in selected_scans:
             console.rule("[bold magenta]Open Redirect Scan[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  redirect_results = await scan_redirect(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for Redirects.[/yellow]")
                  
        if "fuzzer" in selected_scans:
             console.rule("[bold magenta]Sensitive File Fuzzer[/bold magenta]")
             fuzzer_results = await run_fuzzer(session, config.url)

        if "cors" in selected_scans:
             console.rule("[bold magenta]CORS Configuration Scan[/bold magenta]")
             cors_results = await scan_cors(session, config.url)

        if "email" in selected_scans:
             console.rule("[bold magenta]Email Security (SPF/DMARC)[/bold magenta]")
             email_results = await scan_email_security(session, config.url)

        if "clickjacking" in selected_scans:
             console.rule("[bold magenta]Clickjacking Scanner[/bold magenta]")
             clickjacking_results = await scan_clickjacking(session, config.url)

        if "rce" in selected_scans:
             console.rule("[bold magenta]RCE Injection Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  rce_results = await scan_rce(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for RCE.[/yellow]")

        if "ssti" in selected_scans:
             console.rule("[bold magenta]SSTI Injection Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  ssti_results = await scan_ssti(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for SSTI.[/yellow]")

        if "jwt" in selected_scans:
             console.rule("[bold magenta]JWT Security Analyzer[/bold magenta]")
             all_links = crawl_results.get('all_links', [])
             if not all_links: all_links = [config.url]
             jwt_results = await scan_jwt(session, all_links)
             
        if "graphql" in selected_scans:
             console.rule("[bold magenta]GraphQL Introspection Scan[/bold magenta]")
             graphql_results = await scan_graphql(session, config.url)

        if "prototype" in selected_scans:
             console.rule("[bold magenta]Prototype Pollution Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  prototype_results = await scan_prototype(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for Prototype Pollution.[/yellow]")
                  
        if "waf" in selected_scans:
             console.rule("[bold magenta]WAF Bypass Testing[/bold magenta]")
             waf_results = await scan_waf_bypass(session, config.url)

        if "xxe" in selected_scans:
             console.rule("[bold magenta]XXE Injection Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  xxe_results = await scan_xxe(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for XXE.[/yellow]")
                  
        if "idor" in selected_scans:
             console.rule("[bold magenta]IDOR Logic Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  idor_results = await scan_idor(session, urls)
             else:
                  console.print("[yellow][!] No numeric parameters found for IDOR.[/yellow]")
                  
        if "cloud" in selected_scans:
             console.rule("[bold magenta]Cloud Storage Hunter[/bold magenta]")
             urls = crawl_results.get('all_links', [])
             if not urls: urls = [config.url]
             cloud_results = await scan_cloud_hunter(session, urls)
             
        if "spring" in selected_scans:
             console.rule("[bold magenta]Spring Boot Scanner[/bold magenta]")
             spring_results = await scan_spring_boot(session, config.url)

        if "crlf" in selected_scans:
             console.rule("[bold magenta]CRLF Injection Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if urls:
                  crlf_results = await scan_crlf(session, urls)
             else:
                  console.print("[yellow][!] No fuzzable parameters found for CRLF.[/yellow]")

        if "shellshock" in selected_scans:
             console.rule("[bold magenta]Shellshock Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             shellshock_results = await scan_shellshock(session, urls)
             
        if "host" in selected_scans:
             console.rule("[bold magenta]Host Header Injection[/bold magenta]")
             host_results = await scan_host_header(session, config.url)

        if "bypass_403" in selected_scans:
             console.rule("[bold magenta]403 Forbidden Bypass[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             bypass_403_results = await scan_403_bypass(session, urls)

        if "java" in selected_scans:
             console.rule("[bold magenta]Java Deserialization Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             java_results = await scan_java_deser(session, urls)
             
        if "links" in selected_scans:
             console.rule("[bold magenta]Broken Link Hijacker[/bold magenta]")
             urls = crawl_results.get('all_links', [])
             links_results = await scan_broken_links(session, urls)

        if "smuggling" in selected_scans:
             console.rule("[bold magenta]HTTP Request Smuggling[/bold magenta]")
             smuggling_results = await scan_smuggling(session, config.url)

        if "cache" in selected_scans:
             console.rule("[bold magenta]Web Cache Deception[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             cache_results = await scan_cache_deception(session, urls)
             
        if "git" in selected_scans:
             console.rule("[bold magenta]Git Exposure Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             git_results = await scan_git_exposure(session, urls)

        if "swagger" in selected_scans:
             console.rule("[bold magenta]API Swagger Hunter[/bold magenta]")
             swagger_results = await scan_swagger(session, config.url)

        if "race" in selected_scans:
             console.rule("[bold magenta]Race Condition Tester[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             race_results = await scan_race_condition(session, urls)

        if "websocket" in selected_scans:
             console.rule("[bold magenta]WebSocket Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             websocket_results = await scan_websocket(session, urls)

        if "tabnabbing" in selected_scans:
             console.rule("[bold magenta]Reverse Tabnabbing Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             tabnabbing_results = await scan_tabnabbing(session, urls)
             
        if "deps" in selected_scans:
             console.rule("[bold magenta]Dependency Confusion Scanner[/bold magenta]")
             deps_results = await scan_dependencies(session, config.url)

        if "admin" in selected_scans:
             console.rule("[bold magenta]Admin Panel Hunter[/bold magenta]")
             admin_results = await scan_admin_hunt(session, config.url)

        if "s3" in selected_scans:
             console.rule("[bold magenta]S3 Bucket Bruteforcer[/bold magenta]")
             s3_results = await scan_s3_brute(session, config.url)

        if "miner" in selected_scans:
             console.rule("[bold magenta]Hidden Parameter Miner[/bold magenta]")
             miner_results = await scan_param_miner(session, config.url)

        if "webdav" in selected_scans:
             console.rule("[bold magenta]WebDAV Scanner[/bold magenta]")
             urls = crawl_results.get('urls', [])
             if not urls: urls = [config.url]
             webdav_results = await scan_webdav(session, urls)

        if "iis" in selected_scans:
             console.rule("[bold magenta]IIS Shortname Scanner[/bold magenta]")
             iis_results = await scan_iis_shortname(session, config.url)
             
        if "keys" in selected_scans:
             console.rule("[bold magenta]API Key Validator[/bold magenta]")
             keys_results = await scan_key_validator(session, config.url)

        if "ssi" in selected_scans:
             console.rule("[bold magenta]SSI Injection Scanner[/bold magenta]")
             ssi_results = await scan_ssi(session, config.url)

        if "xslt" in selected_scans:
             console.rule("[bold magenta]XSLT Injection Scanner[/bold magenta]")
             xslt_results = await scan_xslt(session, config.url)
             
        if "nosql" in selected_scans:
             console.rule("[bold magenta]NoSQL Injection Scanner[/bold magenta]")
             nosql_results = await scan_nosql(session, config.url)

        if "blind_rce" in selected_scans:
             console.rule("[bold magenta]Ghost RCE (Time-Based)[/bold magenta]")
             blind_rce_results = await scan_blind_rce(session, config.url)

        if "blind_sqli" in selected_scans:
             console.rule("[bold magenta]Silent SQLi (Blind)[/bold magenta]")
             blind_sqli_results = await scan_blind_sqli(session, config.url)

        if "h2c" in selected_scans:
             console.rule("[bold magenta]H2C Smuggling Scanner[/bold magenta]")
             h2c_results = await scan_h2c_smuggler(session, config.url)

        if "php_obj" in selected_scans:
             console.rule("[bold magenta]PHP Object Injection[/bold magenta]")
             php_obj_results = await scan_php_object(session, config.url)
             
        if "ql_batch" in selected_scans:
             console.rule("[bold magenta]GraphQL Batching Scanner[/bold magenta]")
             ql_batch_results = await scan_graphql_batch(session, config.url)

        if "ldap" in selected_scans:
             console.rule("[bold magenta]LDAP Injection Scanner[/bold magenta]")
             ldap_results = await scan_ldap(session, config.url)

        if "xpath" in selected_scans:
             console.rule("[bold magenta]XPath Injection Scanner[/bold magenta]")
             xpath_results = await scan_xpath(session, config.url)

        if "latex" in selected_scans:
             console.rule("[bold magenta]LaTeX Injection Scanner[/bold magenta]")
             latex_results = await scan_latex(session, config.url)

        if "pickle" in selected_scans:
             console.rule("[bold magenta]Pickle Injection Scanner[/bold magenta]")
             pickle_results = await scan_pickle(session, config.url)

        if "ssrf_port" in selected_scans:
             console.rule("[bold magenta]SSRF Internal Port Scanner[/bold magenta]")
             ssrf_port_results = await scan_ssrf_port(session, config.url)

        if "env_dump" in selected_scans:
             console.rule("[bold magenta]ENV & Config Dumper[/bold magenta]")
             env_dump_results = await scan_env_dump(session, config.url)

        if "csv" in selected_scans:
             console.rule("[bold magenta]CSV Injection Scanner[/bold magenta]")
             csv_results = await scan_csv_injection(session, config.url)

        if "rpo" in selected_scans:
             console.rule("[bold magenta]RPO Scanner[/bold magenta]")
             rpo_results = await scan_rpo(session, config.url)

        if "xssi" in selected_scans:
             console.rule("[bold magenta]XSSI Scanner[/bold magenta]")
             xssi_results = await scan_xssi(session, config.url)

        if "esi" in selected_scans:
             console.rule("[bold magenta]ESI Injection Scanner[/bold magenta]")
             esi_results = await scan_esi(session, config.url)

        if "dangling" in selected_scans:
             console.rule("[bold magenta]Dangling Markup Scanner[/bold magenta]")
             dangling_results = await scan_dangling(session, config.url)

        if "csp_bypass" in selected_scans:
             console.rule("[bold magenta]CSP Policy Scanner[/bold magenta]")
             csp_bypass_results = await scan_csp_bypass(session, config.url)

        if "hpp" in selected_scans:
             console.rule("[bold magenta]HPP Scanner[/bold magenta]")
             hpp_results = await scan_hpp(session, config.url)

        if "dom_xss" in selected_scans:
             console.rule("[bold magenta]DOM XSS Scanner[/bold magenta]")
             dom_xss_results = await scan_dom_xss(session, config.url)

        if "proto_client" in selected_scans:
             console.rule("[bold magenta]Proto Pollution Scanner[/bold magenta]")
             proto_client_results = await scan_proto_client(session, config.url)

        if "log4shell" in selected_scans:
             console.rule("[bold magenta]Log4Shell Scanner[/bold magenta]")
             log4shell_results = await scan_log4shell(session, config.url)

        if "spring4shell" in selected_scans:
             console.rule("[bold magenta]Spring4Shell Scanner[/bold magenta]")
             spring4shell_results = await scan_spring4shell(session, config.url)

        if "proto_server" in selected_scans:
             console.rule("[bold magenta]Server-Side Proto Pollution[/bold magenta]")
             proto_server_results = await scan_proto_server(session, config.url)

        if "k8s" in selected_scans:
             console.rule("[bold magenta]Kubernetes Scanner[/bold magenta]")
             k8s_results = await scan_k8s(session, config.url)

        if "firebase" in selected_scans:
             console.rule("[bold magenta]Firebase Scanner[/bold magenta]")
             firebase_results = await scan_firebase(session, config.url)

        if "jenkins" in selected_scans:
             console.rule("[bold magenta]Jenkins Scanner[/bold magenta]")
             jenkins_results = await scan_jenkins(session, config.url)

        if "elastic" in selected_scans:
             console.rule("[bold magenta]Elasticsearch Scanner[/bold magenta]")
             elastic_results = await scan_elastic(session, config.url)

        if "drupal" in selected_scans:
             console.rule("[bold magenta]Drupal Scanner[/bold magenta]")
             drupal_results = await scan_drupal(session, config.url)

        if "tomcat" in selected_scans:
             console.rule("[bold magenta]Tomcat Scanner[/bold magenta]")
             tomcat_results = await scan_tomcat(session, config.url)

        if "ultra_admin" in selected_scans:
             console.rule("[bold magenta]Ultra Admin Hunter[/bold magenta]")
             ultra_admin_results = await scan_ultra_admin(session, config.url)

        if "citrix" in selected_scans:
             console.rule("[bold magenta]Citrix Scanner[/bold magenta]")
             citrix_results = await scan_citrix(session, config.url)

        if "thinkphp" in selected_scans:
             console.rule("[bold magenta]ThinkPHP Scanner[/bold magenta]")
             thinkphp_results = await scan_thinkphp(session, config.url)

        if "rails" in selected_scans:
             console.rule("[bold magenta]Ruby on Rails Scanner[/bold magenta]")
             rails_results = await scan_rails(session, config.url)

        if "weblogic" in selected_scans:
             console.rule("[bold magenta]WebLogic Scanner[/bold magenta]")
             weblogic_results = await scan_weblogic(session, config.url)

        if "sap" in selected_scans:
             console.rule("[bold magenta]SAP Scanner[/bold magenta]")
             sap_results = await scan_sap(session, config.url)

        if "exchange" in selected_scans:
             console.rule("[bold magenta]Exchange Scanner[/bold magenta]")
             exchange_results = await scan_exchange(session, config.url)

        if "vmware" in selected_scans:
             console.rule("[bold magenta]VMware Scanner[/bold magenta]")
             vmware_results = await scan_vmware(session, config.url)

        if "f5" in selected_scans:
             console.rule("[bold magenta]F5 Scanner[/bold magenta]")
             f5_results = await scan_f5(session, config.url)

        if "jira" in selected_scans:
             console.rule("[bold magenta]Jira Scanner[/bold magenta]")
             jira_results = await scan_jira(session, config.url)

        if "confluence" in selected_scans:
             console.rule("[bold magenta]Confluence Scanner[/bold magenta]")
             confluence_results = await scan_confluence(session, config.url)

        if "pulse" in selected_scans:
             console.rule("[bold magenta]Pulse Secure Scanner[/bold magenta]")
             pulse_results = await scan_pulse(session, config.url)

        if "struts" in selected_scans:
             console.rule("[bold magenta]Struts Scanner[/bold magenta]")
             struts_results = await scan_struts(session, config.url)

        if "coldfusion" in selected_scans:
             console.rule("[bold magenta]ColdFusion Scanner[/bold magenta]")
             coldfusion_results = await scan_coldfusion(session, config.url)

        if "solr" in selected_scans:
             console.rule("[bold magenta]Solr Scanner[/bold magenta]")
             solr_results = await scan_solr(session, config.url)

        if "nginx" in selected_scans:
             console.rule("[bold magenta]Nginx Scanner[/bold magenta]")
             nginx_results = await scan_nginx(session, config.url)

        if "sonarqube" in selected_scans:
             console.rule("[bold magenta]SonarQube Scanner[/bold magenta]")
             sonarqube_results = await scan_sonarqube(session, config.url)

        if "grafana" in selected_scans:
             console.rule("[bold magenta]Grafana Scanner[/bold magenta]")
             grafana_results = await scan_grafana(session, config.url)

        if "tech" in selected_scans:
             console.rule("[bold magenta]Deep Tech Detective[/bold magenta]")
             tech_results = await scan_tech(session, config.url)

        if "redis" in selected_scans:
             console.rule("[bold magenta]Redis Scanner[/bold magenta]")
             redis_results = await scan_redis(session, config.url)

        if "docker" in selected_scans:
             console.rule("[bold magenta]Docker API Scanner[/bold magenta]")
             docker_results = await scan_docker(session, config.url)

        if "memcached" in selected_scans:
             console.rule("[bold magenta]Memcached Scanner[/bold magenta]")
             memcached_results = await scan_memcached(session, config.url)

        if "gitea" in selected_scans:
             console.rule("[bold magenta]Gitea Scanner[/bold magenta]")
             gitea_results = await scan_gitea(session, config.url)

        if "minio" in selected_scans:
             console.rule("[bold magenta]MinIO Scanner[/bold magenta]")
             minio_results = await scan_minio(session, config.url)

        if "zabbix" in selected_scans:
             console.rule("[bold magenta]Zabbix Scanner[/bold magenta]")
             zabbix_results = await scan_zabbix(session, config.url)

        if "jboss" in selected_scans:
             console.rule("[bold magenta]JBoss/WildFly Scanner[/bold magenta]")
             jboss_results = await scan_jboss(session, config.url)

        if "glassfish" in selected_scans:
             console.rule("[bold magenta]GlassFish Scanner[/bold magenta]")
             glassfish_results = await scan_glassfish(session, config.url)

        if "hadoop" in selected_scans:
             console.rule("[bold magenta]Hadoop YARN Scanner[/bold magenta]")
             hadoop_results = await scan_hadoop(session, config.url)

        wayback_results = {}
        dns_zone_results = {}
        vhost_results = []
        session_token_results = {}
        param_fuzz_results = []
        google_dork_results = {}
        shodan_results = {}
        vt_results = {}
        github_leak_results = {}

        if "recon" in selected_scans or "wayback" in selected_scans:
            console.rule("[bold magenta]Wayback Machine Deep Recon[/bold magenta]")
            wayback_results = await scan_wayback(session, config.url)

        if "recon" in selected_scans or "dns_zone" in selected_scans:
            console.rule("[bold magenta]DNS Zone Transfer & Enum[/bold magenta]")
            dns_zone_results = await scan_dns_zone(session, config.url)

        if "recon" in selected_scans or "vhost" in selected_scans:
            console.rule("[bold magenta]Virtual Host Discovery[/bold magenta]")
            vhost_results = await scan_vhost(session, config.url)

        if "recon" in selected_scans or "session" in selected_scans:
            console.rule("[bold magenta]Session Token Analysis[/bold magenta]")
            session_token_results = await scan_session(session, config.url)

        if "injection" in selected_scans or "param_fuzz" in selected_scans:
            console.rule("[bold magenta]Smart Parameter Discovery[/bold magenta]")
            param_fuzz_results = await scan_param_fuzzer(session, config.url)

        if "recon" in selected_scans or "google_dorks" in selected_scans:
            console.rule("[bold magenta]Google Dork Intelligence[/bold magenta]")
            google_dork_results = await scan_google_dorks(session, config.url)

        if config.shodan_key:
            console.rule("[bold magenta]Shodan Intelligence[/bold magenta]")
            shodan_results = await scan_shodan(session, config.url, config.shodan_key)

        if config.vt_key:
            console.rule("[bold magenta]VirusTotal Intelligence[/bold magenta]")
            vt_results = await scan_virustotal(session, config.url, config.vt_key)

        if "recon" in selected_scans or config.github_token:
            console.rule("[bold magenta]GitHub Leak Scanner[/bold magenta]")
            github_leak_results = await scan_github_leaks(session, config.url, config.github_token)

        waf_bypass_results = {}
        rate_limit_results = {}
        http2_results = {}
        brute_force_results = {}
        plugin_results = {}

        if "recon" in selected_scans or "waf" in selected_scans:
            console.rule("[bold magenta]WAF Detection & Bypass[/bold magenta]")
            waf_bypass_results = await scan_waf_bypass(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Rate Limit Detection[/bold magenta]")
            rate_limit_results = await detect_rate_limit(session, config.url)

        if "recon" in selected_scans or "http2" in selected_scans:
            console.rule("[bold magenta]HTTP/2 Protocol Scanner[/bold magenta]")
            http2_results = await scan_http2(session, config.url)

        if "brute" in selected_scans:
            console.rule("[bold magenta]Login Brute Force[/bold magenta]")
            brute_force_results = await scan_brute_force(session, config.url, config.wordlist)

        console.rule("[bold magenta]Plugin System[/bold magenta]")
        plugin_results = await run_plugins(session, config.url)

        js_results = {}
        ct_results = {}
        takeover_results = []
        cloud_meta_results = []
        ws_results = {}
        gql_deep_results = {}

        if "recon" in selected_scans or "js" in selected_scans:
            console.rule("[bold magenta]JavaScript File Analyzer[/bold magenta]")
            js_results = await scan_js_files(session, config.url)

        if "recon" in selected_scans or "ct" in selected_scans:
            console.rule("[bold magenta]Certificate Transparency Scanner[/bold magenta]")
            ct_results = await scan_ct_logs(session, config.url)

        if "recon" in selected_scans or "takeover" in selected_scans:
            console.rule("[bold magenta]Subdomain Takeover Scanner[/bold magenta]")
            sub_list = ct_results.get('subdomains', []) if ct_results else None
            takeover_results = await scan_subdomain_takeover(session, config.url, sub_list)

        if "injection" in selected_scans or "ssrf" in selected_scans:
            console.rule("[bold magenta]Cloud Metadata SSRF Scanner[/bold magenta]")
            cloud_meta_results = await scan_cloud_metadata(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]WebSocket Security Scanner[/bold magenta]")
            ws_results = await scan_websocket(session, config.url)

        if "recon" in selected_scans or "graphql" in selected_scans:
            console.rule("[bold magenta]GraphQL Deep Scanner[/bold magenta]")
            gql_deep_results = await scan_graphql_deep(session, config.url)

        nuclei_results = []
        network_map_results = {}
        dark_web_results = {}
        protocol_fuzz_results = []

        if "recon" in selected_scans:
            console.rule("[bold magenta]Nuclei Template Engine[/bold magenta]")
            nuclei_results = await scan_nuclei_templates(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Network Topology Mapper[/bold magenta]")
            network_map_results = await scan_network_topology(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Dark Web & Breach Monitor[/bold magenta]")
            dark_web_results = await scan_dark_web(session, config.url)

        if "injection" in selected_scans or "fuzzing" in selected_scans:
            console.rule("[bold magenta]Advanced Protocol Fuzzer[/bold magenta]")
            protocol_fuzz_results = await scan_protocol_fuzzer(session, config.url)

        oauth_results = {}
        dns_rebind_results = {}
        cache_poison_results = {}
        cicd_results = {}
        email_harvest_results = {}
        whois_results = {}
        tech_fp_results = {}
        social_results = {}

        if "recon" in selected_scans:
            console.rule("[bold magenta]OAuth/SAML Scanner[/bold magenta]")
            oauth_results = await scan_oauth_saml(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]DNS Rebinding Tester[/bold magenta]")
            dns_rebind_results = await scan_dns_rebinding(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Cache Poisoning Scanner[/bold magenta]")
            cache_poison_results = await scan_cache_poisoning(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]CI/CD Pipeline Detector[/bold magenta]")
            cicd_results = await scan_cicd_pipelines(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Email Harvester[/bold magenta]")
            email_harvest_results = await scan_email_harvester(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]WHOIS History[/bold magenta]")
            whois_results = await scan_whois_history(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Deep Tech Fingerprinter[/bold magenta]")
            tech_fp_results = await scan_tech_fingerprint(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Social Recon / OSINT[/bold magenta]")
            social_results = await scan_social_recon(session, config.url)

        blind_xss_results = {}
        api_disc_results = {}
        sensitive_results = {}
        log4j_results = {}
        mass_assign_results = {}
        broken_access_results = {}
        threat_results = {}
        desync_results = {}
        sub_brute_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]Blind XSS Scanner[/bold magenta]")
            blind_xss_results = await scan_blind_xss(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]API Endpoint Discovery[/bold magenta]")
            api_disc_results = await scan_api_discovery(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Sensitive File Finder[/bold magenta]")
            sensitive_results = await scan_sensitive_files(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Log4Shell Scanner[/bold magenta]")
            log4j_results = await scan_log4shell(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Mass Assignment Scanner[/bold magenta]")
            mass_assign_results = await scan_mass_assignment(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Broken Access Control[/bold magenta]")
            broken_access_results = await scan_broken_access(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Threat Intelligence Feed[/bold magenta]")
            threat_results = await scan_threat_intel(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]HTTP Desync / Request Splitting[/bold magenta]")
            desync_results = await scan_http_desync(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Subdomain Brute Force[/bold magenta]")
            sub_brute_results = await scan_subdomain_brute(session, config.url)

        redos_results = {}
        timing_results = {}
        content_disc_results = {}
        dep_confusion_results = {}
        bola_results = {}
        deser_results = {}
        misconfig_results = {}
        zeroday_results = {}
        encoder_results = {}
        compliance_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]ReDoS Scanner[/bold magenta]")
            redos_results = await scan_redos(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Timing Attack Scanner[/bold magenta]")
            timing_results = await scan_timing_attack(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Content Discovery Engine[/bold magenta]")
            content_disc_results = await scan_content_discovery(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Dependency Confusion Scanner[/bold magenta]")
            dep_confusion_results = await scan_dependency_confusion(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]BOLA/BFLA Scanner[/bold magenta]")
            bola_results = await scan_bola(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Insecure Deserialization[/bold magenta]")
            deser_results = await scan_deserialization(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Server Misconfiguration[/bold magenta]")
            misconfig_results = await scan_server_misconfig(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Zero-Day Pattern Detector[/bold magenta]")
            zeroday_results = await scan_zero_day(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]WAF Bypass Payload Encoder[/bold magenta]")
            encoder_results = await scan_with_encoded_payloads(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Compliance Scanner (PCI/GDPR/SOC2)[/bold magenta]")
            compliance_results = await scan_compliance(session, config.url)

        race_results = {}
        wasm_results = {}
        proto_deep_results = {}
        ssrf_chain_results = {}
        biz_logic_results = {}
        jwt_forge_results = {}
        surface_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]Race Condition Deep Scanner[/bold magenta]")
            race_results = await scan_race_condition(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]WebAssembly Scanner[/bold magenta]")
            wasm_results = await scan_wasm(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Prototype Pollution Deep[/bold magenta]")
            proto_deep_results = await scan_proto_pollution(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]SSRF Chain Builder[/bold magenta]")
            ssrf_chain_results = await scan_ssrf_chain(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Business Logic Fuzzer[/bold magenta]")
            biz_logic_results = await scan_business_logic(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]JWT Forge Engine[/bold magenta]")
            jwt_forge_results = await scan_jwt_forge(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Attack Surface Mapper[/bold magenta]")
            surface_results = await scan_attack_surface(session, config.url)

        graphql_deep_results = {}
        ai_predict_results = {}
        dns_exfil_results = {}
        oauth2_results = {}
        rate_bypass_results = {}
        mem_leak_results = {}
        client_atk_results = {}
        supply_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]GraphQL Deep Scanner[/bold magenta]")
            graphql_deep_results = await scan_graphql_deep(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]AI Vulnerability Predictor[/bold magenta]")
            ai_predict_results = await scan_ai_predict(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]DNS Exfiltration Detector[/bold magenta]")
            dns_exfil_results = await scan_dns_exfil(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]OAuth2 Full Chain[/bold magenta]")
            oauth2_results = await scan_oauth2_chain(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Rate Limit Bypass[/bold magenta]")
            rate_bypass_results = await scan_rate_bypass(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Memory Leak Scanner[/bold magenta]")
            mem_leak_results = await scan_memory_leak(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Client-Side Attack Engine[/bold magenta]")
            client_atk_results = await scan_client_attack(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Supply Chain Auditor[/bold magenta]")
            supply_results = await scan_supply_chain(session, config.url)

        smuggle_results = {}
        ws_hijack_results = {}
        cloud_meta_results = {}
        cache_dec_results = {}
        api_recon_results = {}
        blind_ssrf_results = {}
        session_fix_results = {}
        cors_chain_results = {}
        header_inj_results = {}
        iot_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]HTTP Request Smuggling[/bold magenta]")
            smuggle_results = await scan_http_smuggle(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]WebSocket Hijacker[/bold magenta]")
            ws_hijack_results = await scan_websocket_hijack(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Cloud Metadata Harvester[/bold magenta]")
            cloud_meta_results = await scan_cloud_metadata(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Cache Deception Scanner[/bold magenta]")
            cache_dec_results = await scan_cache_deception(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]API Schema Reconstructor[/bold magenta]")
            api_recon_results = await scan_api_reconstruct(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Blind SSRF Oracle[/bold magenta]")
            blind_ssrf_results = await scan_blind_ssrf(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Session Fixation Engine[/bold magenta]")
            session_fix_results = await scan_session_fixation(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]CORS Chain Exploiter[/bold magenta]")
            cors_chain_results = await scan_cors_chain(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]HTTP Header Injection[/bold magenta]")
            header_inj_results = await scan_header_injection(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]IoT/Firmware Scanner[/bold magenta]")
            iot_results = await scan_iot(session, config.url)

        zeroday_results = {}
        waf_results = {}
        sd_takeover_results = {}
        dep_conf_results = {}
        secrets_results = {}
        hpp_results = {}
        email_results = {}
        js_deob_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]Zero-Day Pattern Detector[/bold magenta]")
            zeroday_results = await scan_zeroday_detect(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]WAF Fingerprint & Bypass[/bold magenta]")
            waf_results = await scan_waf_bypass(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Subdomain Takeover Engine[/bold magenta]")
            sd_takeover_results = await scan_subdomain_takeover(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Dependency Confusion Scanner[/bold magenta]")
            dep_conf_results = await scan_dep_confusion(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Secrets Regex Engine[/bold magenta]")
            secrets_results = await scan_secrets_engine(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]HTTP Parameter Pollution[/bold magenta]")
            hpp_results = await scan_hpp(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Email Security Deep[/bold magenta]")
            email_results = await scan_email_deep(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]JavaScript Deobfuscator[/bold magenta]")
            js_deob_results = await scan_js_deobfuscate(session, config.url)

        webshell_results = {}
        backdoor_results = {}
        malware_results = {}
        hidden_admin_results = {}
        phishing_results = {}
        rootkit_results = {}
        deface_results = {}
        c2_results = {}
        forensic_results = {}

        if "injection" in selected_scans:
            console.rule("[bold magenta]WebShell Detector[/bold magenta]")
            webshell_results = await scan_webshell_detect(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Backdoor Finder[/bold magenta]")
            backdoor_results = await scan_backdoor_finder(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Malware Scanner[/bold magenta]")
            malware_results = await scan_malware(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Hidden Admin Finder[/bold magenta]")
            hidden_admin_results = await scan_hidden_admin(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Phishing Detector[/bold magenta]")
            phishing_results = await scan_phishing_detect(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Web Rootkit Detector[/bold magenta]")
            rootkit_results = await scan_rootkit_web(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]Defacement Monitor[/bold magenta]")
            deface_results = await scan_defacement(session, config.url)

        if "injection" in selected_scans:
            console.rule("[bold magenta]C2 Beacon Detector[/bold magenta]")
            c2_results = await scan_c2_detect(session, config.url)

        if "recon" in selected_scans:
            console.rule("[bold magenta]Forensic Analyzer[/bold magenta]")
            forensic_results = await scan_forensic(session, config.url)

        console.rule("[bold magenta]Scan Complete[/bold magenta]")
        console.print("[bold green]All requested phases completed.[/bold green]")
        full_report = {
            "target": config.url,
            "timestamp": get_timestamp(),
            "recon": recon_results,
            "cms": cms_results,
            "cms_details": cms_scan_data,
            "speed": speed_results,
            "ports": port_results,
            "subdomains": subdomain_results,
            "crawl": crawl_results,
            "vulnerabilities": {
                "sqli": sqli_results,
                "xss": xss_results,
                "lfi": lfi_results,
                "redirect": redirect_results,
                "takeover": takeover_results,
                "rce": rce_results,
                "ssti": ssti_results
            },
            "secrets": js_secrets_results,
            "jwt": jwt_results,
            "graphql": graphql_results,
            "prototype": prototype_results,
            "waf": waf_results,
            "xxe": xxe_results,
            "idor": idor_results,
            "cloud": cloud_results,
            "spring": spring_results,
            "crlf": crlf_results,
            "shellshock": shellshock_results,
            "host": host_results,
            "bypass_403": bypass_403_results,
            "java": java_results,
            "links": links_results,
            "smuggling": smuggling_results,
            "cache": cache_results,
            "git": git_results,
            "swagger": swagger_results,
            "race": race_results,
            "websocket": websocket_results,
            "tabnabbing": tabnabbing_results,
            "deps": deps_results,
            "admin": admin_results,
            "s3": s3_results,
            "miner": miner_results,
            "webdav": webdav_results,
            "iis": iis_results,
            "keys": keys_results,
            "ssi": ssi_results,
            "xslt": xslt_results,
            "nosql": nosql_results,
            "blind_rce": blind_rce_results,
            "blind_sqli": blind_sqli_results,
            "metadata": metadata_results,
            "h2c": h2c_results,
            "php_obj": php_obj_results,
            "ql_batch": ql_batch_results,
            "ldap": ldap_results,
            "xpath": xpath_results,
            "latex": latex_results,
            "pickle": pickle_results,
            "ssrf_port": ssrf_port_results,
            "env_dump": env_dump_results,
            "csv": csv_results,
            "rpo": rpo_results,
            "xssi": xssi_results,
            "esi": esi_results,
            "dangling": dangling_results,
            "csp_bypass": csp_bypass_results,
            "hpp": hpp_results,
            "dom_xss": dom_xss_results,
            "proto_client": proto_client_results,
            "log4shell": log4shell_results,
            "spring4shell": spring4shell_results,
            "proto_server": proto_server_results,
            "k8s": k8s_results,
            "firebase": firebase_results,
            "jenkins": jenkins_results,
            "elastic": elastic_results,
            "drupal": drupal_results,
            "tomcat": tomcat_results,
            "ultra_admin": ultra_admin_results,
            "citrix": citrix_results,
            "thinkphp": thinkphp_results,
            "rails": rails_results,
            "weblogic": weblogic_results,
            "sap": sap_results,
            "exchange": exchange_results,
            "vmware": vmware_results,
            "f5": f5_results,
            "jira": jira_results,
            "confluence": confluence_results,
            "pulse": pulse_results,
            "struts": struts_results,
            "coldfusion": coldfusion_results,
            "solr": solr_results,
            "nginx": nginx_results,
            "sonarqube": sonarqube_results,
            "grafana": grafana_results,
            "tech": tech_results,
            "redis": redis_results,
            "docker": docker_results,
            "memcached": memcached_results,
            "gitea": gitea_results,
            "minio": minio_results,
            "zabbix": zabbix_results,
            "jboss": jboss_results,
            "glassfish": glassfish_results,
            "hadoop": hadoop_results,
            "ssl": ssl_results,
            "fuzzer": fuzzer_results,
            "cors": cors_results,
            "email": email_results,
            "clickjacking": clickjacking_results,
            "advanced_resources": advanced_resource_results,
            "scan": scan_results,
            "wayback": wayback_results,
            "dns_zone": dns_zone_results,
            "vhosts": vhost_results,
            "session_tokens": session_token_results,
            "param_discovery": param_fuzz_results,
            "google_dorks": google_dork_results,
            "shodan": shodan_results,
            "virustotal": vt_results,
            "github_leaks": github_leak_results,
            "waf_bypass": waf_bypass_results,
            "rate_limit": rate_limit_results,
            "http2": http2_results,
            "brute_force": brute_force_results,
            "plugins": plugin_results,
            "js_analysis": js_results,
            "ct_logs": ct_results,
            "subdomain_takeover": takeover_results,
            "cloud_metadata_ssrf": cloud_meta_results,
            "websocket": ws_results,
            "graphql_deep": gql_deep_results,
            "nuclei": nuclei_results,
            "network_topology": network_map_results,
            "dark_web": dark_web_results,
            "protocol_fuzz": protocol_fuzz_results,
            "oauth": oauth_results,
            "dns_rebinding": dns_rebind_results,
            "cache_poisoning": cache_poison_results,
            "cicd": cicd_results,
            "emails": email_harvest_results,
            "whois_history": whois_results,
            "tech_fingerprint": tech_fp_results,
            "social_recon": social_results,
            "blind_xss": blind_xss_results,
            "api_discovery": api_disc_results,
            "sensitive_files": sensitive_results,
            "log4shell": log4j_results,
            "mass_assignment": mass_assign_results,
            "broken_access": broken_access_results,
            "threat_intel": threat_results,
            "http_desync": desync_results,
            "subdomain_brute": sub_brute_results,
            "redos": redos_results,
            "timing_attack": timing_results,
            "content_discovery": content_disc_results,
            "dependency_confusion": dep_confusion_results,
            "bola": bola_results,
            "deserialization": deser_results,
            "server_misconfig": misconfig_results,
            "zero_day": zeroday_results,
            "waf_encoder": encoder_results,
            "compliance": compliance_results,
            "race_condition": race_results,
            "wasm": wasm_results,
            "proto_pollution_deep": proto_deep_results,
            "ssrf_chain": ssrf_chain_results,
            "business_logic": biz_logic_results,
            "jwt_forge": jwt_forge_results,
            "attack_surface": surface_results,
            "graphql_deep": graphql_deep_results,
            "ai_predict": ai_predict_results,
            "dns_exfil": dns_exfil_results,
            "oauth2_chain": oauth2_results,
            "rate_bypass": rate_bypass_results,
            "memory_leak": mem_leak_results,
            "client_attack": client_atk_results,
            "supply_chain": supply_results,
            "http_smuggle": smuggle_results,
            "websocket_hijack": ws_hijack_results,
            "cloud_metadata": cloud_meta_results,
            "cache_deception": cache_dec_results,
            "api_reconstruct": api_recon_results,
            "blind_ssrf": blind_ssrf_results,
            "session_fixation": session_fix_results,
            "cors_chain": cors_chain_results,
            "header_injection": header_inj_results,
            "iot_scanner": iot_results,
            "zeroday": zeroday_results,
            "waf_bypass": waf_results,
            "subdomain_takeover": sd_takeover_results,
            "dep_confusion": dep_conf_results,
            "secrets": secrets_results,
            "hpp": hpp_results,
            "email_deep": email_results,
            "js_deobfuscate": js_deob_results,
            "webshell": webshell_results,
            "backdoor": backdoor_results,
            "malware": malware_results,
            "hidden_admin": hidden_admin_results,
            "phishing": phishing_results,
            "rootkit": rootkit_results,
            "defacement": deface_results,
            "c2_beacon": c2_results,
            "forensic": forensic_results,
        }
        console.rule("[bold magenta]CVE & Exploit Intelligence[/bold magenta]")
        all_findings = []
        vuln_data = full_report.get("vulnerabilities", {})
        for mod_name, mod_results in vuln_data.items():
            if isinstance(mod_results, list):
                enriched = enrich_findings_list(mod_results, mod_name)
                enriched = enrich_findings_with_exploits(enriched)
                all_findings.extend(enriched)
                vuln_data[mod_name] = enriched

        for mod_key in ["log4shell", "spring4shell", "jenkins", "elastic", "tomcat", "weblogic",
                         "exchange", "vmware", "f5", "jira", "confluence", "drupal", "citrix",
                         "struts", "coldfusion", "solr", "sap", "k8s", "docker", "firebase",
                         "jboss", "glassfish", "hadoop", "git", "swagger", "cors", "clickjacking",
                         "xxe", "jwt", "nosql", "cache", "host", "crlf", "idor"]:
            mod_data = full_report.get(mod_key, [])
            if isinstance(mod_data, list) and mod_data:
                enriched = enrich_findings_list(mod_data, mod_key)
                enriched = enrich_findings_with_exploits(enriched)
                all_findings.extend(enriched)
                full_report[mod_key] = enriched

        if all_findings:
            print_cve_summary(all_findings)
            for f in all_findings[:5]:
                sug = f.get('exploit_suggestions', [])
                if sug:
                    format_suggestions_console(sug)

        full_report['findings'] = all_findings
        full_report['scan_date'] = get_timestamp()

        console.rule("[bold magenta]OWASP Top 10 Compliance[/bold magenta]")
        owasp_results = assess_owasp_compliance(
            all_findings,
            ssl_data=full_report.get('ssl', {}),
            session_data=session_token_results,
        )
        full_report['owasp'] = owasp_results

        save_scan_report(full_report, config.output_file)

        if config.output_format in ['pdf', 'all']:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(config.url).netloc.replace(':', '_')
            pdf_path = f"report_{domain}_{get_timestamp().replace(' ','_').replace(':','-')}.pdf"
            full_report['duration'] = format_duration(_time.time() - scan_start_time)
            generate_pdf_report(full_report, pdf_path)

        if config.output_format in ['html', 'all'] or True: 
            html_path = generate_html_report(full_report, owasp_data=owasp_results)

        if all_findings:
            console.rule("[bold magenta]Auto Exploit Generator[/bold magenta]")
            exploits = generate_all_exploits(all_findings)
            full_report['exploits_generated'] = len(exploits)

        if all_findings:
            console.rule("[bold magenta]Auto CVE Exploit Search[/bold magenta]")
            cve_exploit_results = await scan_cve_exploits(session, all_findings)
            full_report['cve_exploits'] = cve_exploit_results

        if all_findings:
            console.rule("[bold magenta]AI Vulnerability Classifier[/bold magenta]")
            classification = classify_all_findings(all_findings)
            full_report['classification'] = classification.get('summary', {})

        console.rule("[bold magenta]Live Dashboard[/bold magenta]")
        dashboard_path = await generate_dashboard(session, config.url, full_report=full_report)
        full_report['dashboard'] = dashboard_path

        console.rule("[bold magenta]Security Scorecard[/bold magenta]")
        scorecard = generate_scorecard(full_report)
        full_report['scorecard'] = scorecard

        clear_checkpoint(config.url)

        if config.telegram_token or config.discord_webhook:
            elapsed_notify = _time.time() - scan_start_time
            await send_scan_summary(
                config,
                config.url,
                sum(_vuln_counts.values()),
                _vuln_counts,
                format_duration(elapsed_notify)
            )

        elapsed = _time.time() - scan_start_time
        total_vulns = sum(_vuln_counts.values())
        summary_lines = [
            f"[bold green]Target:[/bold green]   {config.url}",
            f"[bold green]Duration:[/bold green] {format_duration(elapsed)}",
            f"[bold green]Modules:[/bold green]  {_total_modules} run",
        ]
        vuln_lines = []
        if _vuln_counts['Critical']: vuln_lines.append(f"[bold red]Critical: {_vuln_counts['Critical']}[/bold red]")
        if _vuln_counts['High']:     vuln_lines.append(f"[bold orange3]High: {_vuln_counts['High']}[/bold orange3]")
        if _vuln_counts['Medium']:   vuln_lines.append(f"[bold yellow]Medium: {_vuln_counts['Medium']}[/bold yellow]")
        if _vuln_counts['Low']:      vuln_lines.append(f"[bold green]Low: {_vuln_counts['Low']}[/bold green]")
        if _vuln_counts['Info']:     vuln_lines.append(f"[bold blue]Info: {_vuln_counts['Info']}[/bold blue]")
        if vuln_lines:
            summary_lines.append(f"[bold green]Findings:[/bold green] " + "  ".join(vuln_lines))
        else:
            summary_lines.append("[bold green]Findings:[/bold green] [green]No critical issues detected ✓[/green]")

        console.print(Panel(
            "\n".join(summary_lines),
            title="[bold green]✅ Scan Complete[/bold green]",
            border_style="green",
            padding=(1, 2)
        ))

if __name__ == "__main__":
    _verbose_flag = "--verbose" in sys.argv or "-v" in sys.argv
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user. Partial results may have been saved.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red][!] Critical Error: {e}[/bold red]")
        if _verbose_flag:
            import traceback
            traceback.print_exc()