import json
import os
from rich.panel import Panel
from modules.core import console, get_timestamp
try:
    from modules.html_report import generate_html_report
    _HTML_REPORT_AVAILABLE = True
except Exception:
    _HTML_REPORT_AVAILABLE = False

def save_scan_report(data, output_file=None):
    """Save scan results to file"""
    if not output_file:
        domain = data['target'].split("://")[-1].split("/")[0].replace(":", "_")
        timestamp = get_timestamp().replace(" ", "_").replace(":", "-")
        output_file = f"report_{domain}_{timestamp}.json"
    
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        if _HTML_REPORT_AVAILABLE:
            try:
                html_path = generate_html_report(data, output_file)
                console.print(f"[bold green][+] HTML Report:[/bold green] [blue]{os.path.abspath(html_path)}[/blue]")
            except Exception as html_err:
                console.print(f"[yellow][!] HTML report generation skipped: {html_err}[/yellow]")

        console.print(Panel(
            f"[bold green]JSON:[/bold green] [blue]{os.path.abspath(output_file)}[/blue]\n"
            f"[bold green]TXT: [/bold green] [blue]{os.path.abspath(output_file.replace('.json', '.txt'))}[/blue]",
            title="[bold green]Reports Saved[/bold green]", border_style="green"
        ))
        txt_file = output_file.replace(".json", ".txt")
        with open(txt_file, 'w') as f:
            f.write(f"SNAKEBITE SCAN REPORT\n")
            f.write(f"Target: {data['target']}\n")
            f.write(f"Time: {data['timestamp']}\n")
            f.write("="*50 + "\n\n")
            f.write("RELULTS SUMMARY:\n")
            f.write(f"- Open Ports: {len(data.get('ports', []))}\n")
            f.write(f"- Subdomains: {len(data.get('subdomains', []))}\n")
            f.write(f"- Crawled Links: {len(data.get('crawl', {}).get('all_links', []))}\n")
            f.write(f"- Vulnerabilities (SQLi): {len(data.get('vulnerabilities', {}).get('sqli', []))}\n")
            f.write(f"- Vulnerabilities (XSS): {len(data.get('vulnerabilities', {}).get('xss', []))}\n")
            f.write(f"- Vulnerabilities (LFI): {len(data.get('vulnerabilities', {}).get('lfi', []))}\n")
            f.write(f"- Vulnerabilities (Redirect): {len(data.get('vulnerabilities', {}).get('redirect', []))}\n")
            f.write(f"- Takeover Risks: {len(data.get('vulnerabilities', {}).get('takeover', []))}\n")
            f.write(f"- JS Secrets Found: {len(data.get('secrets', []))}\n")
            f.write(f"- Sensitive Files Found: {len(data.get('fuzzer', []))}\n")
            f.write(f"- CORS Issues: {len(data.get('cors', []))}\n")
            f.write(f"- Clickjacking Status: {data.get('clickjacking', {}).get('status', 'N/A')}\n")
            f.write(f"- Email Security: {data.get('email', {}).get('spf_status', 'N/A')}\n")
            f.write(f"- Vulnerabilities (RCE): {len(data.get('vulnerabilities', {}).get('rce', []))}\n")
            f.write(f"- Vulnerabilities (SSTI): {len(data.get('vulnerabilities', {}).get('ssti', []))}\n")
            f.write(f"- JWT Issues: {len(data.get('jwt', []))}\n")
            f.write(f"- GraphQL Endpoints: {len(data.get('graphql', []))}\n")
            f.write(f"- Prototype Pollution: {len(data.get('prototype', []))}\n")
            f.write(f"- WAF Bypasses: {len(data.get('waf', []))}\n")
            f.write(f"- XXE Vulnerabilities: {len(data.get('xxe', []))}\n")
            f.write(f"- IDOR Flaws: {len(data.get('idor', []))}\n")
            f.write(f"- Cloud Buckets: {len(data.get('cloud', []))}\n")
            f.write(f"- Spring Boot Risks: {len(data.get('spring', []))}\n")
            f.write(f"- CRLF Injections: {len(data.get('crlf', []))}\n")
            f.write(f"- Shellshock: {len(data.get('shellshock', []))}\n")
            f.write(f"- Host Header Injection: {len(data.get('host', []))}\n")
            f.write(f"- 403 Bypasses: {len(data.get('bypass_403', []))}\n")
            f.write(f"- Java Deserialization: {len(data.get('java', []))}\n")
            f.write(f"- Broken Links (Hijack): {len(data.get('links', []))}\n")
            f.write(f"- HTTP Smuggling: {len(data.get('smuggling', []))}\n")
            f.write(f"- Web Cache Deception: {len(data.get('cache', []))}\n")
            f.write(f"- Git Exposure: {len(data.get('git', []))}\n")
            f.write(f"- API Swagger Docs: {len(data.get('swagger', []))}\n")
            f.write(f"- Race Conditions: {len(data.get('race', []))}\n")
            f.write(f"- WebSocket Hijacking: {len(data.get('websocket', []))}\n")
            f.write(f"- Reverse Tabnabbing: {len(data.get('tabnabbing', []))}\n")
            f.write(f"- Admin Panels: {len(data.get('admin', []))}\n")
            f.write(f"- S3 Buckets (Brute): {len(data.get('s3', []))}\n")
            f.write(f"- WebDAV Methods: {len(data.get('webdav', []))}\n")
            f.write(f"- IIS Shortnames: {len(data.get('iis', []))}\n")
            f.write(f"- SSI Injection: {len(data.get('ssi', []))}\n")
            f.write(f"- XSLT Injection: {len(data.get('xslt', []))}\n")
            f.write(f"- Ghost RCE (Time): {len(data.get('blind_rce', []))}\n")
            f.write(f"- Silent SQLi: {len(data.get('blind_sqli', []))}\n")
            f.write(f"- H2C Smuggling: {len(data.get('h2c', []))}\n")
            f.write(f"- PHP Object Inj: {len(data.get('php_obj', []))}\n")
            f.write(f"- LDAP Injection: {len(data.get('ldap', []))}\n")
            f.write(f"- XPath Injection: {len(data.get('xpath', []))}\n")
            f.write(f"- Pickle Injection: {len(data.get('pickle', []))}\n")
            f.write(f"- SSRF Port Scan: {len(data.get('ssrf_port', []))}\n")
            f.write(f"- CSV Injection: {len(data.get('csv', []))}\n")
            f.write(f"- RPO Scanner: {len(data.get('rpo', []))}\n")
            f.write(f"- ESI Injection: {len(data.get('esi', []))}\n")
            f.write(f"- Dangling Markup: {len(data.get('dangling', []))}\n")
            f.write(f"- HPP Scanner: {len(data.get('hpp', []))}\n")
            f.write(f"- DOM XSS Scan: {len(data.get('dom_xss', []))}\n")
            f.write(f"- Proto Pollution: {len(data.get('proto_client', []))}\n")
            f.write(f"- Log4Shell: {len(data.get('log4shell', []))}\n")
            f.write(f"- Spring4Shell: {len(data.get('spring4shell', []))}\n")
            f.write(f"- Server Proto: {len(data.get('proto_server', []))}\n")
            f.write(f"- Kubernetes: {len(data.get('k8s', []))}\n")
            f.write(f"- Firebase DB: {len(data.get('firebase', []))}\n")
            f.write(f"- Jenkins CI: {len(data.get('jenkins', []))}\n")
            f.write(f"- Elasticsearch: {len(data.get('elastic', []))}\n")
            f.write(f"- Drupal RCE: {len(data.get('drupal', []))}\n")
            f.write(f"- Tomcat Mgr: {len(data.get('tomcat', []))}\n")
            f.write(f"- Ultra Admin: {len(data.get('ultra_admin', []))}\n")
            f.write(f"- Citrix RCE: {len(data.get('citrix', []))}\n")
            f.write(f"- ThinkPHP RCE: {len(data.get('thinkphp', []))}\n")
            f.write(f"- Rails Discl: {len(data.get('rails', []))}\n")
            f.write(f"- WebLogic RCE: {len(data.get('weblogic', []))}\n")
            f.write(f"- SAP Recon: {len(data.get('sap', []))}\n")
            f.write(f"- Exchange: {len(data.get('exchange', []))}\n")
            f.write(f"- VMware RCE: {len(data.get('vmware', []))}\n")
            f.write(f"- F5 RCE: {len(data.get('f5', []))}\n")
            f.write(f"- Jira RCE: {len(data.get('jira', []))}\n")
            f.write(f"- Confluence RCE: {len(data.get('confluence', []))}\n")
            f.write(f"- Pulse VPN: {len(data.get('pulse', []))}\n")
            f.write(f"- Struts RCE: {len(data.get('struts', []))}\n")
            f.write(f"- ColdFusion LFI: {len(data.get('coldfusion', []))}\n")
            f.write(f"- Solr RCE: {len(data.get('solr', []))}\n")
            f.write(f"- Nginx Alias: {len(data.get('nginx', []))}\n")
            f.write(f"- SonarQube: {len(data.get('sonarqube', []))}\n")
            f.write(f"- Grafana LFI: {len(data.get('grafana', []))}\n")
            f.write(f"- Redis RCE: {len(data.get('redis', []))}\n")
            f.write(f"- Docker API: {len(data.get('docker', []))}\n")
            f.write(f"- Memcached: {len(data.get('memcached', []))}\n")
            f.write(f"- Gitea RCE: {len(data.get('gitea', []))}\n")
            f.write(f"- MinIO Leak: {len(data.get('minio', []))}\n")
            f.write(f"- Zabbix Bypass: {len(data.get('zabbix', []))}\n")
            f.write(f"- JBoss RCE: {len(data.get('jboss', []))}\n")
            f.write(f"- GlassFish LFI: {len(data.get('glassfish', []))}\n")
            f.write(f"- Hadoop RCE: {len(data.get('hadoop', []))}\n")
            f.write("\nCMS ANALYSIS:\n")
            cms_list = data.get('cms', [])
            f.write(f"- Detected Systems: {', '.join(cms_list) if cms_list else 'None Detected'}\n")
            cms_details = data.get('cms_details', {})
            
            if 'version' in cms_details:
                f.write(f"- Version: {cms_details['version']}\n")
            if 'users' in cms_details and cms_details['users']:
                f.write(f"- Users Found: {', '.join(cms_details['users'])}\n")
            if 'xmlrpc' in cms_details:
                 f.write(f"- XML-RPC Enabled: {cms_details['xmlrpc']}\n")
            
            if 'files' in cms_details and cms_details['files']:
                f.write(f"- Interesting Files: {', '.join(cms_details['files'])}\n")

            if 'speed' in data and data['speed'] and 'total' in data['speed']:
                perf = data['speed']
                f.write("\nPERFORMANCE METRICS:\n")
                f.write(f"- Total Time: {perf.get('total')}\n")
                f.write(f"- TTFB: {perf.get('ttfb')}\n")
                f.write(f"- Rating: {perf.get('rating')}\n")

        all_links = data.get('crawl', {}).get('all_links', [])
        if all_links:
            link_file = output_file.replace(".json", "_links.txt")
            with open(link_file, 'w') as f:
                for link in sorted(all_links):
                    f.write(f"{link}\n")
            console.print(f"[cyan]  -> Links saved to {os.path.basename(link_file)}[/cyan]")

        vulns = data.get('vulnerabilities', {})
        sqli = vulns.get('sqli', [])
        xss = vulns.get('xss', [])
        bug_file = output_file.replace(".json", "_bugs.txt")
        has_any_vuln = False
        with open(bug_file, 'w') as f:
            f.write("CRITICAL VULNERABILITIES FOUND\n")
            f.write("==============================\n\n")
            
            if sqli:
                has_any_vuln = True
                f.write(f"[ SQL INJECTION ]\n")
                for v in sqli:
                    f.write(f"URL: {v['url']}\nParam: {v.get('param', v.get('parameter',''))}\nDB: {v.get('db', v.get('database',''))}\n\n")
            
            if xss:
                has_any_vuln = True
                f.write(f"\n[ REFLECTED XSS ]\n")
                for v in xss:
                    f.write(f"URL: {v['url']}\nParam: {v.get('param', v.get('parameter',''))}\nPayload: {v['payload']}\n\n")

            lfi = vulns.get('lfi', [])
            if lfi:
                has_any_vuln = True
                f.write(f"\n[ LOCAL FILE INCLUSION ]\n")
                for v in lfi:
                    f.write(f"URL: {v['url']}\nPayload: {v['payload']}\nIndicator: {v['indicator']}\n\n")

            redirect = vulns.get('redirect', [])
            if redirect:
                has_any_vuln = True
                f.write(f"\n[ OPEN REDIRECT ]\n")
                for v in redirect:
                    f.write(f"URL: {v['url']}\nRedirect To: {v['redirect_to']}\n\n")

            takeover = vulns.get('takeover', [])
            if takeover:
                has_any_vuln = True
                f.write(f"\n[ SUBDOMAIN TAKEOVER ]\n")
                for v in takeover:
                    f.write(f"URL: {v['url']}\nService: {v['service']}\nStatus: {v['status']}\n\n")
            
            secrets = data.get('secrets', [])
            if secrets:
                has_any_vuln = True
                f.write("\nJS SECRETS DISCOVERED\n")
                f.write("=====================\n")
                for s in secrets:
                    f.write(f"Type: {s['type']}\nURL: {s['url']}\nMatch: {s['match']}\n\n")

            ssl_data = data.get('ssl', {})
            if ssl_data and 'error' not in ssl_data:
                 f.write("\nSSL/TLS CONFIGURATION\n")
                 f.write("=====================\n")
                 f.write(f"Protocol: {ssl_data.get('protocol')}\n")
                 f.write(f"Cipher: {ssl_data.get('cipher')}\n")
                 f.write(f"Issuer: {ssl_data.get('issuer_cn')} ({ssl_data.get('issuer_org')})\n")
                 f.write(f"Expires: {ssl_data.get('expiry')} ({ssl_data.get('days_remaining')} days left)\n")

            sensitive = data.get('fuzzer', [])
            if sensitive:
                 f.write("\nSENSITIVE FILES EXPOSED\n")
                 f.write("=======================\n")
                 for s in sensitive:
                      f.write(f"File: {s['file']}\nURL: {s['url']}\n\n")

            cors = data.get('cors', [])
            if cors:
                 f.write("\nCORS MISCONFIGURATIONS\n")
                 f.write("======================\n")
                 for c in cors:
                      f.write(f"Type: {c['type']}\nOrigin: {c['origin']}\nSeverity: {c['severity']}\n\n")

            email = data.get('email', {})
            if email:
                 f.write("\nEMAIL SECURITY (DNS)\n")
                 f.write("====================\n")
                 f.write(f"SPF Status: {email.get('spf_status')}\nRecord: {email.get('spf_record')}\n\n")
                 f.write(f"DMARC Status: {email.get('dmarc_status')}\nRecord: {email.get('dmarc_record')}\n\n")

            clickjacking = data.get('clickjacking', {})
            if clickjacking:
                 f.write("\nCLICKJACKING PROTECTION\n")
                 f.write("=======================\n")
                 f.write(f"Status: {clickjacking.get('status')}\n")
                 f.write(f"X-Frame-Options: {clickjacking.get('xfo')}\n")
                 f.write(f"CSP: {clickjacking.get('csp')}\n\n")

            rce = vulns.get('rce', [])
            if rce:
                f.write(f"\n[ CRITICAL: REMOTE CODE EXECUTION ]\n")
                f.write("===================================\n")
                for v in rce:
                    f.write(f"URL: {v['url']}\nPayload: {v['payload']}\nIndicator: {v['indicator']}\n\n")

            ssti = vulns.get('ssti', [])
            if ssti:
                f.write(f"\n[ CRITICAL: SSTI ]\n")
                f.write("==================\n")
                for v in ssti:
                    f.write(f"URL: {v['url']}\nPayload: {v['payload']}\nIndicator: {v['indicator']}\n\n")
                    
            jwts = data.get('jwt', [])
            if jwts:
                 f.write("\nJWT SECURITY ANALYSIS\n")
                 f.write("=====================\n")
                 for j in jwts:
                      f.write(f"Token: {j['token']}\nURL: {j['url']}\nAlgorithm: {j['alg']}\n")
                      if j['vulns']:
                           f.write("Vulnerabilities:\n")
                           for err in j['vulns']:
                                f.write(f"- {err}\n")
                      f.write("\n")

            graphql = data.get('graphql', [])
            if graphql:
                 f.write("\nGRAPHQL INTROSPECTION\n")
                 f.write("=====================\n")
                 for g in graphql:
                      f.write(f"Endpoint: {g['url']}\nMethod: {g['method']}\nType: {g['type']}\n\n")

            prototype = data.get('prototype', [])
            if prototype:
                 f.write("\nPROTOTYPE POLLUTION (NODEJS)\n")
                 f.write("============================\n")
                 for p in prototype:
                      f.write(f"URL: {p['url']}\nPayload: {p['payload']}\nIndicator: {p['indicator']}\n\n")

            waf = data.get('waf', [])
            if waf:
                 f.write("\nWAF BYPASS SUCCESS\n")
                 f.write("==================\n")
                 for w in waf:
                      f.write(f"Header: {w['header']}: {w['value']}\nStatus: {w['status']}\n\n")

            xxe = data.get('xxe', [])
            if xxe:
                 f.write("\n[ CRITICAL: XXE INJECTION ]\n")
                 f.write("===========================\n")
                 for x in xxe:
                      f.write(f"URL: {x['url']}\nType: {x['type']}\nIndicator: {x['indicator']}\n\n")

            idor = data.get('idor', [])
            if idor:
                 f.write("\n[ POTENTIAL IDOR ]\n")
                 f.write("==================\n")
                 for i in idor:
                      f.write(f"URL: {i['url']}\nParam: {i['param']}\nLogic: {i['original']} -> {i['fuzzed']}\n\n")

            cloud = data.get('cloud', [])
            if cloud:
                 f.write("\nCLOUD STORAGE LEAKS\n")
                 f.write("===================\n")
                 for c in cloud:
                      f.write(f"Provider: {c['provider']}\nBucket: {c['bucket']}\nSource: {c['source_url']}\n\n")

            spring = data.get('spring', [])
            if spring:
                 f.write("\nSPRING BOOT ACTUATORS\n")
                 f.write("=====================\n")
                 for s in spring:
                      f.write(f"URL: {s['url']}\nEndpoint: {s['endpoint']}\nStatus: {s['status']}\n\n")

            crlf = data.get('crlf', [])
            if crlf:
                 f.write("\nCRLF INJECTION / SPLITTING\n")
                 f.write("==========================\n")
                 for cl in crlf:
                      f.write(f"URL: {cl['url']}\nPayload: {cl['payload']}\nType: {cl['type']}\n\n")

            shellshock = data.get('shellshock', [])
            if shellshock:
                 f.write("\n[ CRITICAL: SHELLSHOCK RCE ]\n")
                 f.write("============================\n")
                 for sh in shellshock:
                      f.write(f"URL: {sh['url']}\nPayload: {sh['payload']}\nStatus: {sh['status']}\n\n")

            host = data.get('host', [])
            if host:
                 f.write("\nHOST HEADER INJECTION\n")
                 f.write("=====================\n")
                 for h in host:
                      f.write(f"URL: {h['url']}\nType: {h['type']}\nEvidence: {h['evidence']}\n\n")

            bypass = data.get('bypass_403', [])
            if bypass:
                 f.write("\n403 ACCESS BYPASS\n")
                 f.write("=================\n")
                 for b in bypass:
                      f.write(f"Target: {b['original']}\nPayload: {b['bypass_method']}\nSuccess URL: {b['url']}\n\n")

            java = data.get('java', [])
            if java:
                 f.write("\n[ CRITICAL: JAVA DESERIALIZATION ]\n")
                 f.write("==================================\n")
                 for j in java:
                      f.write(f"URL: {j['url']}\nLocation: {j['location']}\nData: {j['evidence']}\n\n")

            links = data.get('links', [])
            if links:
                 f.write("\nBROKEN LINK HIJACKING\n")
                 f.write("=====================\n")
                 for l in links:
                      f.write(f"Broken URL: {l['url']}\nType: 404 Not Found (Potential Hijack)\n\n")

            smuggling = data.get('smuggling', [])
            if smuggling:
                 f.write("\n[ CRITICAL: HTTP REQUEST SMUGGLING ]\n")
                 f.write("====================================\n")
                 for sm in smuggling:
                      f.write(f"Type: {sm['type']}\nDetails: {sm['details']}\n\n")

            cache = data.get('cache', [])
            if cache:
                 f.write("\nWEB CACHE DECEPTION\n")
                 f.write("===================\n")
                 for ca in cache:
                      f.write(f"Target: {ca['url']}\nPayload: {ca['payload']}\nHeader: {ca['cache_header']}\n\n")

            git = data.get('git', [])
            if git:
                 f.write("\n[ CRITICAL: SOURCE CODE EXPOSURE ]\n")
                 f.write("==================================\n")
                 for g in git:
                      f.write(f"URL: {g['url']}\nType: {g['type']}\nEvidence: {g['evidence']}\n\n")

            swagger = data.get('swagger', [])
            if swagger:
                 f.write("\nAPI SWAGGER DOCUMENTATION\n")
                 f.write("=========================\n")
                 for sw in swagger:
                      f.write(f"Found: {sw['url']}\nPath: {sw['path']}\n\n")

            race = data.get('race', [])
            if race:
                 f.write("\nRACE CONDITION ANOMALIES\n")
                 f.write("========================\n")
                 for r in race:
                      f.write(f"URL: {r['url']}\nSuccess Count: {r['success_count']}/{r['total']}\nCodes: {r['codes']}\n\n")

            websocket = data.get('websocket', [])
            if websocket:
                 f.write("\nCROSS-SITE WEBSOCKET HIJACKING (CSWSH)\n")
                 f.write("======================================\n")
                 for ws in websocket:
                      f.write(f"Endpoint: {ws['url']}\nEvidence: {ws['evidence']}\n\n")

            tabnabbing = data.get('tabnabbing', [])
            if tabnabbing:
                 f.write("\nREVERSE TABNABBING (PHISHING)\n")
                 f.write("=============================\n")
                 for t in tabnabbing:
                      f.write(f"Source: {t['url']}\nUnsafe Link: {t['link']}\n\n")

            admin = data.get('admin', [])
            if admin:
                 f.write("\nADMIN PANEL HUNTER\n")
                 f.write("==================\n")
                 for a in admin:
                      f.write(f"URL: {a['url']}\nType: {a['type']}\nStatus: {a['status']}\n\n")

            s3 = data.get('s3', [])
            if s3:
                 f.write("\nACTIVE S3 BUCKET BRUTEFORCE\n")
                 f.write("===========================\n")
                 for b in s3:
                      f.write(f"Bucket: {b['bucket']}\nURL: {b['url']}\nStatus: {b['status']}\n\n")

            webdav = data.get('webdav', [])
            if webdav:
                 f.write("\nWEBDAV DANGEROUS METHODS\n")
                 f.write("========================\n")
                 for w in webdav:
                      f.write(f"URL: {w['url']}\nMethods: {w['methods']}\n\n")

            iis = data.get('iis', [])
            if iis:
                 f.write("\nIIS SHORTNAME ENUMERATION\n")
                 f.write("=========================\n")
                 for i in iis:
                      f.write(f"URL: {i['url']}\nPrefix: {i['prefix']}~1\n\n")

            ssi = data.get('ssi', [])
            if ssi:
                 f.write("\nSSI INJECTION (RCE)\n")
                 f.write("===================\n")
                 for s in ssi:
                      f.write(f"URL: {s['url']}\nParam: {s['param']}\nType: {s['type']}\n\n")

            xslt = data.get('xslt', [])
            if xslt:
                 f.write("\nXSLT INJECTION\n")
                 f.write("==============\n")
                 for x in xslt:
                      f.write(f"URL: {x['url']}\nType: {x['type']}\nEvidence: {x.get('evidence')}\n\n")

            blind_rce = data.get('blind_rce', [])
            if blind_rce:
                 f.write("\nGHOST RCE (TIME-BASED)\n")
                 f.write("======================\n")
                 for b in blind_rce:
                      f.write(f"URL: {b['url']}\nParam: {b['param']}\nPayload: {b['payload']}\nDuration: {b['duration']}\n\n")

            blind_sqli = data.get('blind_sqli', [])
            if blind_sqli:
                 f.write("\nSILENT SQLi (BLIND)\n")
                 f.write("===================\n")
                 for s in blind_sqli:
                      f.write(f"URL: {s['url']}\nParam: {s['param']}\nPayload: {s['payload']}\nDuration: {s['duration']}\n\n")

            h2c = data.get('h2c', [])
            if h2c:
                 f.write("\nH2C SMUGGLING (PROTOCOL BYPASS)\n")
                 f.write("===============================\n")
                 for h in h2c:
                      f.write(f"URL: {h['url']}\nDetails: {h['details']}\n\n")

            php_obj = data.get('php_obj', [])
            if php_obj:
                 f.write("\nPHP OBJECT INJECTION (RCE)\n")
                 f.write("==========================\n")
                 for p in php_obj:
                      f.write(f"URL: {p['url']}\nParam: {p['param']}\nEvidence: {p.get('evidence')}\n\n")

            ldap = data.get('ldap', [])
            if ldap:
                 f.write("\nLDAP INJECTION (AUTH BYPASS)\n")
                 f.write("============================\n")
                 for l in ldap:
                      f.write(f"URL: {l['url']}\nParam: {l['param']}\nType: {l['type']}\n\n")

            xpath = data.get('xpath', [])
            if xpath:
                 f.write("\nXPATH INJECTION (XML DB THEFT)\n")
                 f.write("==============================\n")
                 for x in xpath:
                      f.write(f"URL: {x['url']}\nParam: {x['param']}\nType: {x['type']}\n\n")

            pickle = data.get('pickle', [])
            if pickle:
                 f.write("\nPICKLE INJECTION (PYTHON RCE)\n")
                 f.write("=============================\n")
                 for pk in pickle:
                      f.write(f"URL: {pk['url']}\nParam: {pk['param']}\nEvidence: {pk.get('evidence')}\n\n")

            ssrf_port = data.get('ssrf_port', [])
            if ssrf_port:
                 f.write("\nSSRF PORT SCAN (INTERNAL RECON)\n")
                 f.write("===============================\n")
                 for sp in ssrf_port:
                      f.write(f"Port: {sp['port']}\nStatus: {sp['status']}\nParam: {sp['param']}\n\n")

            csv = data.get('csv', [])
            if csv:
                 f.write("\nCSV INJECTION (FORMULA RCE)\n")
                 f.write("===========================\n")
                 for c in csv:
                      f.write(f"URL: {c['url']}\nParam: {c['param']}\nPayload: {c['payload']}\n\n")

            rpo = data.get('rpo', [])
            if rpo:
                 f.write("\nRPO SCANNER (CSS HIJACK)\n")
                 f.write("========================\n")
                 for r in rpo:
                      f.write(f"URL: {r['url']}\nEvidence: {r.get('evidence')}\n\n")

            esi = data.get('esi', [])
            if esi:
                 f.write("\nESI INJECTION (CDN RCE)\n")
                 f.write("=======================\n")
                 for e in esi:
                      f.write(f"URL: {e['url']}\nParam: {e['param']}\nType: {e['type']}\n\n")

            dangling = data.get('dangling', [])
            if dangling:
                 f.write("\nDANGLING MARKUP (CSP BYPASS)\n")
                 f.write("============================\n")
                 for d in dangling:
                      f.write(f"URL: {d['url']}\nParam: {d['param']}\nEvidence: {d.get('evidence')}\n\n")

            csp = data.get('csp_bypass', [])
            if csp:
                 f.write("\nCSP WEAKNESSES (SECURITY POLICY)\n")
                 f.write("================================\n")
                 for c in csp:
                      f.write(f"URL: {c['url']}\nIssues: {c.get('evidence')}\n\n")

            hpp = data.get('hpp', [])
            if hpp:
                 f.write("\nHTTP PARAMETER POLLUTION (HPP)\n")
                 f.write("==============================\n")
                 for h in hpp:
                      f.write(f"URL: {h['url']}\nParam: {h['param']}\nBehavior: {h['behavior']}\n\n")

            dom_xss = data.get('dom_xss', [])
            if dom_xss:
                 f.write("\nDOM XSS (CLIENT SIDE SINKS)\n")
                 f.write("===========================\n")
                 for d in dom_xss:
                      f.write(f"URL: {d['url']}\nPairs: {d.get('evidence')}\n\n")

            proto_client = data.get('proto_client', [])
            if proto_client:
                 f.write("\nCLIENT PROTOTYPE POLLUTION\n")
                 f.write("==========================\n")
                 for p in proto_client:
                      f.write(f"URL: {p['url']}\nEvidence: {p.get('evidence')}\n\n")

            l4s = data.get('log4shell', [])
            if l4s:
                 f.write("\nLOG4SHELL (CVE-2021-44228)\n")
                 f.write("==========================\n")
                 for l in l4s:
                      f.write(f"URL: {l['url']}\nStatus: {l['type']}\n\n")

            s4s = data.get('spring4shell', [])
            if s4s:
                 f.write("\nSPRING4SHELL (CVE-2022-22965)\n")
                 f.write("=============================\n")
                 for s in s4s:
                      f.write(f"URL: {s['url']}\nEvidence: {s.get('evidence')}\n\n")

            proto_server = data.get('proto_server', [])
            if proto_server:
                 f.write("\nSERVER-SIDE PROTO POLLUTION\n")
                 f.write("===========================\n")
                 for ps in proto_server:
                      f.write(f"URL: {ps['url']}\nEvidence: {ps.get('evidence')}\n\n")

            k8s = data.get('k8s', [])
            if k8s:
                 f.write("\nKUBERNETES EXPOSURE (CLUSTER)\n")
                 f.write("=============================\n")
                 for k in k8s:
                      f.write(f"URL: {k['url']}\nType: {k['type']}\nEvidence: {k.get('evidence')}\n\n")

            fb = data.get('firebase', [])
            if fb:
                 f.write("\nFIREBASE DATABASE (OPEN JSON)\n")
                 f.write("=============================\n")
                 for fbd in fb:
                      f.write(f"URL: {fbd['url']}\nEvidence: {fbd.get('evidence')}\n\n")

            jenkins = data.get('jenkins', [])
            if jenkins:
                 f.write("\nJENKINS CI/CD EXPOSURE\n")
                 f.write("======================\n")
                 for j in jenkins:
                      f.write(f"URL: {j['url']}\nStatus: {j.get('evidence')}\n\n")

            elastic = data.get('elastic', [])
            if elastic:
                 f.write("\nELASTICSEARCH EXPOSURE\n")
                 f.write("======================\n")
                 for el in elastic:
                      f.write(f"URL: {el['url']}\nStatus: {el['type']}\n\n")

            drupal = data.get('drupal', [])
            if drupal:
                 f.write("\nDRUPAL RCE (DRUPALGEDDON2)\n")
                 f.write("==========================\n")
                 for dr in drupal:
                      f.write(f"URL: {dr['url']}\nEvidence: {dr.get('evidence')}\n\n")

            tomcat = data.get('tomcat', [])
            if tomcat:
                 f.write("\nTOMCAT MANAGER RCE\n")
                 f.write("==================\n")
                 for t in tomcat:
                      f.write(f"URL: {t['url']}\nEvidence: {t.get('evidence')}\n\n")

            u_admin = data.get('ultra_admin', [])
            if u_admin:
                 f.write("\nULTRA ADMIN HUNTER\n")
                 f.write("==================\n")
                 for ua in u_admin:
                      f.write(f"URL: {ua['url']}\nStatus: {ua['type']}\n\n")

            citrix = data.get('citrix', [])
            if citrix:
                 f.write("\nCITRIX GATEWAY RCE (CVE-2019-19781)\n")
                 f.write("===================================\n")
                 for c in citrix:
                      f.write(f"URL: {c['url']}\nStatus: {c['evidence']}\n\n")

            tp = data.get('thinkphp', [])
            if tp:
                 f.write("\nTHINKPHP FRAMEWORK RCE\n")
                 f.write("======================\n")
                 for x in tp:
                      f.write(f"URL: {x['url']}\nEvidence: {x.get('evidence')}\n\n")

            rails = data.get('rails', [])
            if rails:
                 f.write("\nRUBY ON RAILS VULNERABILITY\n")
                 f.write("===========================\n")
                 for r in rails:
                      f.write(f"URL: {r['url']}\nEvidence: {r.get('evidence')}\n\n")

            weblogic = data.get('weblogic', [])
            if weblogic:
                 f.write("\nORACLE WEBLOGIC EXPOSURE\n")
                 f.write("========================\n")
                 for w in weblogic:
                      f.write(f"URL: {w['url']}\nStatus: {w.get('type')}\n\n")

            sap = data.get('sap', [])
            if sap:
                 f.write("\nSAP NETWEAVER EXPOSURE\n")
                 f.write("======================\n")
                 for sp in sap:
                      f.write(f"URL: {sp['url']}\nStatus: {sp.get('type')}\n\n")

            exch = data.get('exchange', [])
            if exch:
                 f.write("\nMICROSOFT EXCHANGE EXPOSURE\n")
                 f.write("===========================\n")
                 for ex in exch:
                      f.write(f"URL: {ex['url']}\nStatus: {ex.get('type')}\n\n")

            vm = data.get('vmware', [])
            if vm:
                 f.write("\nVMWARE VCENTER VULNERABILITY\n")
                 f.write("============================\n")
                 for v in vm:
                      f.write(f"URL: {v['url']}\nStatus: {v.get('type')}\n\n")

            f5 = data.get('f5', [])
            if f5:
                 f.write("\nF5 BIG-IP VULNERABILITY\n")
                 f.write("=======================\n")
                 for f in f5:
                      f.write(f"URL: {f['url']}\nStatus: {f.get('type')}\n\n")

            jira = data.get('jira', [])
            if jira:
                 f.write("\nATLASSIAN JIRA VULNERABILITY\n")
                 f.write("============================\n")
                 for j in jira:
                      f.write(f"URL: {j['url']}\nStatus: {j.get('evidence')}\n\n")

            conf = data.get('confluence', [])
            if conf:
                 f.write("\nATLASSIAN CONFLUENCE VULNERABILITY\n")
                 f.write("==================================\n")
                 for c in conf:
                      f.write(f"URL: {c['url']}\nStatus: {c.get('evidence')}\n\n")

            pl = data.get('pulse', [])
            if pl:
                 f.write("\nPULSE SECURE VPN LEAK\n")
                 f.write("=====================\n")
                 for p in pl:
                      f.write(f"URL: {p['url']}\nStatus: {p.get('type')}\n\n")

            st = data.get('struts', [])
            if st:
                 f.write("\nAPACHE STRUTS RCE\n")
                 f.write("=================\n")
                 for s in st:
                      f.write(f"URL: {s['url']}\nStatus: {s.get('evidence')}\n\n")

            cf = data.get('coldfusion', [])
            if cf:
                 f.write("\nADOBE COLDFUSION VULNERABILITY\n")
                 f.write("==============================\n")
                 for c in cf:
                      f.write(f"URL: {c['url']}\nStatus: {c.get('type')}\n\n")

            solr = data.get('solr', [])
            if solr:
                 f.write("\nAPACHE SOLR EXPOSURE\n")
                 f.write("====================\n")
                 for sl in solr:
                      f.write(f"URL: {sl['url']}\nStatus: {sl.get('type')}\n\n")

            ngx = data.get('nginx', [])
            if ngx:
                 f.write("\nNGINX MISCONFIGURATION\n")
                 f.write("======================\n")
                 for n in ngx:
                      f.write(f"URL: {n['url']}\nStatus: {n.get('type')}\n\n")

            sonar = data.get('sonarqube', [])
            if sonar:
                 f.write("\nSONARQUBE SOURCE CODE LEAK\n")
                 f.write("==========================\n")
                 for sn in sonar:
                      f.write(f"URL: {sn['url']}\nStatus: {sn.get('evidence')}\n\n")

            graf = data.get('grafana', [])
            if graf:
                 f.write("\nGRAFANA LFI VULNERABILITY\n")
                 f.write("=========================\n")
                 for g in graf:
                      f.write(f"URL: {g['url']}\nStatus: {g.get('type')}\n\n")

            tec = data.get('tech', {})
            if tec and (tec.get("technologies") or tec.get("theme", {}).get("name") != "Unknown"):
                 f.write("\nTECHNOLOGY STACK REPORT\n")
                 f.write("=======================\n")
                 
                 if tec.get("technologies"):
                     f.write("Detected Technologies:\n")
                     by_cat = {}
                     for t in tec["technologies"]:
                         for c in t["categories"]:
                             if c not in by_cat: by_cat[c] = []
                             by_cat[c].append(t["name"])
                     for cat, names in by_cat.items():
                         f.write(f"- {cat}: {', '.join(names)}\n")
                     f.write("\n")
                 
                 th = tec.get("theme", {})
                 if th.get("name") != "Unknown":
                     f.write("Theme Details:\n")
                     f.write(f"- Name: {th.get('name')}\n")
                     f.write(f"- Version: {th.get('version')}\n")
                     f.write(f"- Source: {th.get('source')}\n")

            rds = data.get('redis', [])
            if rds:
                 f.write("\nREDIS UNAUTHENTICATED ACCESS\n")
                 f.write("============================\n")
                 for r in rds:
                      f.write(f"HOST: {r['url']}\nStatus: {r.get('evidence')}\n\n")

            dck = data.get('docker', [])
            if dck:
                 f.write("\nDOCKER API EXPOSED (ROOT RCE)\n")
                 f.write("=============================\n")
                 for d in dck:
                      f.write(f"URL: {d['url']}\nStatus: {d.get('type')}\n\n")

            mem = data.get('memcached', [])
            if mem:
                 f.write("\nMEMCACHED EXPOSED\n")
                 f.write("=================\n")
                 for m in mem:
                      f.write(f"HOST: {m['url']}\nStatus: {m.get('evidence')}\n\n")

            git = data.get('gitea', [])
            if git:
                 f.write("\nGITEA VULNERABILITY\n")
                 f.write("===================\n")
                 for gt in git:
                      f.write(f"URL: {gt['url']}\nStatus: {gt.get('evidence')}\n\n")

            mini = data.get('minio', [])
            if mini:
                 f.write("\nMINIO INFO LEAK\n")
                 f.write("===============\n")
                 for mn in mini:
                      f.write(f"URL: {mn['url']}\nStatus: {mn.get('type')}\n\n")

            zab = data.get('zabbix', [])
            if zab:
                 f.write("\nZABBIX AUTH BYPASS\n")
                 f.write("==================\n")
                 for z in zab:
                      f.write(f"URL: {z['url']}\nStatus: {z.get('type')}\n\n")

            jbs = data.get('jboss', [])
            if jbs:
                 f.write("\nJBOSS/WILDFLY EXPOSED\n")
                 f.write("=====================\n")
                 for j in jbs:
                      f.write(f"URL: {j['url']}\nStatus: {j.get('type')}\n\n")

            gfs = data.get('glassfish', [])
            if gfs:
                 f.write("\nGLASSFISH VULNERABILITY\n")
                 f.write("=======================\n")
                 for gf in gfs:
                      f.write(f"URL: {gf['url']}\nStatus: {gf.get('type')}\n\n")

            hdo = data.get('hadoop', [])
            if hdo:
                has_any_vuln = True
                f.write("\nHADOOP YARN RCE\n")
                f.write("===============\n")
                for h in hdo:
                    f.write(f"URL: {h['url']}\nStatus: {h.get('type')}\n\n")
        
        if has_any_vuln:
            console.print(f"[bold red]  -> BUGS saved to {os.path.basename(bug_file)}[/bold red]")
        else:
            try:
                os.remove(bug_file)
            except Exception:
                pass
            
    except Exception as e:
        console.print(f"[bold red]! Error saving report: {e}[/bold red]")
