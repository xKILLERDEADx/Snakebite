"""CVE Mapper — maps vulnerability findings to real CVE IDs with CVSS scores."""

from modules.core import console

CVE_DATABASE = {
    "log4shell": {
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "title": "Apache Log4j2 Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    "spring4shell": {
        "cve": "CVE-2022-22965",
        "cvss": 9.8,
        "title": "Spring Framework RCE via Data Binding",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
    },
    "drupalgeddon2": {
        "cve": "CVE-2018-7600",
        "cvss": 9.8,
        "title": "Drupal Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"
    },
    "shellshock": {
        "cve": "CVE-2014-6271",
        "cvss": 9.8,
        "title": "GNU Bash Remote Code Execution (Shellshock)",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    },
    "heartbleed": {
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "title": "OpenSSL Heartbleed Information Disclosure",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    },
    "citrix_rce": {
        "cve": "CVE-2019-19781",
        "cvss": 9.8,
        "title": "Citrix ADC/Gateway Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-19781"
    },
    "pulse_vpn": {
        "cve": "CVE-2019-11510",
        "cvss": 10.0,
        "title": "Pulse Secure VPN Arbitrary File Read",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-11510"
    },
    "apache_struts": {
        "cve": "CVE-2017-5638",
        "cvss": 10.0,
        "title": "Apache Struts 2 Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
    },
    "weblogic_rce": {
        "cve": "CVE-2020-14882",
        "cvss": 9.8,
        "title": "Oracle WebLogic Server Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"
    },
    "exchange_proxyshell": {
        "cve": "CVE-2021-34473",
        "cvss": 9.8,
        "title": "Microsoft Exchange Server ProxyShell RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473"
    },
    "exchange_proxylogon": {
        "cve": "CVE-2021-26855",
        "cvss": 9.8,
        "title": "Microsoft Exchange Server ProxyLogon SSRF",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"
    },
    "vmware_rce": {
        "cve": "CVE-2021-21972",
        "cvss": 9.8,
        "title": "VMware vCenter Server Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-21972"
    },
    "f5_bigip_rce": {
        "cve": "CVE-2020-5902",
        "cvss": 9.8,
        "title": "F5 BIG-IP TMUI Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"
    },
    "confluence_rce": {
        "cve": "CVE-2022-26134",
        "cvss": 9.8,
        "title": "Atlassian Confluence OGNL Injection RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-26134"
    },
    "jira_ssrf": {
        "cve": "CVE-2019-8451",
        "cvss": 6.1,
        "title": "Atlassian Jira Server-Side Request Forgery",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-8451"
    },
    "jenkins_rce": {
        "cve": "CVE-2024-23897",
        "cvss": 9.8,
        "title": "Jenkins Arbitrary File Read via CLI",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-23897"
    },
    "grafana_lfi": {
        "cve": "CVE-2021-43798",
        "cvss": 7.5,
        "title": "Grafana Arbitrary File Read",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-43798"
    },
    "elasticsearch_rce": {
        "cve": "CVE-2015-1427",
        "cvss": 7.5,
        "title": "Elasticsearch Groovy Scripting RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"
    },
    "tomcat_ghostcat": {
        "cve": "CVE-2020-1938",
        "cvss": 9.8,
        "title": "Apache Tomcat AJP Connector (Ghostcat)",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938"
    },
    "thinkphp_rce": {
        "cve": "CVE-2018-20062",
        "cvss": 9.8,
        "title": "ThinkPHP Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-20062"
    },
    "rails_rce": {
        "cve": "CVE-2019-5418",
        "cvss": 7.5,
        "title": "Ruby on Rails File Disclosure",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-5418"
    },
    "coldfusion_rce": {
        "cve": "CVE-2023-26360",
        "cvss": 9.8,
        "title": "Adobe ColdFusion Deserialization RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-26360"
    },
    "solr_rce": {
        "cve": "CVE-2019-17558",
        "cvss": 9.8,
        "title": "Apache Solr Remote Code Execution via Velocity",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-17558"
    },
    "nginx_off_by_slash": {
        "cve": "CVE-2017-7529",
        "cvss": 7.5,
        "title": "Nginx Integer Overflow / Off-by-Slash",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7529"
    },
    "sap_rce": {
        "cve": "CVE-2020-6287",
        "cvss": 10.0,
        "title": "SAP NetWeaver RECON (Remotely Exploitable)",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-6287"
    },
    "kubernetes_api": {
        "cve": "CVE-2018-1002105",
        "cvss": 9.8,
        "title": "Kubernetes API Server Privilege Escalation",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"
    },
    "docker_api": {
        "cve": "CVE-2019-5736",
        "cvss": 8.6,
        "title": "Docker runc Container Escape",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-5736"
    },
    "jboss_rce": {
        "cve": "CVE-2017-12149",
        "cvss": 9.8,
        "title": "JBoss Application Server Deserialization RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-12149"
    },
    "glassfish_rce": {
        "cve": "CVE-2017-1000028",
        "cvss": 7.5,
        "title": "GlassFish Server LFI / Path Traversal",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-1000028"
    },
    "hadoop_yarn_rce": {
        "cve": "CVE-2018-8088",
        "cvss": 9.8,
        "title": "Apache Hadoop YARN ResourceManager RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-8088"
    },
    "wordpress_rce": {
        "cve": "CVE-2019-8942",
        "cvss": 8.8,
        "title": "WordPress Crop Image RCE",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-8942"
    },
    "wordpress_sqli": {
        "cve": "CVE-2022-21661",
        "cvss": 9.8,
        "title": "WordPress WP_Query SQL Injection",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-21661"
    },
    "firebase_misconfig": {
        "cve": "N/A",
        "cvss": 7.5,
        "title": "Firebase Database Misconfiguration (Public Read)",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "git_exposure": {
        "cve": "N/A",
        "cvss": 7.5,
        "title": "Git Repository Exposure (.git/HEAD accessible)",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "env_exposure": {
        "cve": "N/A",
        "cvss": 9.0,
        "title": "Environment File Exposure (.env accessible)",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "swagger_exposure": {
        "cve": "N/A",
        "cvss": 5.3,
        "title": "Swagger/OpenAPI Specification Exposed",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "graphql_introspection": {
        "cve": "N/A",
        "cvss": 5.3,
        "title": "GraphQL Introspection Enabled",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "cors_misconfig": {
        "cve": "N/A",
        "cvss": 6.5,
        "title": "CORS Misconfiguration (Origin Reflection)",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "clickjacking": {
        "cve": "N/A",
        "cvss": 4.3,
        "title": "Clickjacking (Missing X-Frame-Options)",
        "ref": "https://owasp.org/www-community/attacks/Clickjacking"
    },
    "xxe": {
        "cve": "N/A",
        "cvss": 9.0,
        "title": "XML External Entity Injection",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "jwt_weak": {
        "cve": "CVE-2022-23529",
        "cvss": 7.5,
        "title": "JWT None Algorithm / Weak Secret",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-23529"
    },
    "subdomain_takeover": {
        "cve": "N/A",
        "cvss": 8.0,
        "title": "Subdomain Takeover (Dangling DNS)",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "crlf_injection": {
        "cve": "N/A",
        "cvss": 6.1,
        "title": "CRLF Injection / HTTP Response Splitting",
        "ref": "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"
    },
    "open_redirect": {
        "cve": "N/A",
        "cvss": 6.1,
        "title": "Open Redirect / Unvalidated Redirects",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "idor": {
        "cve": "N/A",
        "cvss": 7.5,
        "title": "Insecure Direct Object Reference",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "sqli": {
        "cve": "N/A",
        "cvss": 9.8,
        "title": "SQL Injection",
        "ref": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "xss": {
        "cve": "N/A",
        "cvss": 6.1,
        "title": "Cross-Site Scripting (XSS)",
        "ref": "https://owasp.org/www-community/attacks/xss/"
    },
    "lfi": {
        "cve": "N/A",
        "cvss": 7.5,
        "title": "Local File Inclusion",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "rce": {
        "cve": "N/A",
        "cvss": 9.8,
        "title": "Remote Code Execution",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "ssti": {
        "cve": "N/A",
        "cvss": 9.8,
        "title": "Server-Side Template Injection",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "ssrf": {
        "cve": "N/A",
        "cvss": 9.0,
        "title": "Server-Side Request Forgery",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "http_smuggling": {
        "cve": "N/A",
        "cvss": 8.1,
        "title": "HTTP Request Smuggling (CL.TE/TE.CL)",
        "ref": "https://portswigger.net/web-security/request-smuggling"
    },
    "java_deserialization": {
        "cve": "CVE-2015-4852",
        "cvss": 9.8,
        "title": "Java Deserialization Remote Code Execution",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-4852"
    },
    "nosql_injection": {
        "cve": "N/A",
        "cvss": 9.0,
        "title": "NoSQL Injection (MongoDB/CouchDB)",
        "ref": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "prototype_pollution": {
        "cve": "N/A",
        "cvss": 6.1,
        "title": "JavaScript Prototype Pollution",
        "ref": "https://portswigger.net/web-security/prototype-pollution"
    },
    "host_header_injection": {
        "cve": "N/A",
        "cvss": 6.1,
        "title": "Host Header Injection / Password Reset Poisoning",
        "ref": "https://portswigger.net/web-security/host-header"
    },
    "cache_deception": {
        "cve": "N/A",
        "cvss": 7.5,
        "title": "Web Cache Deception / Cache Poisoning",
        "ref": "https://portswigger.net/web-security/web-cache-poisoning"
    },
}

MODULE_TO_CVE_KEY = {
    "log4shell": "log4shell",
    "spring4shell": "spring4shell",
    "drupal": "drupalgeddon2",
    "shellshock": "shellshock",
    "citrix": "citrix_rce",
    "pulse": "pulse_vpn",
    "struts": "apache_struts",
    "weblogic": "weblogic_rce",
    "exchange": "exchange_proxyshell",
    "vmware": "vmware_rce",
    "f5": "f5_bigip_rce",
    "confluence": "confluence_rce",
    "jira": "jira_ssrf",
    "jenkins": "jenkins_rce",
    "grafana": "grafana_lfi",
    "elastic": "elasticsearch_rce",
    "tomcat": "tomcat_ghostcat",
    "thinkphp": "thinkphp_rce",
    "rails": "rails_rce",
    "coldfusion": "coldfusion_rce",
    "solr": "solr_rce",
    "nginx": "nginx_off_by_slash",
    "sap": "sap_rce",
    "k8s": "kubernetes_api",
    "docker": "docker_api",
    "jboss": "jboss_rce",
    "glassfish": "glassfish_rce",
    "hadoop": "hadoop_yarn_rce",
    "firebase": "firebase_misconfig",
    "git": "git_exposure",
    "swagger": "swagger_exposure",
    "graphql": "graphql_introspection",
    "cors": "cors_misconfig",
    "clickjacking": "clickjacking",
    "xxe": "xxe",
    "jwt": "jwt_weak",
    "takeover": "subdomain_takeover",
    "crlf": "crlf_injection",
    "redirect": "open_redirect",
    "idor": "idor",
    "sqli": "sqli",
    "xss": "xss",
    "lfi": "lfi",
    "rce": "rce",
    "ssti": "ssti",
    "ssrf": "ssrf",
    "smuggling": "http_smuggling",
    "java": "java_deserialization",
    "nosql": "nosql_injection",
    "prototype": "prototype_pollution",
    "host": "host_header_injection",
    "cache": "cache_deception",
    "wordpress": "wordpress_rce",
    "env_dump": "env_exposure",
}


def get_cve_for_module(module_name):
    """Get CVE info for a scan module name."""
    key = MODULE_TO_CVE_KEY.get(module_name, module_name)
    return CVE_DATABASE.get(key)


def enrich_finding_with_cve(finding, module_name=None):
    """Add CVE data to a finding dict."""
    if module_name:
        cve_info = get_cve_for_module(module_name)
    else:
        vuln_type = finding.get("type", finding.get("vulnerability", "")).lower()
        cve_info = CVE_DATABASE.get(vuln_type)

    if cve_info:
        finding['cve'] = cve_info['cve']
        finding['cvss'] = cve_info['cvss']
        finding['cve_title'] = cve_info['title']
        finding['cve_ref'] = cve_info['ref']

    return finding


def enrich_findings_list(findings, module_name=None):
    """Add CVE data to a list of findings."""
    return [enrich_finding_with_cve(f, module_name) for f in findings]


def print_cve_summary(findings):
    """Print CVE mapping summary to console."""
    cve_findings = [f for f in findings if f.get('cve')]
    if not cve_findings:
        return

    console.print("\n[bold red]📋 CVE MAPPING SUMMARY[/bold red]")
    for f in cve_findings:
        cvss = f.get('cvss', 0)
        color = 'red' if cvss >= 9.0 else 'yellow' if cvss >= 7.0 else 'cyan'
        console.print(f"  [{color}]{f['cve']}[/{color}] (CVSS: {cvss}) — {f.get('cve_title', '')}")
        if f.get('cve_ref'):
            console.print(f"    [dim]{f['cve_ref']}[/dim]")
