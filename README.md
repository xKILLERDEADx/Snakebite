<a id="top"></a>

<div align="center">

<img src="Snakebite.png" alt="Snakebite Banner" width="100%"/>

# 🐍 Snakebite — Advanced Vulnerability Scanner

![Version](https://img.shields.io/badge/Version-2.0-00ff41?style=for-the-badge&labelColor=1a1a2e)
![Modules](https://img.shields.io/badge/Modules-122+-ff6b6b?style=for-the-badge&labelColor=1a1a2e)
![Platform](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Platform](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-Proprietary-e94560?style=for-the-badge&labelColor=1a1a2e)

**The Most Powerful All-in-One Web Vulnerability Scanner**

[⬇️ Download](#-download) • [🚀 Quick Start](#-quick-start) • [📋 Features](#-features) • [📖 Usage](#-usage)

---

</div>

## 🔥 What is Snakebite?

Snakebite is a **professional-grade vulnerability scanner** with **122+ security modules** built for penetration testers, bug bounty hunters, and security researchers. It performs comprehensive security assessments including reconnaissance, injection testing, CMS scanning, and advanced exploit detection — all from a **single executable**.

### ✅ Why Snakebite?

- 🔥 **122+ Security Modules** — More than any other scanner
- 🎯 **Zero Dependencies** — Single standalone executable
- ⚡ **Async Architecture** — Lightning-fast concurrent scanning
- 📊 **Professional Reports** — JSON, HTML & PDF output
- 🛡️ **OWASP Top 10** — Full compliance assessment
- 🤖 **AI-Powered** — Smart vulnerability prediction

### 📊 Comparison

| Feature | Snakebite | Others |
|---------|:---------:|:------:|
| Modules | **122+** | 10-30 |
| CMS Detection | **10** | 1-3 |
| Auto Exploit | ✅ | ❌ |
| OWASP Compliance | ✅ | ❌ |
| CVE Intelligence | ✅ | ❌ |
| Single .exe | ✅ | ❌ |

---

## ⬇️ Download

### 🚀 Latest Release: **v2.0**

| Platform | Download | Size |
|:--------:|:--------:|:----:|
| 🪟 **Windows x64** | [**Snakebite.exe**](https://github.com/xKILLERDEADx/snakebite/releases/latest) | ~17 MB |
| 🐧 **Linux x64** | [**snakebite-linux**](https://github.com/xKILLERDEADx/snakebite/releases/latest) | ~28 MB |

> 💡 **No Python installation required.** Just download and run!

---

## 🚀 Quick Start

### 🪟 Windows
```powershell
# Basic scan
.\Snakebite.exe -u https://target.com

# Verbose + custom timeout
.\Snakebite.exe -u https://target.com -v --timeout 20

# Stealth scan
.\Snakebite.exe -u https://target.com --profile stealth

# Through Burp Suite proxy
.\Snakebite.exe -u https://target.com --proxy http://127.0.0.1:8080

# Scan with auth cookie
.\Snakebite.exe -u https://target.com --cookie "session=abc123"
```

### 🐧 Linux / Termux
```bash
# Make executable
chmod +x snakebite-linux

# Basic scan
./snakebite-linux -u https://target.com

# Stealth mode
./snakebite-linux -u https://target.com --profile stealth
```

---

## 📋 Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Reconnaissance & OSINT
- DNS Records, GeoIP, Reverse IP
- Subdomain Enumeration (CT + Brute)
- Wayback Machine Archive
- Email Harvesting & Social Media
- Technology Fingerprinting
- Google Dorking & Shodan

### 💉 Injection Testing
- SQL Injection (Error + Blind + Time)
- Cross-Site Scripting (Reflected/Stored/DOM)
- Remote Code Execution (RCE)
- Server-Side Template Injection (SSTI)
- Local File Inclusion (LFI)
- XML External Entity (XXE)
- NoSQL / LDAP / XPath Injection
- OS Command Injection
- Log4Shell & Spring4Shell

### 🔐 Authentication & Session
- JWT Security Analysis & Forge Engine
- OAuth2 Full Chain Testing
- Session Fixation Detection
- Broken Access Control (BOLA/BFLA)
- Password Spray & Brute Force

</td>
<td width="50%" valign="top">

### 🌐 Web Application
- CORS Misconfiguration
- Clickjacking Detection
- HTTP Request Smuggling
- Cache Poisoning & Deception
- WebSocket Hijacking
- Race Condition Scanner
- Prototype Pollution

### ☁️ Cloud & Infrastructure
- AWS S3 Bucket Scanner
- Cloud Metadata SSRF
- Kubernetes (K8s) Scanner
- Docker API Scanner
- Firebase Misconfiguration
- Cloud IAM Privilege Escalation

### 🏢 CMS & Enterprise
- WordPress, Drupal, Joomla
- Jenkins, Elastic, Tomcat, WebLogic
- SAP, Exchange, VMware, F5, Citrix
- Jira, Confluence, SonarQube

### 🛡️ Advanced Security
- WAF Detection & ML Bypass
- Zero-Day Pattern Detection
- AI Vulnerability Prediction
- Auto CVE Exploit Engine (2023-2025)
- Supply Chain Auditor

</td>
</tr>
</table>

---

## 📖 Usage

```
Snakebite.exe [OPTIONS]

Options:
  -u, --url URL           Target URL
  -t, --threads N         Concurrent connections (default: 50)
  -o, --output FILE       Output file name
  -v, --verbose           Enable debug logging
  --proxy PROXY           HTTP/SOCKS proxy
  --timeout SEC           Request timeout (default: 15)
  --profile PROFILE       Scan profile: light, standard, full, stealth
  --cookie COOKIE         Authentication cookie
  --header HEADER         Custom header (e.g. 'Authorization: Bearer TOKEN')
  --wordlist FILE         Custom wordlist for fuzzing
  --webhook URL           Callback URL for blind XSS/SSRF
  --telegram-token TOKEN  Telegram alerts
  --discord-webhook URL   Discord alerts
  --shodan-key KEY        Shodan API key
  --vt-key KEY            VirusTotal API key
  --github-token TOKEN    GitHub leak scanning
  --diff OLD NEW          Compare two scan reports
```

---

## ⚙️ Scan Profiles

| Profile | Speed | Coverage | Best For |
|:-------:|:-----:|:--------:|:--------:|
| 🥷 `stealth` | 🐢 Slow | Passive only | Avoid detection |
| ⚡ `light` | 🚀 Fast | Core modules | Quick assessment |
| 🎯 `standard` | ⚖️ Medium | All modules | Default scan |
| 💀 `aggressive` | 🔥 Maximum | Everything | Full pentest |

---

## 📊 Report Formats

| Format | Description |
|:------:|:-----------:|
| 📄 **JSON** | Machine-readable output for automation & CI/CD |
| 🌐 **HTML** | Interactive dashboard with risk scores |
| 📑 **PDF** | Professional pentest report for clients |

---

## ⚠️ Legal Disclaimer

> **Snakebite is designed for authorized security testing only.**
>
> Only use this tool on systems you own or have explicit written permission to test.
> Unauthorized access to computer systems is illegal. The developer assumes no liability
> for misuse of this software.

---

## 📞 Contact

<div align="center">

**Made with 🐍 by [xKILLERDEADx](https://github.com/xKILLERDEADx)**

🌐 [muhammadabid.com](https://muhammadabid.com)

![Stars](https://img.shields.io/github/stars/xKILLERDEADx/snakebite?style=social)
![Downloads](https://img.shields.io/github/downloads/xKILLERDEADx/snakebite/total?style=social)

---

[⬆️ Back to Top](#top)

</div>
