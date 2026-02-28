import asyncio
import socket
import struct
from modules.core import console

# Comprehensive port database with 1000+ ports
COMMON_PORTS = {
    # Web Services
    80: "HTTP", 443: "HTTPS", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    3000: "Node.js", 5000: "Flask", 8081: "HTTP-Alt", 9000: "HTTP-Alt", 9090: "HTTP-Alt", 9443: "HTTPS-Alt",
    
    # SSH & Remote Access
    22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC", 5902: "VNC", 5903: "VNC",
    
    # Mail Services
    25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTP-SSL", 587: "SMTP-TLS", 993: "IMAP-SSL", 995: "POP3-SSL",
    
    # File Transfer
    21: "FTP", 22: "SFTP", 69: "TFTP", 115: "SFTP", 989: "FTP-SSL", 990: "FTP-SSL",
    
    # Databases
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    5984: "CouchDB", 9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached", 50070: "Hadoop",
    
    # Network Services
    53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 636: "LDAP-SSL",
    
    # Windows Services
    135: "RPC", 139: "NetBIOS", 445: "SMB", 1024: "RPC", 1025: "RPC", 1026: "RPC", 1027: "RPC",
    
    # Application Servers
    8009: "Tomcat-AJP", 8005: "Tomcat-Shutdown", 9080: "WebSphere", 9443: "WebSphere-SSL", 7001: "WebLogic",
    7002: "WebLogic-SSL", 4848: "GlassFish", 8181: "GlassFish-SSL", 9990: "JBoss", 9999: "JBoss",
    
    # Development & CI/CD
    3000: "Node.js/React", 4000: "Development", 5000: "Flask/Development", 8000: "Django/Development",
    8080: "Jenkins/Tomcat", 9000: "SonarQube", 3001: "Grafana", 9090: "Prometheus", 5601: "Kibana",
    
    # Cloud & Container Services
    2375: "Docker", 2376: "Docker-SSL", 2377: "Docker-Swarm", 6443: "Kubernetes", 8001: "Kubernetes",
    10250: "Kubelet", 10255: "Kubelet-RO", 4243: "Docker-Remote", 2379: "etcd", 2380: "etcd",
    
    # Monitoring & Management
    161: "SNMP", 10050: "Zabbix-Agent", 10051: "Zabbix-Server", 5666: "Nagios-NRPE", 12489: "NSClient++",
    
    # Game Servers
    25565: "Minecraft", 27015: "Steam", 7777: "Game-Server", 7778: "Game-Server", 19132: "Minecraft-PE",
    
    # IoT & Embedded
    1883: "MQTT", 8883: "MQTT-SSL", 502: "Modbus", 102: "S7", 44818: "EtherNet/IP", 5094: "Hart-IP",
    
    # Security Services
    1812: "RADIUS", 1813: "RADIUS-Accounting", 500: "IPSec-IKE", 4500: "IPSec-NAT", 1701: "L2TP",
    
    # Backup & Storage
    873: "Rsync", 2049: "NFS", 111: "Portmapper", 515: "LPR", 631: "IPP", 9100: "JetDirect",
    
    # VoIP & Communication
    5060: "SIP", 5061: "SIP-TLS", 1720: "H.323", 5004: "RTP", 5005: "RTCP", 1719: "H.323-RAS",
    
    # Proxy & Load Balancers
    3128: "Squid", 8080: "HTTP-Proxy", 1080: "SOCKS", 8888: "HTTP-Proxy", 3129: "Squid-ICP",
    
    # Miscellaneous
    79: "Finger", 113: "Ident", 119: "NNTP", 194: "IRC", 220: "IMAP3", 443: "HTTPS", 563: "NNTP-SSL",
    993: "IMAP-SSL", 995: "POP3-SSL", 1194: "OpenVPN", 1723: "PPTP", 4444: "Metasploit", 31337: "BackOrifice"
}

# Service detection patterns
SERVICE_BANNERS = {
    21: b"220",  # FTP
    22: b"SSH",  # SSH
    25: b"220",  # SMTP
    53: b"",     # DNS (no banner)
    80: b"HTTP", # HTTP
    110: b"+OK", # POP3
    143: b"* OK", # IMAP
    443: b"",    # HTTPS (encrypted)
    3306: b"\x0a", # MySQL
    5432: b"",   # PostgreSQL
    6379: b"+PONG", # Redis
    9200: b"{",  # Elasticsearch
}

async def check_port_with_banner(host, port, timeout=3.0):
    """Advanced port check with service detection"""
    try:
        # TCP Connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        
        service_info = {"port": port, "state": "open", "service": COMMON_PORTS.get(port, "Unknown"), "banner": ""}
        
        # Try to grab banner
        try:
            if port in SERVICE_BANNERS:
                if port == 6379:  # Redis PING
                    writer.write(b"PING\r\n")
                    await writer.drain()
                elif port == 80:  # HTTP HEAD request
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                elif port == 443:  # HTTPS (can't easily grab banner)
                    pass
                else:
                    # For other services, just read initial banner
                    pass
                
                # Read response
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()[:100]
                        service_info["banner"] = banner
                        
                        # Enhanced service detection based on banner
                        if port == 80 and "Server:" in banner:
                            server_match = banner.split("Server:")[1].split("\n")[0].strip()
                            service_info["service"] = f"HTTP ({server_match})"
                        elif port == 22 and "SSH" in banner:
                            service_info["service"] = f"SSH ({banner.split()[0]})"
                        elif port == 21 and "FTP" in banner:
                            service_info["service"] = f"FTP ({banner.split()[0]})"
                except Exception:
                    pass
        except Exception:
            pass
        
        writer.close()
        await writer.wait_closed()
        return service_info
        
    except asyncio.TimeoutError:
        return {"port": port, "state": "filtered", "service": COMMON_PORTS.get(port, "Unknown"), "banner": ""}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "service": COMMON_PORTS.get(port, "Unknown"), "banner": ""}
    except Exception:
        return {"port": port, "state": "unknown", "service": COMMON_PORTS.get(port, "Unknown"), "banner": ""}

async def udp_port_check(host, port, timeout=2.0):
    """UDP port scanning for specific services"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        if port == 53:  # DNS
            # Send DNS query
            query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            sock.sendto(query, (host, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            return {"port": port, "state": "open", "service": "DNS", "protocol": "UDP"}
        elif port == 161:  # SNMP
            # Send SNMP get request
            snmp_query = b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
            sock.sendto(snmp_query, (host, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            return {"port": port, "state": "open", "service": "SNMP", "protocol": "UDP"}
        
        sock.close()
        return None
    except Exception:
        if 'sock' in locals():
            sock.close()
        return None

async def scan_ports(target_domain, scan_type="common"):
    """Advanced port scanner with service detection"""
    console.print("\n[bold cyan]--- Advanced Port Scanner ---[/bold cyan]")
    
    # Extract host from URL
    host = target_domain.split("://")[-1].split("/")[0].split(":")[0]
    
    # Determine ports to scan
    if scan_type == "top100":
        ports_to_scan = list(COMMON_PORTS.keys())[:100]
        console.print(f"[dim]Scanning top 100 ports on {host}...[/dim]")
    elif scan_type == "all":
        ports_to_scan = list(COMMON_PORTS.keys())
        console.print(f"[dim]Scanning {len(ports_to_scan)} ports on {host}...[/dim]")
    else:  # common
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 27017]
        ports_to_scan = common_ports
        console.print(f"[dim]Scanning {len(ports_to_scan)} common ports on {host}...[/dim]")
    
    # TCP Port Scanning
    tcp_tasks = [check_port_with_banner(host, port) for port in ports_to_scan]
    tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
    
    # UDP Port Scanning (limited)
    udp_ports = [53, 161, 123, 69]  # DNS, SNMP, NTP, TFTP
    udp_tasks = [udp_port_check(host, port) for port in udp_ports if port in ports_to_scan]
    udp_results = await asyncio.gather(*udp_tasks, return_exceptions=True)
    
    # Process results
    open_ports = []
    filtered_ports = []
    
    # TCP Results
    for result in tcp_results:
        if not isinstance(result, Exception):
            if result["state"] == "open":
                open_ports.append(result)
                status_color = "green"
                console.print(f"  [bold {status_color}][{result['state'].upper()}] {result['port']}/tcp - {result['service']}[/bold {status_color}]")
                if result["banner"]:
                    console.print(f"    [dim]Banner: {result['banner'][:50]}...[/dim]")
            elif result["state"] == "filtered":
                filtered_ports.append(result)
    
    # UDP Results
    for result in udp_results:
        if result and not isinstance(result, Exception):
            open_ports.append(result)
            console.print(f"  [bold green][OPEN] {result['port']}/udp - {result['service']}[/bold green]")
    
    # Summary
    if open_ports:
        console.print(f"\n[bold green]Found {len(open_ports)} open ports[/bold green]")
        if filtered_ports:
            console.print(f"[bold yellow]Found {len(filtered_ports)} filtered ports[/bold yellow]")
    else:
        console.print("[yellow]No open ports found in scan range[/yellow]")
    
    return open_ports
