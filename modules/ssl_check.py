import ssl
import socket
import datetime
from urllib.parse import urlparse
from modules.core import console

def analyze_ssl(url):
    """
    Analyze SSL/TLS configuration of the target.
    """
    console.print(f"\n[bold cyan]--- SSL/TLS Security Scanner ---[/bold cyan]")
    
    parsed = urlparse(url)
    hostname = parsed.netloc
    port = 443
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Check Expiry
                not_after = cert['notAfter']
                # Format: May 25 12:00:00 2024 GMT
                expiry_date = datetime.datetime.strptime(not_after, r"%b %d %H:%M:%S %Y %Z")
                remaining = expiry_date - datetime.datetime.now()
                
                # Issuer
                issuer = dict(x[0] for x in cert['issuer'])
                common_name = issuer.get('commonName', 'Unknown')
                organization = issuer.get('organizationName', 'Unknown')
                
                console.print(f"  [bold white]Protocol:[/bold white] {version}")
                console.print(f"  [bold white]Cipher:[/bold white] {cipher[0]} ({cipher[1]})")
                console.print(f"  [bold white]Issuer:[/bold white] {common_name} ({organization})")
                
                color = "green" if remaining.days > 30 else "red"
                console.print(f"  [bold {color}]Expires:[/bold {color}] {expiry_date.strftime('%Y-%m-%d')} ({remaining.days} days remaining)")
                
                return {
                    "protocol": version,
                    "cipher": cipher[0],
                    "issuer_cn": common_name,
                    "issuer_org": organization,
                    "expiry": expiry_date.strftime('%Y-%m-%d'),
                    "days_remaining": remaining.days
                }
                
    except Exception as e:
        console.print(f"[bold red][!] SSL Handshake Failed: {e}[/bold red]")
        return {"error": str(e)}

# Async wrapper not strictly needed as SSL handshake is blocking, 
# but for consistency we can run it in executor if needed.
# For simplicity, we call it directly as it's fast enough for one target.
