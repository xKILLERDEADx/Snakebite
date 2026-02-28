import asyncio
import dns.resolver
from urllib.parse import urlparse
from modules.core import console

async def get_dns_txt(domain):
    """
    Get TXT records using dnspython for real-time DNS queries.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        answers = resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            txt_record = ''.join([s.decode() for s in rdata.strings])
            records.append(txt_record)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
        return []

async def scan_email_security(session, url):
    """
    Check SPF and DMARC records with real-time DNS queries.
    """
    console.print(f"\n[bold cyan]--- Email Security (SPF/DMARC) Scanner ---[/bold cyan]")
    
    domain = urlparse(url).netloc
    console.print(f"[dim]Querying real-time DNS records for {domain}...[/dim]")
    
    # 1. Check SPF Record
    spf_records = await get_dns_txt(domain)
    spf_record = None
    spf_status = "MISSING"
    
    for record in spf_records:
        if record.startswith("v=spf1"):
            spf_record = record
            break
            
    if spf_record:
        if "-all" in spf_record:
            spf_status = "STRONG (Hard Fail)"
        elif "~all" in spf_record:
            spf_status = "MODERATE (Soft Fail)"
        elif "+all" in spf_record:
            spf_status = "WEAK (Allow All)"
        elif "?all" in spf_record:
            spf_status = "NEUTRAL"
        else:
            spf_status = "CONFIGURED"
    
    # 2. Check DMARC Record
    dmarc_records = await get_dns_txt(f"_dmarc.{domain}")
    dmarc_record = None
    dmarc_status = "MISSING"
    
    for record in dmarc_records:
        if record.startswith("v=DMARC1"):
            dmarc_record = record
            break
            
    if dmarc_record:
        if "p=reject" in dmarc_record:
            dmarc_status = "STRONG (Reject)"
        elif "p=quarantine" in dmarc_record:
            dmarc_status = "MODERATE (Quarantine)"
        elif "p=none" in dmarc_record:
            dmarc_status = "WEAK (None)"
        else:
            dmarc_status = "CONFIGURED"
    
    # 3. Enhanced DKIM Detection
    dkim_status = "MISSING"
    dkim_found = False
    try:
        # Common DKIM selectors to check
        selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'mail', 'dkim', 's1', 's2', 'key1', 'key2']
        for selector in selectors:
            try:
                dkim_records = await get_dns_txt(f"{selector}._domainkey.{domain}")
                if any("v=DKIM1" in record or "k=rsa" in record for record in dkim_records):
                    dkim_status = "CONFIGURED"
                    dkim_found = True
                    break
            except Exception:
                continue
        
        if not dkim_found:
            dkim_status = "NOT DETECTED"
    except Exception:
        dkim_status = "CHECK FAILED"
            
    # Display Results with Security Assessment
    console.print("\n[bold yellow]Security Assessment:[/bold yellow]")
    
    spf_color = "red" if spf_status == "MISSING" or "WEAK" in spf_status else "yellow" if "MODERATE" in spf_status else "green"
    console.print(f"  [bold {spf_color}]SPF Record:[/bold {spf_color}]   {spf_status}")
    if spf_record:
        console.print(f"      [dim]{spf_record[:100]}{'...' if len(spf_record) > 100 else ''}[/dim]")
        
    dmarc_color = "red" if dmarc_status == "MISSING" or "WEAK" in dmarc_status else "yellow" if "MODERATE" in dmarc_status else "green"
    console.print(f"  [bold {dmarc_color}]DMARC Record:[/bold {dmarc_color}] {dmarc_status}")
    if dmarc_record:
        console.print(f"      [dim]{dmarc_record[:100]}{'...' if len(dmarc_record) > 100 else ''}[/dim]")
        
    dkim_color = "red" if "MISSING" in dkim_status or "NOT DETECTED" in dkim_status else "yellow" if "FAILED" in dkim_status else "green"
    console.print(f"  [bold {dkim_color}]DKIM Record:[/bold {dkim_color}]  {dkim_status}")
    
    # Overall Security Score
    score = 0
    if spf_status != "MISSING" and "WEAK" not in spf_status:
        score += 1
    if dmarc_status != "MISSING" and "WEAK" not in dmarc_status:
        score += 1
    if dkim_status == "CONFIGURED":
        score += 1
        
    if score == 3:
        overall_color = "green"
        overall_status = "EXCELLENT"
    elif score == 2:
        overall_color = "yellow"
        overall_status = "GOOD"
    elif score == 1:
        overall_color = "orange1"
        overall_status = "MODERATE"
    else:
        overall_color = "red"
        overall_status = "POOR"
        
    console.print(f"\n[bold {overall_color}]Overall Email Security: {overall_status} ({score}/3)[/bold {overall_color}]")
        
    return {
        "spf_status": spf_status,
        "spf_record": spf_record,
        "dmarc_status": dmarc_status,
        "dmarc_record": dmarc_record,
        "dkim_status": dkim_status,
        "security_score": score,
        "overall_status": overall_status
    }
