from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "sqli",
        "title": "SQL Injection",
        "description": "Tests if tools are vulnerable to SQL Injection by sending non-destructive SQL probes and checking for database error patterns.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "sqli"],
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = [
        "'", '"', "1' OR '1'='1", "1\" OR \"1\"=\"1",
        "1; --", "1) OR 1=1 --", "1') OR ('1'='1"
    ]

    sqli_errors = [
        "sql syntax", "sqlite3.operationalerror", "unclosed quotation mark",
        "postgresql query failed", "mysql_query", "pg_query",
        "you have an error in your sql syntax", "right syntax to use near",
        "sqlstate", "driver description", "unrecognized token:",
        "near \"'\": syntax error", "near \"\"\": syntax error",
        "near \"-\": syntax error", "near \"%\": syntax error"
    ]

    def check_vuln(res_text, exc, is_error=False):
        text = str(exc).lower() if exc else (res_text or "").lower()
        return any(err in text for err in sqli_errors)

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="SQL Injection",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' returned a database error indicating SQL injection vulnerability.",
        vuln_severity=Severity.HIGH,
        success_message="No SQL injection vulnerabilities detected."
    )
