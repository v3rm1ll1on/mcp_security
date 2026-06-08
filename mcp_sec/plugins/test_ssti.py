from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "ssti",
        "title": "Server-Side Template Injection (SSTI)",
        "description": "Tests for template injection vulnerabilities in tools that generate formatted output.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "injection"],
        "cwe": "CWE-1336",
        "owasp": "A03:2021-Injection"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    # Common SSTI payloads that evaluate to "343" if vulnerable
    payloads = [
        "{{7*7*7}}",
        "${7*7*7}",
        "<%= 7*7*7 %>",
        "${{7*7*7}}",
        "#{7*7*7}"
    ]

    def check_vuln(res_text, exc, is_error=False):
        return bool(res_text and "343" in res_text and "7*7*7" not in res_text)

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Server-Side Template Injection (SSTI)",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' evaluated the template payload '{pl}'.",
        vuln_severity=Severity.HIGH,
        success_message="No SSTI vulnerabilities found."
    )
