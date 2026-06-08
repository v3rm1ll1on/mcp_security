from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "xss",
        "title": "Cross-Site Scripting (XSS)",
        "description": "Tests if tools return unsanitized input that could lead to XSS if rendered in a UI.",
        "severity": Severity.MEDIUM,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "xss"],
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]

    def check_vuln(res_text, exc, is_error=False):
        if is_error or not res_text:
            return False
        return any(p in res_text for p in payloads)

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Potential XSS / Unescaped Output",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' reflected potentially malicious HTML/JS: '{pl}'.",
        vuln_severity=Severity.MEDIUM,
        success_message="No XSS reflection found."
    )
