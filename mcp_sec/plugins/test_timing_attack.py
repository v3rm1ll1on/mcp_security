from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "timing_attack",
        "title": "Timing Attack / Blind Injection",
        "description": "Tests for blind vulnerabilities by attempting to delay tool execution.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "injection", "dos"],
        "cwe": "CWE-208",
        "owasp": "A03:2021-Injection"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    # We use sleep values > call_timeout (default 10s) to trigger the timeout.
    payloads = [
        "sleep 12",
        "; sleep 12 ;",
        "$(sleep 12)",
        "pg_sleep(12)",
        "WAITFOR DELAY '0:0:12'"
    ]

    def check_vuln(res_text, exc, is_error=False):
        return isinstance(exc, TimeoutError)

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Timing Attack / Blind Injection",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' execution timed out when injected with payload '{pl}', indicating a blind injection vulnerability.",
        vuln_severity=Severity.HIGH,
        success_message="No timing vulnerabilities detected."
    )
