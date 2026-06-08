from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "command_injection",
        "title": "Command Injection (Safe)",
        "description": "Attempts to inject harmless shell commands into tool string arguments.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "rce"],
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = ["; ls -la ;", "$(whoami)", "`id`"]

    def check_vuln(res_text, exc, is_error=False):
        return bool(res_text and ("total " in res_text or "-rw" in res_text or "root" in res_text))

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Command Injection",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' executed shell command via payload '{pl}'.",
        vuln_severity=Severity.HIGH,
        success_message="No command injection found."
    )
