from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "dos_redos",
        "title": "Denial of Service (DoS/ReDoS)",
        "description": "Tests if tools are vulnerable to resource exhaustion via large inputs or ReDoS payloads.",
        "severity": Severity.MEDIUM,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "dos"],
        "cwe": "CWE-400",
        "owasp": "A04:2021-Insecure Design"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = [
        "A" * 1_000_000,           # 1MB payload (memory exhaustion/buffer DoS)
        "(((a.*)+)+)+b",           # Evil Regex (ReDoS)
        "(a+)+b"
    ]

    def check_vuln(res_text, exc, is_error=False):
        # Wenn der Server abstürzt (Connection Error) oder ein Timeout auftritt, ist es eine DoS.
        return isinstance(exc, TimeoutError) or (exc is not None and "connection" in str(exc).lower())

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Denial of Service Vulnerability",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' crashed or timed out when processing a DoS payload (length: {len(pl)}).",
        vuln_severity=Severity.MEDIUM,
        success_message="No DoS vulnerabilities detected."
    )
