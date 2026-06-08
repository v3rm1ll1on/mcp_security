from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "path_traversal",
        "title": "Path Traversal",
        "description": "Tests if file paths can be manipulated to read sensitive data.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "lfi"],
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = [
        "../../../etc/passwd", 
        "/etc/passwd", 
        "////etc/passwd", 
        "..\\..\\..\\windows\\win.ini", 
        "C:\\Windows\\win.ini", 
        "C:/Windows/win.ini"
    ]

    def check_vuln(res_text, exc, is_error=False):
        return bool(res_text and ("root:x:0:0:" in res_text or "[extensions]" in res_text))

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Path Traversal",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' read files outside the working directory using path '{pl}'.",
        vuln_severity=Severity.HIGH,
        success_message="No path traversal found."
    )
