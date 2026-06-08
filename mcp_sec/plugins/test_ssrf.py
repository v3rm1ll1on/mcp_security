from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "ssrf",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Checks if tools accepting URLs or hostnames filter out internal/loopback IP addresses.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "ssrf"],
        "cwe": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = [
        "http://127.0.0.1:54321",              # Closed local port — expects ECONNREFUSED on SSRF
        "http://169.254.169.254/latest/meta-data/",  # AWS Cloud Metadata IP
        "http://localhost:54321"
    ]

    ssrf_indicators = [
        "connection refused", "econnrefused", "connect ETIMEDOUT",
        "timeout", "host unreachable", "instance-id", "ami-id", "metadata"
    ]
    blocked_keywords = ["blocked", "forbidden", "restricted", "invalid url", "not allowed", "disallowed"]
    suspect_params = {"url", "uri", "link", "host", "hostname", "address", "target", "domain"}

    def filter_param(prop_name, prop_details):
        return prop_name.lower() in suspect_params

    def check_vuln(res_text, exc, is_error=False):
        if exc:
            return any(ind in str(exc).lower() for ind in ssrf_indicators)
        content = (res_text or "").lower()
        if any(ind in content for ind in ssrf_indicators):
            return True
        return not is_error and not any(k in content for k in blocked_keywords)

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Potential SSRF Vulnerability",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' accepted internal URL '{pl}' and seems to process it.",
        vuln_severity=Severity.HIGH,
        success_message="No SSRF vulnerabilities detected.",
        filter_param=filter_param
    )
