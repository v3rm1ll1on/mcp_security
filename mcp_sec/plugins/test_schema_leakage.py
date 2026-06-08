from mcp_sec.core.models import PluginResult, Vulnerability, Severity
import re

def info():
    return {
        "name": "schema_leakage",
        "title": "Schema Information Leakage",
        "description": "Analyzes tool schemas for leaked sensitive information (internal IPs, API keys, hidden parameters).",
        "severity": Severity.LOW,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "leakage"],
        "cwe": "CWE-200",
        "owasp": "A01:2021-Broken Access Control"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info()["title"]
    vulnerabilities = []

    # Regexes for sensitive data
    sensitive_patterns = {
        "Internal IP": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})",
        "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
        "JWT": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "AWS Key": r"AKIA[0-9A-Z]{16}"
    }

    for tool in server_tools:
        schema_str = str(getattr(tool, "inputSchema", {})) + str(getattr(tool, "description", ""))
        
        for vuln_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, schema_str)
            if matches:
                vulnerabilities.append(Vulnerability(
                    title=f"Schema Leakage: {vuln_type}",
                    description=f"Tool '{tool.name}' leaked a {vuln_type} in its schema or description.",
                    severity=Severity.MEDIUM if "Key" in vuln_type or "Token" in vuln_type else Severity.LOW,
                    tool_name=tool.name,
                    payload=f"Matched: {matches[0]}"
                ))

    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No schema leakage detected.")
