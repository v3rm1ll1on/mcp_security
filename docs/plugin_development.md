# Plugin Development Guide

The MCP Security Scanner is designed to be highly extensible. Writing a new test is as simple as creating a new Python file in the `mcp_sec/plugins/` directory.

## Requirements

Every plugin must define two things:
1. An `info()` function returning metadata.
2. An `async def run_test(mcp_client)` function returning a `PluginResult`.

## Basic Structure

```python
from mcp_sec.core.models import PluginResult, Vulnerability, Severity

def info():
    return {
        "name": "My Custom Test",
        "description": "Tests for XYZ vulnerabilities.",
        "severity": Severity.MEDIUM,
        "author": "Your Name",
        "contact": "your.email@example.com",
        "version": "1.0.0"
    }

async def run_test(mcp_client) -> PluginResult:
    plugin_name = info()["name"]
    vulnerabilities = []
    
    try:
        tools = await mcp_client.list_tools()
        
        # ... logic to test the tools ...
        # if a vulnerability is found:
        # vuln = Vulnerability(title="Found XYZ", description="...", severity=Severity.MEDIUM)
        # vulnerabilities.append(vuln)
        
        success = len(vulnerabilities) == 0
        message = f"Found {len(vulnerabilities)} issues." if not success else "No issues found."
        
        return PluginResult(
            plugin_name=plugin_name,
            success=success,
            message=message,
            vulnerabilities=vulnerabilities
        )
    except Exception as e:
        return PluginResult(plugin_name=plugin_name, success=False, message=str(e))
```

## Interacting with the MCP Client
The `mcp_client` passed to `run_test` is a connected `ClientSession` from the official Anthropic MCP SDK.
You can use standard methods like:
- `await mcp_client.list_tools()`
- `await mcp_client.call_tool("tool_name", arguments={"key": "value"})`
