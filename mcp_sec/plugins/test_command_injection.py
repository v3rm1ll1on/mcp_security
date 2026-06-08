from mcp_sec.core.models import PluginResult, Vulnerability, Severity

def info():
    return {
        "name": "Command Injection (Safe)",
        "description": "Attempts to inject harmless shell commands into tool string arguments.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0"
    }

async def run_test(mcp_client) -> PluginResult:
    plugin_name = info()["name"]
    try:
        tools = await mcp_client.list_tools()
        if not tools.tools:
            return PluginResult(plugin_name=plugin_name, success=True, message="No tools available to test.")
            
        vulnerabilities = []
        payloads = ["; ls -la ;", "& ls -la &", "| ls -la", "`ls -la`", "$(ls -la)", "; whoami ;"]
        
        for tool in tools.tools:
            schema = tool.inputSchema
            if not schema or "properties" not in schema:
                continue
                
            for payload in payloads:
                args = {}
                for prop_name, prop_details in schema["properties"].items():
                    if prop_details.get("type") == "string":
                        args[prop_name] = payload
                    elif prop_details.get("type") == "number":
                        args[prop_name] = 1
                    elif prop_details.get("type") == "boolean":
                        args[prop_name] = True
                        
                if not args:
                    continue
                    
                try:
                    result = await mcp_client.call_tool(tool.name, arguments=args)
                    for content in result.content:
                        if content.type == "text":
                            if "total " in content.text or "-rw" in content.text or "root" in content.text:
                                vuln = Vulnerability(
                                    title="Command Injection",
                                    description="Command execution successful via parameter injection.",
                                    severity=Severity.HIGH,
                                    tool_name=tool.name,
                                    payload=payload
                                )
                                vulnerabilities.append(vuln)
                                break
                except Exception:
                    pass
                    
        success = len(vulnerabilities) == 0
        message = f"Found {len(vulnerabilities)} vulnerabilities." if not success else "No command injection found."
        
        return PluginResult(
            plugin_name=plugin_name,
            success=success,
            message=message,
            vulnerabilities=vulnerabilities
        )
        
    except Exception as e:
        return PluginResult(plugin_name=plugin_name, success=False, message=f"Test failed with error: {str(e)}")
