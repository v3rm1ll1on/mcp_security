from mcp_sec.core.models import PluginResult, Severity

def info():
    return {
        "name": "Basic Ping",
        "description": "Checks if the MCP server is reachable and exposes tools.",
        "severity": Severity.INFO,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0"
    }

async def run_test(mcp_client) -> PluginResult:
    plugin_name = info()["name"]
    try:
        tools = await mcp_client.list_tools()
        return PluginResult(
            plugin_name=plugin_name,
            success=True,
            message=f"Ping successful. Server exposes {len(tools.tools)} tools."
        )
    except Exception as e:
        return PluginResult(
            plugin_name=plugin_name,
            success=False,
            message=f"Ping failed: {str(e)}"
        )
