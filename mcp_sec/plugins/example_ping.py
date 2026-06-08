import time
from mcp_sec.core.models import PluginResult, Severity

def info():
    return {
        "name": "ping",
        "title": "Basic Ping",
        "description": "Verifies server connectivity and protocol compliance via standard MCP ping.",
        "severity": Severity.INFO,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["utility"]
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info().get("title", info()["name"])
    # Pinge den Server und messe die Latenz
    start_time = time.perf_counter()
    await mcp_client.send_ping()
    latency = (time.perf_counter() - start_time) * 1000
    
    num_tools = len(server_tools)
    tool_names = [t.name for t in server_tools]
    tool_str = f": ({', '.join(tool_names)})" if tool_names else ""
    
    return PluginResult(
        plugin_name=plugin_name,
        success=True,
        message=f"Ping OK ({latency:.2f}ms). Target exposes {num_tools} tools{tool_str}"
    )
