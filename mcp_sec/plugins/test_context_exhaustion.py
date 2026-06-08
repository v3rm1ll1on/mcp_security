from mcp_sec.core.models import PluginResult, Vulnerability, Severity
from mcp_sec.core.utils import build_default_args
import asyncio

def info():
    return {
        "name": "context_exhaustion",
        "title": "Context Window Exhaustion",
        "description": "Tests if tools return excessively large responses that could crash the calling LLM.",
        "severity": Severity.MEDIUM,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["llm", "dos"],
        "cwe": "CWE-400",
        "owasp": "LLM04: Model Denial of Service"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info()["title"]
    vulnerabilities = []

    # MAX_CHARS represents roughly 15k-20k tokens. A well-behaved MCP tool should paginate or summarize.
    MAX_CHARS = 50000 

    for tool in server_tools:
        schema = getattr(tool, "inputSchema", {})
        properties = schema.get("properties", {})
        args = build_default_args(properties)
        
        try:
            # We just call it normally and see how much it returns
            result = await mcp_client.call_tool(tool.name, arguments=args)
            if result and hasattr(result, "content"):
                total_length = sum(len(c.text) for c in result.content if hasattr(c, "text"))
                if total_length > MAX_CHARS:
                    vulnerabilities.append(Vulnerability(
                        title="Context Window Flooding",
                        description=f"Tool '{tool.name}' returned an excessively large response ({total_length} chars). This can cause Model DoS or token exhaustion.",
                        severity=Severity.MEDIUM,
                        tool_name=tool.name,
                        payload="[Default args execution]"
                    ))
        except Exception as e:
            # Crashes are handled by DoS tests
            pass

    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No excessively large responses detected.")
