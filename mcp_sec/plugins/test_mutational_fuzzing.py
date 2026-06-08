from mcp_sec.core.models import PluginResult, Vulnerability, Severity
from mcp_sec.core.utils import build_default_args
import asyncio

def info():
    return {
        "name": "mutational_fuzzing",
        "title": "Mutational Fuzzing (Type Juggling)",
        "description": "Tests if tools crash when provided with unexpected types (arrays instead of strings, massive integers).",
        "severity": Severity.MEDIUM,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "fuzzing"],
        "cwe": "CWE-20",
        "owasp": "A04:2021-Insecure Design"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info()["title"]
    vulnerabilities = []

    fuzz_payloads = [
        {"fuzz": "array_injection"}, # Type juggling (dict/object instead of string)
        ["array_injection"],         # List instead of string
        999999999999999999999999,    # Integer overflow
        -1,                          # Negative
        "\x00" * 1000                # Null byte flood
    ]

    for tool in server_tools:
        schema = getattr(tool, "inputSchema", {})
        properties = schema.get("properties", {})
        
        if not properties:
            continue
            
        for param_name in properties:
            for payload in fuzz_payloads:
                args = build_default_args(properties)
                # Mutate the specific parameter
                args[param_name] = payload
                
                try:
                    result = await mcp_client.call_tool(tool.name, arguments=args)
                    # If it returns a graceful error or handles it, it's fine.
                except Exception as e:
                    # If it raises a connection error or unhandled exception, the parser crashed.
                    # FastMCP normally handles validation errors gracefully. If it throws here, it's a hard crash.
                    err_str = str(e).lower()
                    if "connection" in err_str or "closed" in err_str or "timeout" in err_str:
                        vulnerabilities.append(Vulnerability(
                            title="Parser Crash / Unhandled Exception",
                            description=f"Tool '{tool.name}' crashed or closed connection when parameter '{param_name}' was mutated with type {type(payload).__name__}.",
                            severity=Severity.HIGH,
                            tool_name=tool.name,
                            payload=f"Param: {param_name}, Value: {payload}"
                        ))
                        break # Stop testing this tool if the server crashed

    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No type juggling or fuzzing crashes detected.")
