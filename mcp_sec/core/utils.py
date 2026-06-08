from typing import Any, Dict, Optional, Callable, AsyncGenerator, Union
from mcp_sec.core.models import PluginResult, Vulnerability, Severity

async def run_payload_scan(
    mcp_client: Any,
    server_tools: list,
    plugin_info: Dict[str, Any],
    payloads: list,
    check_vuln: Callable[[Optional[str], Optional[Exception], bool], bool],
    vuln_title: str,
    vuln_description: Union[str, Callable[[Any, str, str], str]],
    vuln_severity: "Severity",
    success_message: str = "No issues found.",
    filter_param: Optional[Callable[[str, Dict[str, Any]], bool]] = None
) -> "PluginResult":
    """
    High-level helper that encapsulates the complete run_test boilerplate
    for injection-style payload scans.

    Usage:
        async def run_test(mcp_client, server_tools):
            return await run_payload_scan(
                mcp_client, server_tools, info(),
                payloads=["' OR 1=1 --"],
                check_vuln=lambda text, exc, err: text and "sql" in text.lower(),
                vuln_title="SQL Injection",
                vuln_description=lambda t, p, pl: f"Tool '{t.name}' is vulnerable.",
                vuln_severity=Severity.HIGH,
                success_message="No SQL injection found."
            )
    """
    plugin_name = plugin_info.get("title", plugin_info["name"])

    if not server_tools:
        return PluginResult.from_vulnerabilities(plugin_name, [], "No tools available to test.")

    vulnerabilities = []

    async for tool, prop_name, payload in scan_tool_payloads(
        mcp_client, server_tools, payloads, check_vuln, filter_param=filter_param
    ):
        desc = (
            vuln_description(tool, prop_name, payload)
            if callable(vuln_description)
            else vuln_description
        )
        vulnerabilities.append(Vulnerability(
            title=vuln_title,
            description=desc,
            severity=vuln_severity,
            tool_name=tool.name,
            payload=payload
        ))

    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, success_message)



async def scan_tool_payloads(
    mcp_client: Any,
    server_tools: list,
    payloads: list,
    check_vuln: Callable[[Optional[str], Optional[Exception], bool], bool],
    filter_param: Optional[Callable[[str, Dict[str, Any]], bool]] = None
) -> AsyncGenerator[tuple, None]:
    """
    Iteriert über alle Tools, deren String-Parameter und die angegebenen Payloads.
    Führt das Tool aus und ruft check_vuln auf, um eine Sicherheitslücke zu erkennen.
    Bricht beim ersten Treffer pro Parameter ab (break).
    """
    for tool in server_tools:
        schema = getattr(tool, "inputSchema", None) or {}
        properties = schema.get("properties", {})
        for prop_name, prop_details in properties.items():
            if prop_details.get("type") != "string":
                continue
            if filter_param and not filter_param(prop_name, prop_details):
                continue
                
            for payload in payloads:
                args = build_default_args(properties, {prop_name: payload})
                res_text = None
                exc = None
                is_error = False
                try:
                    res = await mcp_client.call_tool(tool.name, arguments=args)
                    is_error = getattr(res, "isError", False) is True
                    res_text = extract_text_content(res)
                except Exception as e:
                    exc = e
                
                if check_vuln(res_text, exc, is_error):
                    yield tool, prop_name, payload
                    break


def build_default_args(properties: Dict[str, Any], overrides: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Builds a valid argument dictionary from a JSON Schema properties map,
    filling in sensible defaults. Pass 'overrides' to inject specific values.
    """
    args = {}
    overrides = overrides or {}
    
    for p_name, p_details in properties.items():
        if p_name in overrides:
            args[p_name] = overrides[p_name]
        else:
            p_type = p_details.get("type")
            if p_type == "string":
                args[p_name] = "dummy"
            elif p_type in ("number", "integer"):
                args[p_name] = 1
            elif p_type == "boolean":
                args[p_name] = True
            elif p_type == "array":
                args[p_name] = []
            elif p_type == "object":
                args[p_name] = {}
                
    return args

def extract_text_content(result: Any) -> str:
    """
    Extrahiert den gesamten Textinhalt aus einem Tool-Result-Objekt.
    """
    content_str = ""
    if result and hasattr(result, "content"):
        for content in result.content:
            if hasattr(content, "text"):
                content_str += content.text
    return content_str

async def call_tool_safe(mcp_client: Any, tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
    """
    Calls a tool safely and returns the extracted text response.
    Returns None if an error occurs or the server returns isError: true.
    """
    try:
        result = await mcp_client.call_tool(tool_name, arguments=arguments)
        if result and getattr(result, "isError", False) is True:
            return None
        return extract_text_content(result)
    except Exception:
        return None

def is_read_tool(tool_name: str) -> bool:
    """Returns True if the tool name suggests a read operation."""
    name_lower = tool_name.lower()
    return any(kw in name_lower for kw in ["read", "view", "cat", "get_file", "show_file"])

def is_write_tool(tool_name: str) -> bool:
    """Returns True if the tool name suggests a write operation."""
    name_lower = tool_name.lower()
    return any(kw in name_lower for kw in ["write", "create", "save", "dump", "export", "touch"])

def is_delete_tool(tool_name: str) -> bool:
    """Returns True if the tool name suggests a delete operation."""
    name_lower = tool_name.lower()
    return any(kw in name_lower for kw in ["delete", "remove", "rm", "unlink"])

def is_config_env_tool(tool_name: str) -> bool:
    """Returns True if the tool name suggests reading config or environment variables."""
    name_lower = tool_name.lower()
    return any(kw in name_lower for kw in ["env", "config", "log", "settings", "setup", "credential"])
