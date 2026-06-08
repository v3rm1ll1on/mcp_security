import uuid
from mcp_sec.core.models import PluginResult, Vulnerability, Severity
from mcp_sec.core.utils import build_default_args, is_write_tool, is_delete_tool

def info():
    return {
        "name": "arbitrary_file_write",
        "title": "Arbitrary File Write (Path Traversal)",
        "description": "Attempts to write benign test files using path traversal payloads.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "write"],
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info().get("title", info()["name"])
    if not server_tools:
        return PluginResult.from_vulnerabilities(plugin_name, [], "No tools available to test.")
        
    vulnerabilities = []
    
    # Ethisch korrekter Inhalt und eindeutiger Dateiname
    test_id = str(uuid.uuid4())[:8]
    test_filename = f"mcp_sec_write_test_{test_id}.txt"
    test_content = "MCP Security Scanner Write Test. Safe to delete."
    
    # Traversal-Payloads für Schreiboperationen
    payloads = [
        f"../../{test_filename}",
        f"../{test_filename}"
    ]
    
    for tool in server_tools:
        schema = tool.inputSchema or {}
        properties = schema.get("properties", {})
        
        # Finde Parameter für Pfad und Inhalt
        path_param = None
        content_param = None
        
        for prop_name, prop_details in properties.items():
            prop_name_lower = prop_name.lower()
            if prop_name_lower in ["path", "filepath", "filename", "file", "dest", "destination"] and prop_details.get("type") == "string":
                path_param = prop_name
            elif prop_name_lower in ["content", "data", "text", "body"] and prop_details.get("type") == "string":
                content_param = prop_name
                
        # Wenn wir ein Schreib-Tool und einen Pfad-Parameter gefunden haben
        if is_write_tool(tool.name) and path_param:
            for payload in payloads:
                overrides = {path_param: payload}
                if content_param:
                    overrides[content_param] = test_content
                    
                args = build_default_args(properties, overrides)
                            
                try:
                    # Führe Schreiboperation aus
                    result = await mcp_client.call_tool(tool.name, arguments=args)
                    
                    # Wenn der Aufruf erfolgreich war (kein Fehler), liegt eine Sicherheitslücke vor
                    if result and not result.isError:
                        vulnerabilities.append(Vulnerability(
                            title="Arbitrary File Write / Path Traversal Write",
                            description=f"Tool '{tool.name}' successfully wrote a test file outside the workspace directory via traversal path '{payload}'.",
                            severity=Severity.HIGH,
                            tool_name=tool.name,
                            payload=payload
                        ))
                        
                        # Ethisches Cleanup: Versuche die erstellte Datei wieder zu löschen, falls ein Lösch-Tool existiert
                        await try_cleanup(mcp_client, server_tools, payload)
                        break # Ein Treffer pro Tool reicht
                        
                except Exception:
                    pass
                    
    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No arbitrary file write vulnerabilities detected.")

async def try_cleanup(mcp_client, server_tools, payload):
    """Versucht, die geschriebene Testdatei über vorhandene Lösch-Tools zu entfernen."""
    for tool in server_tools:
        if is_delete_tool(tool.name):
            schema = tool.inputSchema or {}
            properties = schema.get("properties", {})
            path_param = None
            for prop_name in properties.keys():
                if prop_name.lower() in ["path", "filepath", "filename", "file"]:
                    path_param = prop_name
                    break
            if path_param:
                try:
                    await mcp_client.call_tool(tool.name, arguments={path_param: payload})
                except Exception:
                    pass
