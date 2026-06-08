import re
from mcp_sec.core.models import PluginResult, Vulnerability, Severity
from mcp_sec.core.utils import build_default_args, call_tool_safe, is_read_tool, is_config_env_tool

def info():
    return {
        "name": "secrets_exposure",
        "title": "Secrets & Credentials Exposure",
        "description": "Scans tool responses for exposed secrets, private keys, or credentials.",
        "severity": Severity.CRITICAL,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "groups": ["owasp", "leak"],
        "cwe": "CWE-200",
        "owasp": "A02:2021-Cryptographic Failures"
    }

SECRET_PATTERNS = {
    "PEM Private Key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASCA|ASIA)[0-9A-Z]{16}\b"),
    "Generic Secret/Password": re.compile(r"\b(api_key|apikey|secret|password|passwd|token)\b\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\/]{8,64})['\"]", re.IGNORECASE),
    "Database Connection String": re.compile(r"\b[a-zA-Z0-9\+]+://[^:]+:[^@]+@[a-zA-Z0-9\.-]+", re.IGNORECASE)
}

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info().get("title", info()["name"])
    if not server_tools:
        return PluginResult.from_vulnerabilities(plugin_name, [], "No tools available to test.")
        
    vulnerabilities = []
    
    # Sensible Dateinamen zum Auslesen bei File-Read-Tools
    file_payloads = [".env", "config.json", "credentials.json"]
    
    for tool in server_tools:
        schema = tool.inputSchema or {}
        properties = schema.get("properties", {})
        
        # Bestimme, wie das Tool aufgerufen werden soll
        calls_to_make = []
        
        # Fall A: File-Reading Tools (z.B. read_file, view_file, cat)
        path_param = None
        for prop_name, prop_details in properties.items():
            if prop_name.lower() in ["path", "filepath", "filename", "file"] and prop_details.get("type") == "string":
                path_param = prop_name
                break
                
        if is_read_tool(tool.name) and path_param:
            for payload in file_payloads:
                args = build_default_args(properties, {path_param: payload})
                calls_to_make.append((args, f"reading file '{payload}'"))
                
        # Fall B: Config/Env/Logs Tools (z.B. show_env, get_logs, get_config)
        elif is_config_env_tool(tool.name):
            args = build_default_args(properties)
            calls_to_make.append((args, "retrieving configuration/environment"))
            
        # Führe die Aufrufe durch und scanne die Antworten
        for args, description in calls_to_make:
            content_str = await call_tool_safe(mcp_client, tool.name, args)
            if content_str:
                for secret_type, pattern in SECRET_PATTERNS.items():
                    match = pattern.search(content_str)
                    if match:
                        vulnerabilities.append(Vulnerability(
                            title="Secrets & Credentials Exposure",
                            description=f"Tool '{tool.name}' exposed a potential {secret_type} when {description}.",
                            severity=Severity.CRITICAL,
                            tool_name=tool.name,
                            payload=str(args)
                        ))
                        break # Ein Treffer pro Tool-Aufruf reicht
                
    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No exposed secrets or credentials detected.")
