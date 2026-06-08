import asyncio
import logging
import os
import fnmatch
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp_sec.core.models import PluginResult, Vulnerability, Severity

logger = logging.getLogger("mcp_sec")

# Patterns for env var keys that should never be forwarded to the MCP target process
_SECRET_ENV_PATTERNS = [
    "*SECRET*", "*API_KEY*", "*APIKEY*", "*PASSWORD*", "*PASSWD*",
    "*TOKEN*", "*PRIVATE_KEY*", "*CREDENTIAL*", "*AUTH*",
]

def _sanitize_env(env: dict) -> dict:
    """Remove secret-looking keys from an env dict before passing to a subprocess."""
    safe = {}
    for k, v in env.items():
        if any(fnmatch.fnmatch(k.upper(), pat) for pat in _SECRET_ENV_PATTERNS):
            logger.debug("Stripped sensitive env var '%s' from subprocess environment.", k)
        else:
            safe[k] = v
    return safe

class Runner:
    def __init__(self, target: str, args: list, plugins: list, env: dict = None,
                 allow_destructive: bool = False, unsafe_keywords: list = None,
                 exclude_tools: list = None, include_only_tools: list = None,
                 playbook: dict = None, call_timeout: float = 10.0,
                 max_concurrent_calls: int = 5):
        self.target = target
        self.args = args
        self.plugins = plugins
        self.env = env
        self.allow_destructive = allow_destructive
        self.call_timeout = call_timeout
        self.semaphore = asyncio.Semaphore(max_concurrent_calls)
        self.unsafe_keywords = set(unsafe_keywords) if unsafe_keywords is not None else {
            "write", "delete", "remove", "create", "update", "patch", "put", 
            "destroy", "rm", "mkdir", "upload", "send", "publish", "insert", 
            "add", "set", "modify", "save", "append", "touch", "post"
        }
        self.exclude_tools = exclude_tools or []
        self.include_only_tools = include_only_tools or []
        self.playbook = playbook or {}
        
    async def run(self, on_discovery=None):
        results = []
        
        # Merge os.environ with user-supplied variables (PATH etc.), then strip secrets
        merged_env = _sanitize_env(os.environ.copy())
        if self.env:
            merged_env.update(self.env)
            
        server_params = StdioServerParameters(
            command=self.target,
            args=self.args,
            env=merged_env
        )
        
        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    
                    # Discovery Phase: Einmal Tools fetchen und durchreichen
                    tools_response = await session.list_tools()
                    server_tools = tools_response.tools if tools_response and hasattr(tools_response, "tools") else []
                    
                    if on_discovery:
                        on_discovery(server_tools)
                    
                    for plugin in self.plugins:
                        info = plugin.info()
                        plugin_name = info.get("title", info.get("name", "Unknown"))
                        
                        # 1. Check if plugin is excluded via configuration
                        if getattr(plugin, "_excluded", False) is True:
                            results.append(PluginResult(
                                plugin_name=plugin_name,
                                success=True,
                                message="Excluded by configuration.",
                                skipped=True
                            ))
                            continue
                            
                        # 2. Filter: include_only / exclude per tool name
                        temp_tools = server_tools
                        if self.include_only_tools:
                            temp_tools = [t for t in temp_tools if t.name in self.include_only_tools]
                        if self.exclude_tools:
                            temp_tools = [t for t in temp_tools if t.name not in self.exclude_tools]
                            
                        # 3. Filter: Destruktive Tools herausfiltern (falls nicht global oder per Plugin erlaubt)
                        if self.allow_destructive or info.get("allow_destructive", False):
                            filtered_tools = temp_tools
                        else:
                            filtered_tools = [
                                t for t in temp_tools
                                if not any(kw in t.name.lower() for kw in self.unsafe_keywords)
                            ]
                            
                        # 4. Filter: Playbook-spezifische Zuweisung (Unterstützung für Glob-Wildcards bei Tool-Namen)
                        if self.playbook:
                            playbook_filtered = []
                            for t in filtered_tools:
                                # Finde alle Schlüssel im Playbook, die auf t.name zutreffen
                                matching_patterns = [
                                    pat for pat in self.playbook 
                                    if fnmatch.fnmatch(t.name, pat)
                                ]
                                for pat in matching_patterns:
                                    allowed = self.playbook[pat]
                                    plugin_id = info.get("name")
                                    plugin_module = plugin.__name__.split(".")[-1]
                                    plugin_groups = info.get("groups", [])
                                    if not isinstance(plugin_groups, list):
                                        plugin_groups = [plugin_groups]
                                        
                                    if (
                                        "*" in allowed or 
                                        plugin_id in allowed or 
                                        plugin_module in allowed or 
                                        any(g in allowed for g in plugin_groups)
                                    ):
                                        playbook_filtered.append(t)
                                        break  # Ein passendes Pattern reicht aus
                            filtered_tools = playbook_filtered
                            
                        # 5. Check if plugin was skipped due to empty tools (and it's not a utility plugin)
                        is_utility = "utility" in info.get("groups", [])
                        if not filtered_tools and not is_utility:
                            if not server_tools:
                                reason = "No tools available on target."
                            elif not temp_tools:
                                reason = "All tools excluded by tool configuration."
                            elif self.playbook:
                                reason = "No tools allowed for this plugin in playbook."
                            else:
                                reason = "All matching tools restricted (destructive)."
                                
                            results.append(PluginResult(
                                plugin_name=plugin_name,
                                success=True,
                                message=reason,
                                skipped=True
                            ))
                            continue
                        
                        try:
                            # run_test returns a PluginResult object
                            result: PluginResult = await plugin.run_test(session, filtered_tools)
                            # CWE and OWASP metadata propagation from plugin info
                            p_cwe = info.get("cwe")
                            p_owasp = info.get("owasp")
                            if p_cwe or p_owasp:
                                for vuln in result.vulnerabilities:
                                    if vuln.cwe is None:
                                        vuln.cwe = p_cwe
                                    if vuln.owasp is None:
                                        vuln.owasp = p_owasp
                            results.append(result)
                        except Exception as e:
                            logger.error(
                                "Plugin '%s' raised an unhandled exception: %s",
                                plugin_name, e, exc_info=True
                            )
                            results.append(PluginResult(
                                plugin_name=info.get("title", info.get("name", "Unknown")),
                                success=False,
                                message=f"Execution error: {str(e)}"
                            ))
        except Exception as e:
            logger.critical("Critical error connecting to server '%s': %s", self.target, e)
            results.append(PluginResult(
                plugin_name="Engine",
                success=False,
                message=f"Failed to connect to '{self.target}'. Details: {str(e)}",
                vulnerabilities=[
                    Vulnerability(
                        title="Connection Error",
                        description=f"Could not establish MCP connection to target.",
                        severity=Severity.CRITICAL
                    )
                ]
            ))
            
        return results
