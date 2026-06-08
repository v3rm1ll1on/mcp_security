import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp_sec.core.models import PluginResult, Vulnerability, Severity

class Runner:
    def __init__(self, target: str, args: list, plugins: list):
        self.target = target
        self.args = args
        self.plugins = plugins
        
    async def run(self):
        results = []
        
        server_params = StdioServerParameters(
            command=self.target,
            args=self.args,
            env=None
        )
        
        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    
                    for plugin in self.plugins:
                        info = plugin.info()
                        print(f" -> Executing test: {info.get('name', 'Unknown')}")
                        try:
                            # run_test returns a PluginResult object
                            result: PluginResult = await plugin.run_test(session)
                            results.append(result)
                        except Exception as e:
                            results.append(PluginResult(
                                plugin_name=info.get("name", "Unknown"),
                                success=False,
                                message=f"Execution error: {str(e)}"
                            ))
        except Exception as e:
            print(f"[!] Critical error connecting to server: {str(e)}")
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
