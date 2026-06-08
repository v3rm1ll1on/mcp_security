import json
import dataclasses
from enum import Enum
from mcp_sec.core.models import PluginResult

class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)

class Reporter:
    def __init__(self, results: list[PluginResult], format: str = "text"):
        self.results = results
        self.format = format
        
    def generate(self):
        if self.format == "json":
            dict_results = [dataclasses.asdict(r) for r in self.results]
            print(json.dumps(dict_results, indent=2, cls=EnumEncoder))
        else:
            print("\n" + "="*50)
            print(" MCP SECURITY SCAN REPORT ")
            print("="*50)
            for res in self.results:
                status = "[OK]" if res.success else "[FAIL]"
                print(f"{status} {res.plugin_name}: {res.message}")
                for vuln in res.vulnerabilities:
                    print(f"    -> [VULN - {vuln.severity.value}] {vuln.title}")
                    print(f"       Tool: {vuln.tool_name} | Payload: {vuln.payload}")
                    print(f"       Desc: {vuln.description}")
            print("="*50 + "\n")
