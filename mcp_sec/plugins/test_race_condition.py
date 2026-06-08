from mcp_sec.core.models import PluginResult, Vulnerability, Severity
from mcp_sec.core.utils import build_default_args, is_write_tool
import asyncio

def info():
    return {
        "name": "race_condition",
        "title": "Race Condition (Concurrency)",
        "description": "Tests if tools are vulnerable to race conditions by sending multiple concurrent requests.",
        "severity": Severity.HIGH,
        "author": "Marc Stöcker",
        "contact": "v3rm1ll1on@proton.me",
        "version": "1.0.0",
        "allow_destructive": True,
        "groups": ["owasp", "concurrency"],
        "cwe": "CWE-362",
        "owasp": "A04:2021-Insecure Design"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    plugin_name = info()["title"]
    vulnerabilities = []

    for tool in server_tools:
        # Nur potenziell zustandsändernde Tools prüfen, um Zeit zu sparen
        if not is_write_tool(tool.name):
            continue

        schema = getattr(tool, "inputSchema", {})
        properties = schema.get("properties", {})
        args = build_default_args(properties)
        
        # Sende 15 Anfragen absolut gleichzeitig
        num_requests = 15
        tasks = []
        for _ in range(num_requests):
            tasks.append(mcp_client.call_tool(tool.name, arguments=args))
            
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Auswertung: Zähle Timeouts, Exceptions oder serverseitige Fehler
            error_count = sum(1 for r in results if isinstance(r, Exception) or getattr(r, "isError", False) is True)
            success_count = num_requests - error_count
            
            # Wenn einige durchgehen und andere fehlschlagen, ist das oft ein Indikator für Concurrency-Probleme
            # Oder wenn wir DB Lock Fehler sehen
            if 0 < error_count < num_requests:
                db_lock_errors = [r for r in results if isinstance(r, Exception) and "lock" in str(r).lower()]
                
                desc = f"Tool '{tool.name}' exhibited unstable behavior under concurrency. {error_count} out of {num_requests} requests failed, indicating a potential race condition or missing thread safety."
                if db_lock_errors:
                    desc += " Found explicit database lock errors."
                
                vulnerabilities.append(Vulnerability(
                    title="Race Condition",
                    description=desc,
                    severity=Severity.HIGH,
                    tool_name=tool.name,
                    payload=f"[Concurrent requests: {num_requests}]"
                ))
            elif error_count == num_requests:
                 # Alle sind fehlgeschlagen -> Eventuell kompletter Deadlock oder Service Crash
                 vulnerabilities.append(Vulnerability(
                    title="Concurrency Denial of Service",
                    description=f"Tool '{tool.name}' failed completely when handling {num_requests} concurrent requests.",
                    severity=Severity.HIGH,
                    tool_name=tool.name,
                    payload=f"[Concurrent requests: {num_requests}]"
                ))
        except Exception as e:
            vulnerabilities.append(Vulnerability(
                title="Race Condition (Crash)",
                description=f"Tool '{tool.name}' crashed the connection when handling concurrent requests: {e}",
                severity=Severity.HIGH,
                tool_name=tool.name,
                payload=f"[Concurrent requests: {num_requests}]"
            ))

    return PluginResult.from_vulnerabilities(plugin_name, vulnerabilities, "No race conditions detected.")
