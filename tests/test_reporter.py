import io
import sys
import json
from mcp_sec.core.reporter import Reporter
from mcp_sec.core.models import PluginResult, Vulnerability, Severity

def test_reporter_text_output(capsys):
    results = [
        PluginResult(
            plugin_name="Ping",
            success=True,
            message="OK",
            vulnerabilities=[]
        )
    ]
    reporter = Reporter(results, format="text")
    reporter.generate()
    
    captured = capsys.readouterr()
    assert "MCP SECURITY SCAN REPORT" in captured.out
    assert "[OK] Ping: OK" in captured.out

def test_reporter_json_output(capsys):
    results = [
        PluginResult(
            plugin_name="Ping",
            success=False,
            message="Fail",
            vulnerabilities=[
                Vulnerability(
                    title="Timeout",
                    description="Server did not respond",
                    severity=Severity.HIGH
                )
            ]
        )
    ]
    reporter = Reporter(results, format="json")
    reporter.generate()
    
    captured = capsys.readouterr()
    output_data = json.loads(captured.out)
    assert len(output_data) == 1
    assert output_data[0]["success"] is False
    assert output_data[0]["plugin_name"] == "Ping"
    assert len(output_data[0]["vulnerabilities"]) == 1
    assert output_data[0]["vulnerabilities"][0]["severity"] == "HIGH"
