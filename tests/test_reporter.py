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
    assert "MCP Security Scan Report" in captured.out
    assert "PASS" in captured.out
    assert "Ping" in captured.out

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

def test_reporter_html_output(capsys):
    results = [
        PluginResult(
            plugin_name="Ping",
            success=False,
            message="Fail",
            vulnerabilities=[
                Vulnerability(
                    title="Timeout",
                    description="Server did not respond",
                    severity=Severity.HIGH,
                    cwe="CWE-89",
                    owasp="A03:2021-Injection"
                )
            ]
        )
    ]
    reporter = Reporter(results, format="html", target="test-command")
    reporter.generate()
    
    captured = capsys.readouterr()
    assert "<!DOCTYPE html>" in captured.out
    assert "test-command" in captured.out
    assert "CWE-89" in captured.out
    assert "A03:2021-Injection" in captured.out

def test_reporter_markdown_output(capsys):
    results = [
        PluginResult(
            plugin_name="Ping",
            success=False,
            message="Fail",
            vulnerabilities=[
                Vulnerability(
                    title="Timeout",
                    description="Server did not respond",
                    severity=Severity.HIGH,
                    cwe="CWE-89",
                    owasp="A03:2021-Injection"
                )
            ]
        )
    ]
    reporter = Reporter(results, format="markdown", target="test-command")
    reporter.generate()
    
    captured = capsys.readouterr()
    assert "# MCP Security Scanner Report" in captured.out
    assert "test-command" in captured.out
    assert "CWE-89" in captured.out
    assert "A03:2021-Injection" in captured.out

def test_reporter_markdown_vuln_count(capsys):
    results = [
        PluginResult(
            plugin_name="Sqli",
            success=False,
            message="Fail",
            vulnerabilities=[
                Vulnerability(title="SQL Injection 1", description="1", severity=Severity.HIGH),
                Vulnerability(title="SQL Injection 2", description="2", severity=Severity.HIGH)
            ]
        ),
        PluginResult(
            plugin_name="Ping",
            success=True,
            message="OK",
            vulnerabilities=[]
        )
    ]
    reporter = Reporter(results, format="markdown", target="test-command")
    reporter.generate()
    
    captured = capsys.readouterr()
    assert "## Vulnerabilities Found (2)" in captured.out

