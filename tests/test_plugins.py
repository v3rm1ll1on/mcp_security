import pytest
from unittest.mock import AsyncMock, MagicMock
from mcp_sec.core.models import Severity

# Import plugins directly
import mcp_sec.plugins.test_command_injection as cmd_injection_plugin
import mcp_sec.plugins.test_path_traversal as path_traversal_plugin
import mcp_sec.plugins.test_ssrf as ssrf_plugin
import mcp_sec.plugins.test_sqli as sqli_plugin
import mcp_sec.plugins.test_secrets_exposure as secrets_exposure_plugin
import mcp_sec.plugins.test_arbitrary_file_write as arbitrary_file_write_plugin

# Helper to mock a Tool schema
def make_mock_tool(name, properties=None):
    tool = MagicMock()
    tool.name = name
    tool.description = "Test tool description"
    tool.inputSchema = {
        "type": "object",
        "properties": properties or {}
    }
    return tool

# --- Command Injection Plugin Tests ---

@pytest.mark.anyio
async def test_cmd_injection_vulnerable():
    tool = make_mock_tool("run_cmd", {"cmd": {"type": "string"}})
    
    # Mock return value of call_tool indicating successful execution (contains 'root')
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = "root:x:0:0:root:/root:/bin/bash"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await cmd_injection_plugin.run_test(mcp_client, [tool])
    assert result.success is False
    assert len(result.vulnerabilities) > 0
    assert result.vulnerabilities[0].title == "Command Injection"

@pytest.mark.anyio
async def test_cmd_injection_safe():
    tool = make_mock_tool("run_cmd", {"cmd": {"type": "string"}})
    
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = "Error: Invalid command format"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await cmd_injection_plugin.run_test(mcp_client, [tool])
    assert result.success is True
    assert len(result.vulnerabilities) == 0

# --- Path Traversal Plugin Tests ---

@pytest.mark.anyio
async def test_path_traversal_vulnerable():
    tool = make_mock_tool("read_file", {"filepath": {"type": "string"}})
    
    # Mock return value containing /etc/passwd contents
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = "root:x:0:0:root:/root:/bin/bash"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await path_traversal_plugin.run_test(mcp_client, [tool])
    assert result.success is False
    assert len(result.vulnerabilities) > 0
    assert "Path Traversal" in result.vulnerabilities[0].title

@pytest.mark.anyio
async def test_path_traversal_safe():
    tool = make_mock_tool("read_file", {"filepath": {"type": "string"}})
    
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = "Permission denied or File not found"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await path_traversal_plugin.run_test(mcp_client, [tool])
    assert result.success is True
    assert len(result.vulnerabilities) == 0

# --- SSRF Plugin Tests ---

@pytest.mark.anyio
async def test_ssrf_vulnerable_via_exception():
    tool = make_mock_tool("fetch_url", {"url": {"type": "string"}})
    
    mcp_client = AsyncMock()
    # SSRF indicator in exception string
    mcp_client.call_tool.side_effect = Exception("Failed to fetch: Connection refused")
    
    result = await ssrf_plugin.run_test(mcp_client, [tool])
    assert result.success is False
    assert len(result.vulnerabilities) > 0
    assert "SSRF" in result.vulnerabilities[0].title

@pytest.mark.anyio
async def test_ssrf_safe():
    tool = make_mock_tool("fetch_url", {"url": {"type": "string"}})
    
    mcp_client = AsyncMock()
    # Custom block message returned cleanly
    mock_content = MagicMock()
    mock_content.type = "text"
    mock_content.text = "Error: Access to local IP addresses is blocked."
    
    call_res = MagicMock()
    call_res.isError = True
    call_res.content = [mock_content]
    mcp_client.call_tool.return_value = call_res
    
    result = await ssrf_plugin.run_test(mcp_client, [tool])
    assert result.success is True
    assert len(result.vulnerabilities) == 0

# --- SQL Injection Plugin Tests ---

@pytest.mark.anyio
async def test_sqli_vulnerable():
    tool = make_mock_tool("get_user", {"username": {"type": "string"}})
    
    mock_content = MagicMock()
    mock_content.text = "Database error: sqlite3.OperationalError: unrecognized token: ''"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await sqli_plugin.run_test(mcp_client, [tool])
    assert result.success is False
    assert len(result.vulnerabilities) > 0
    assert result.vulnerabilities[0].title == "SQL Injection"

@pytest.mark.anyio
async def test_sqli_safe():
    tool = make_mock_tool("get_user", {"username": {"type": "string"}})
    
    mock_content = MagicMock()
    mock_content.text = "User not found"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await sqli_plugin.run_test(mcp_client, [tool])
    assert result.success is True
    assert len(result.vulnerabilities) == 0

# --- Secrets Exposure Plugin Tests ---

@pytest.mark.anyio
async def test_secrets_exposure_vulnerable():
    tool = make_mock_tool("show_env", {"var": {"type": "string"}})
    
    mock_content = MagicMock()
    mock_content.text = "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await secrets_exposure_plugin.run_test(mcp_client, [tool])
    assert result.success is False
    assert len(result.vulnerabilities) > 0
    assert "Secrets & Credentials Exposure" in result.vulnerabilities[0].title

@pytest.mark.anyio
async def test_secrets_exposure_safe():
    tool = make_mock_tool("show_env", {"var": {"type": "string"}})
    
    mock_content = MagicMock()
    mock_content.text = "All environment variables are hidden."
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await secrets_exposure_plugin.run_test(mcp_client, [tool])
    assert result.success is True
    assert len(result.vulnerabilities) == 0

# --- Arbitrary File Write Plugin Tests ---

@pytest.mark.anyio
async def test_arbitrary_file_write_vulnerable():
    tool = make_mock_tool("save_file", {"path": {"type": "string"}, "content": {"type": "string"}})
    
    call_res = MagicMock()
    call_res.isError = False
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await arbitrary_file_write_plugin.run_test(mcp_client, [tool])
    assert result.success is False
    assert len(result.vulnerabilities) > 0
    assert "Arbitrary File Write" in result.vulnerabilities[0].title

@pytest.mark.anyio
async def test_arbitrary_file_write_safe():
    tool = make_mock_tool("save_file", {"path": {"type": "string"}, "content": {"type": "string"}})
    
    call_res = MagicMock()
    call_res.isError = True  # Tool returns error on directory traversal
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await arbitrary_file_write_plugin.run_test(mcp_client, [tool])
    assert result.success is True
    assert len(result.vulnerabilities) == 0

