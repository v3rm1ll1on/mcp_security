import pytest
from unittest.mock import MagicMock, AsyncMock
from mcp_sec.core.utils import (
    build_default_args,
    extract_text_content,
    call_tool_safe,
    is_read_tool,
    is_write_tool,
    is_delete_tool,
    is_config_env_tool,
    scan_tool_payloads
)

def test_build_default_args():
    properties = {
        "str_param": {"type": "string"},
        "int_param": {"type": "integer"},
        "num_param": {"type": "number"},
        "bool_param": {"type": "boolean"},
        "arr_param": {"type": "array"},
        "obj_param": {"type": "object"}
    }
    
    args = build_default_args(properties, {"str_param": "override_value"})
    assert args["str_param"] == "override_value"
    assert args["int_param"] == 1
    assert args["num_param"] == 1
    assert args["bool_param"] is True
    assert args["arr_param"] == []
    assert args["obj_param"] == {}

def test_extract_text_content():
    content1 = MagicMock()
    content1.text = "Hello "
    content2 = MagicMock()
    content2.text = "World"
    
    result = MagicMock()
    result.content = [content1, content2]
    
    assert extract_text_content(result) == "Hello World"
    assert extract_text_content(None) == ""

@pytest.mark.anyio
async def test_call_tool_safe():
    mock_content = MagicMock()
    mock_content.text = "Success Text"
    
    call_res = MagicMock()
    call_res.isError = False
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    result = await call_tool_safe(mcp_client, "some_tool", {})
    assert result == "Success Text"
    
    # Error state
    error_res = MagicMock()
    error_res.isError = True
    mcp_client.call_tool.return_value = error_res
    
    result = await call_tool_safe(mcp_client, "some_tool", {})
    assert result is None

def test_is_read_tool():
    assert is_read_tool("read_file") is True
    assert is_read_tool("view_config") is True
    assert is_read_tool("write_file") is False

def test_is_write_tool():
    assert is_write_tool("save_config") is True
    assert is_write_tool("touch_file") is True
    assert is_write_tool("read_file") is False

def test_is_delete_tool():
    assert is_delete_tool("delete_user") is True
    assert is_delete_tool("rm_dir") is True
    assert is_delete_tool("read_file") is False

def test_is_config_env_tool():
    assert is_config_env_tool("get_env") is True
    assert is_config_env_tool("read_config") is True
    assert is_config_env_tool("read_file") is False

@pytest.mark.anyio
async def test_scan_tool_payloads():
    # Mock a tool
    tool = MagicMock()
    tool.name = "test_tool"
    tool.inputSchema = {
        "type": "object",
        "properties": {
            "str_param": {"type": "string"},
            "int_param": {"type": "integer"}
        }
    }
    
    # Mock return value
    mock_content = MagicMock()
    mock_content.text = "vulnerable_response"
    
    call_res = MagicMock()
    call_res.content = [mock_content]
    
    mcp_client = AsyncMock()
    mcp_client.call_tool.return_value = call_res
    
    def check_vuln(res_text, exc, is_error):
        return res_text == "vulnerable_response"
        
    results = []
    async for t, prop, payload in scan_tool_payloads(mcp_client, [tool], ["payload1"], check_vuln):
        results.append((t, prop, payload))
        
    assert len(results) == 1
    assert results[0][1] == "str_param"
    assert results[0][2] == "payload1"

