import os
import tempfile
import pytest
from mcp_sec.core.loader import PluginLoader

def test_loader_empty_dir():
    with tempfile.TemporaryDirectory() as tempdir:
        loader = PluginLoader(tempdir)
        plugins = loader.load_plugins()
        assert len(plugins) == 0

def test_loader_loads_valid_plugin():
    with tempfile.TemporaryDirectory() as tempdir:
        plugin_code = """
from mcp_sec.core.models import PluginResult, Severity

def info():
    return {
        "name": "TestPlugin", 
        "description": "Test", 
        "severity": Severity.LOW,
        "author": "Test",
        "contact": "Test",
        "version": "1.0"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    return PluginResult(plugin_name="TestPlugin", success=True, message="Success")
"""
        with open(os.path.join(tempdir, "test_plugin.py"), "w") as f:
            f.write(plugin_code)
            
        loader = PluginLoader(tempdir)
        plugins = loader.load_plugins()
        assert len(plugins) == 1
        assert plugins[0].info()["name"] == "TestPlugin"

def test_loader_ignores_invalid_plugin():
    with tempfile.TemporaryDirectory() as tempdir:
        plugin_code = """
def info():
    return {"name": "InvalidPlugin"}
"""
        with open(os.path.join(tempdir, "invalid_plugin.py"), "w") as f:
            f.write(plugin_code)
            
        loader = PluginLoader(tempdir)
        plugins = loader.load_plugins()
        assert len(plugins) == 0

def test_loader_invalid_names():
    # Test spaces, dots, hyphens, and numbers which should all be ignored
    for invalid_name in ["Invalid Space", "plugin.name", "plugin-name", "plugin123"]:
        with tempfile.TemporaryDirectory() as tempdir:
            plugin_code = f"""
from mcp_sec.core.models import PluginResult, Severity

def info():
    return {{
        "name": "{invalid_name}", 
        "description": "Test", 
        "severity": Severity.LOW,
        "author": "Test",
        "contact": "Test",
        "version": "1.0"
    }}

async def run_test(mcp_client, server_tools) -> PluginResult:
    return PluginResult(plugin_name="Test", success=True, message="Success")
"""
            with open(os.path.join(tempdir, "invalid_plugin.py"), "w") as f:
                f.write(plugin_code)
                
            loader = PluginLoader(tempdir)
            plugins = loader.load_plugins()
            assert len(plugins) == 0

def test_loader_exclude_plugins():
    with tempfile.TemporaryDirectory() as tempdir:
        plugin_code = """
from mcp_sec.core.models import PluginResult, Severity

def info():
    return {
        "name": "excluded_plugin", 
        "description": "Test", 
        "severity": Severity.LOW,
        "author": "Test",
        "contact": "Test",
        "version": "1.0"
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    return PluginResult(plugin_name="excluded_plugin", success=True, message="Success")
"""
        with open(os.path.join(tempdir, "excluded_plugin.py"), "w") as f:
            f.write(plugin_code)
            
        loader = PluginLoader(tempdir, exclude_plugins=["excluded_plugin"])
        plugins = loader.load_plugins()
        assert len(plugins) == 1
        assert plugins[0]._excluded is True
