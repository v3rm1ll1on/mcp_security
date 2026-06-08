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

async def run_test(mcp_client) -> PluginResult:
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
