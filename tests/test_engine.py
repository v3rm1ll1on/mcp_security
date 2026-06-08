import pytest
from unittest.mock import AsyncMock, MagicMock
from mcp_sec.core.engine import Runner
from mcp_sec.core.models import PluginResult, Severity

@pytest.mark.anyio
async def test_runner_tool_filtering():
    # Mock-Objekt für Tool
    def make_mock_tool(name):
        tool = MagicMock()
        tool.name = name
        tool.description = "Test Description"
        tool.inputSchema = {"type": "object", "properties": {}}
        return tool

    # Liste von Mock-Tools (darunter ein sicheres und ein unsicheres)
    mock_tools = [
        make_mock_tool("read_file"),
        make_mock_tool("delete_user"),  # Sollte gefiltert werden
        make_mock_tool("write_file")    # Sollte gefiltert werden
    ]

    # Mock für ClientSession
    session_mock = AsyncMock()
    # list_tools() Rückgabewert mocken
    list_tools_res = MagicMock()
    list_tools_res.tools = mock_tools
    session_mock.list_tools.return_value = list_tools_res

    # Mock-Plugin
    plugin_mock = MagicMock()
    plugin_mock.info.return_value = {
        "name": "Mock Test",
        "allow_destructive": False
    }
    
    # run_test Mock
    run_test_mock = AsyncMock(return_value=PluginResult(plugin_name="Mock Test", success=True, message="OK"))
    plugin_mock.run_test = run_test_mock

    # Mock für stdio_client
    # Da Runner standardmäßig stdio_client aufruft, mocken wir den stdio_client-Context-Manager im Modul
    import mcp_sec.core.engine
    original_stdio_client = mcp_sec.core.engine.stdio_client
    original_ClientSession = mcp_sec.core.engine.ClientSession
    
    try:
        # stdio_client mocken
        stdio_cm_mock = MagicMock()
        stdio_cm_mock.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mcp_sec.core.engine.stdio_client = MagicMock(return_value=stdio_cm_mock)

        # ClientSession mocken
        session_cm_mock = MagicMock()
        session_cm_mock.__aenter__.return_value = session_mock
        mcp_sec.core.engine.ClientSession = MagicMock(return_value=session_cm_mock)

        # Runner erstellen und ausführen
        runner = Runner(
            target="mock_cmd",
            args=[],
            plugins=[plugin_mock],
            allow_destructive=False,
            unsafe_keywords=["delete", "write"]
        )

        results = await runner.run()

        # Überprüfen, ob das Plugin nur mit dem sicheren Tool aufgerufen wurde
        assert len(results) == 1
        assert results[0].success is True
        
        # Das Plugin sollte nur mit "read_file" aufgerufen worden sein
        run_test_mock.assert_called_once()
        passed_tools = run_test_mock.call_args[0][1]
        assert len(passed_tools) == 1
        assert passed_tools[0].name == "read_file"

    finally:
        # Mocks aufräumen
        mcp_sec.core.engine.stdio_client = original_stdio_client
        mcp_sec.core.engine.ClientSession = original_ClientSession

@pytest.mark.anyio
async def test_runner_include_exclude_tools():
    def make_mock_tool(name):
        tool = MagicMock()
        tool.name = name
        tool.inputSchema = {"type": "object", "properties": {}}
        return tool

    mock_tools = [
        make_mock_tool("read_file"),
        make_mock_tool("fetch_url"),
        make_mock_tool("ping_host")
    ]

    session_mock = AsyncMock()
    list_tools_res = MagicMock()
    list_tools_res.tools = mock_tools
    session_mock.list_tools.return_value = list_tools_res

    plugin_mock = MagicMock()
    plugin_mock.info.return_value = {"name": "Mock Test"}
    run_test_mock = AsyncMock(return_value=PluginResult(plugin_name="Mock Test", success=True, message="OK"))
    plugin_mock.run_test = run_test_mock

    import mcp_sec.core.engine
    original_stdio_client = mcp_sec.core.engine.stdio_client
    original_ClientSession = mcp_sec.core.engine.ClientSession
    
    try:
        stdio_cm_mock = MagicMock()
        stdio_cm_mock.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mcp_sec.core.engine.stdio_client = MagicMock(return_value=stdio_cm_mock)

        session_cm_mock = MagicMock()
        session_cm_mock.__aenter__.return_value = session_mock
        mcp_sec.core.engine.ClientSession = MagicMock(return_value=session_cm_mock)

        # exclude_tools testen
        runner = Runner(
            target="mock_cmd",
            args=[],
            plugins=[plugin_mock],
            exclude_tools=["fetch_url"]
        )
        await runner.run()
        passed_tools = run_test_mock.call_args[0][1]
        passed_names = [t.name for t in passed_tools]
        assert "fetch_url" not in passed_names
        assert "read_file" in passed_names
        assert "ping_host" in passed_names

        # include_only_tools testen
        run_test_mock.reset_mock()
        runner = Runner(
            target="mock_cmd",
            args=[],
            plugins=[plugin_mock],
            include_only_tools=["ping_host"]
        )
        await runner.run()
        passed_tools = run_test_mock.call_args[0][1]
        assert len(passed_tools) == 1
        assert passed_tools[0].name == "ping_host"

    finally:
        mcp_sec.core.engine.stdio_client = original_stdio_client
        mcp_sec.core.engine.ClientSession = original_ClientSession

@pytest.mark.anyio
async def test_runner_playbook():
    def make_mock_tool(name):
        tool = MagicMock()
        tool.name = name
        tool.inputSchema = {"type": "object", "properties": {}}
        return tool

    mock_tools = [
        make_mock_tool("read_file"),
        make_mock_tool("fetch_url"),
        make_mock_tool("search_users")
    ]

    session_mock = AsyncMock()
    list_tools_res = MagicMock()
    list_tools_res.tools = mock_tools
    session_mock.list_tools.return_value = list_tools_res

    # Wir erstellen zwei Plugins
    plugin_a = MagicMock()
    plugin_a.info.return_value = {"name": "sqli", "groups": ["owasp"]}
    plugin_a.__name__ = "mcp_sec.plugins.test_sqli"
    run_test_a = AsyncMock(return_value=PluginResult(plugin_name="SQL Injection", success=True, message="OK"))
    plugin_a.run_test = run_test_a

    plugin_b = MagicMock()
    plugin_b.info.return_value = {"name": "path_traversal", "groups": ["owasp", "lfi"]}
    plugin_b.__name__ = "mcp_sec.plugins.test_path_traversal"
    run_test_b = AsyncMock(return_value=PluginResult(plugin_name="Path Traversal", success=True, message="OK"))
    plugin_b.run_test = run_test_b

    import mcp_sec.core.engine
    original_stdio_client = mcp_sec.core.engine.stdio_client
    original_ClientSession = mcp_sec.core.engine.ClientSession
    
    try:
        stdio_cm_mock = MagicMock()
        stdio_cm_mock.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mcp_sec.core.engine.stdio_client = MagicMock(return_value=stdio_cm_mock)

        session_cm_mock = MagicMock()
        session_cm_mock.__aenter__.return_value = session_mock
        mcp_sec.core.engine.ClientSession = MagicMock(return_value=session_cm_mock)

        playbook = {
            "read_file": ["path_traversal"],
            "search_users": ["sqli", "test_another_one"],
            "fetch_url": ["owasp"]  # Per group matching
        }

        runner = Runner(
            target="mock_cmd",
            args=[],
            plugins=[plugin_a, plugin_b],
            playbook=playbook
        )
        await runner.run()

        # sqli sollte für "search_users" (per Name) und "fetch_url" (per Group) aufgerufen worden sein
        run_test_a.assert_called_once()
        passed_a = run_test_a.call_args[0][1]
        assert len(passed_a) == 2
        passed_a_names = [t.name for t in passed_a]
        assert "search_users" in passed_a_names
        assert "fetch_url" in passed_a_names

        # path_traversal sollte für "read_file" (per Name) und "fetch_url" (per Group) aufgerufen worden sein
        run_test_b.assert_called_once()
        passed_b = run_test_b.call_args[0][1]
        assert len(passed_b) == 2
        passed_b_names = [t.name for t in passed_b]
        assert "read_file" in passed_b_names
        assert "fetch_url" in passed_b_names

    finally:
        mcp_sec.core.engine.stdio_client = original_stdio_client
        mcp_sec.core.engine.ClientSession = original_ClientSession

@pytest.mark.anyio
async def test_runner_playbook_wildcards():
    def make_mock_tool(name):
        tool = MagicMock()
        tool.name = name
        tool.inputSchema = {"type": "object", "properties": {}}
        return tool

    mock_tools = [
        make_mock_tool("read_text_file"),
        make_mock_tool("read_media_file"),
        make_mock_tool("write_file")
    ]

    session_mock = AsyncMock()
    list_tools_res = MagicMock()
    list_tools_res.tools = mock_tools
    session_mock.list_tools.return_value = list_tools_res

    plugin_mock = MagicMock()
    plugin_mock.info.return_value = {"name": "path_traversal"}
    plugin_mock.__name__ = "mcp_sec.plugins.test_path_traversal"
    run_test_mock = AsyncMock(return_value=PluginResult(plugin_name="Path Traversal", success=True, message="OK"))
    plugin_mock.run_test = run_test_mock

    import mcp_sec.core.engine
    original_stdio_client = mcp_sec.core.engine.stdio_client
    original_ClientSession = mcp_sec.core.engine.ClientSession
    
    try:
        stdio_cm_mock = MagicMock()
        stdio_cm_mock.__aenter__.return_value = (AsyncMock(), AsyncMock())
        mcp_sec.core.engine.stdio_client = MagicMock(return_value=stdio_cm_mock)

        session_cm_mock = MagicMock()
        session_cm_mock.__aenter__.return_value = session_mock
        mcp_sec.core.engine.ClientSession = MagicMock(return_value=session_cm_mock)

        playbook = {
            "read_*": ["path_traversal"]
        }

        runner = Runner(
            target="mock_cmd",
            args=[],
            plugins=[plugin_mock],
            playbook=playbook
        )
        await runner.run()

        run_test_mock.assert_called_once()
        passed = run_test_mock.call_args[0][1]
        passed_names = [t.name for t in passed]
        assert len(passed_names) == 2
        assert "read_text_file" in passed_names
        assert "read_media_file" in passed_names
        assert "write_file" not in passed_names

    finally:
        mcp_sec.core.engine.stdio_client = original_stdio_client
        mcp_sec.core.engine.ClientSession = original_ClientSession

@pytest.mark.anyio
async def test_integration_mock_server_scan():
    import sys
    import os
    from mcp_sec.core.loader import PluginLoader
    from mcp_sec.core.engine import Runner
    
    plugin_dir = os.path.join(os.path.dirname(__file__), "..", "mcp_sec", "plugins")
    loader = PluginLoader(plugin_dir)
    plugins = loader.load_plugins()
    
    mock_server_path = os.path.join(os.path.dirname(__file__), "..", "mock_server.py")
    
    runner = Runner(
        target=sys.executable,
        args=[mock_server_path],
        plugins=plugins,
        allow_destructive=False,
        unsafe_keywords=[]
    )
    
    results = await runner.run()
    
    # We expect results back from our scan
    assert len(results) > 0
    # Let's verify that SQL Injection, SSRF and Path Traversal flagged issues
    vuln_plugins = [r.plugin_name for r in results if r.vulnerabilities]
    assert "SQL Injection" in vuln_plugins
    assert "Server-Side Request Forgery (SSRF)" in vuln_plugins
    assert "Path Traversal" in vuln_plugins

