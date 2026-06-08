# Plugin Development Guide

The MCP Security Scanner is designed to be highly extensible. Writing a new test is as simple as creating a new Python file in the `mcp_sec/plugins/` directory.

## Requirements

Every plugin must define two things:
1. An `info()` function returning metadata (names must be unique and contain **only letters and underscores**).
2. An `async def run_test(mcp_client, server_tools)` function returning a `PluginResult`.

## Minimal Structure

For injection-style tests (payload → scan response), the entire plugin is just:

```python
from mcp_sec.core.models import PluginResult, Severity
from mcp_sec.core.utils import run_payload_scan

def info():
    return {
        "name": "my_custom_test",            # Unique identifier — only letters and underscores
        "title": "My Custom Test",           # Human-readable display title
        "description": "Tests for XYZ vulnerabilities.",
        "severity": Severity.MEDIUM,
        "author": "Your Name",
        "contact": "your.email@example.com",
        "version": "1.0.0",
        "groups": ["owasp", "custom"],       # Logical groupings for playbook/filtering
        "cwe": "CWE-999",                    # Optional: standardized CWE identifier
        "owasp": "A03:2021-Injection",       # Optional: standardized OWASP category
        "allow_destructive": False           # Optional: set True to test state-modifying tools
    }

async def run_test(mcp_client, server_tools) -> PluginResult:
    payloads = ["<your>", "<payloads>"]

    def check_vuln(res_text, exc, is_error=False):
        """Return True if the response indicates a vulnerability."""
        return bool(res_text and "indicator_of_compromise" in res_text)

    return await run_payload_scan(
        mcp_client, server_tools, info(),
        payloads=payloads,
        check_vuln=check_vuln,
        vuln_title="Found XYZ",
        vuln_description=lambda t, p, pl: f"Tool '{t.name}' is vulnerable via payload '{pl}'.",
        vuln_severity=Severity.MEDIUM,
        success_message="No issues found."
    )
```

---

## Core Helpers (`mcp_sec.core.utils`)

All helpers are importable from `mcp_sec.core.utils`. They form a **three-level hierarchy** — use the highest level that fits your plugin:

```
run_payload_scan      ← Level 1: full boilerplate handled (recommended for injection tests)
  └── scan_tool_payloads  ← Level 2: loop handled, you build Vulnerability objects
        └── mcp_client.call_tool()  ← Level 3: full manual control
```

---

### `run_payload_scan` *(recommended)*

Handles **everything**: the early-return guard, the tool/parameter/payload loop, building `Vulnerability` objects, and returning a `PluginResult`. You only supply the detection logic.

```python
from mcp_sec.core.utils import run_payload_scan

return await run_payload_scan(
    mcp_client, server_tools, info(),
    payloads=["<payload1>", "<payload2>"],
    check_vuln=check_vuln,              # (res_text, exc, is_error) -> bool
    vuln_title="XYZ Vulnerability",
    vuln_description=lambda t, p, pl: f"Tool '{t.name}' is vulnerable via '{pl}'.",
    vuln_severity=Severity.HIGH,
    success_message="No issues found.",
    filter_param=None                   # optional: (prop_name, prop_details) -> bool
)
```

| Parameter | Type | Description |
|---|---|---|
| `payloads` | `list` | Strings injected into each string parameter |
| `check_vuln` | `Callable` | Returns `True` if the response indicates a vulnerability |
| `vuln_title` | `str` | Title field of the `Vulnerability` object |
| `vuln_description` | `str` or `Callable(tool, prop_name, payload) -> str` | Static string or dynamic description factory |
| `vuln_severity` | `Severity` | Severity level of the finding |
| `success_message` | `str` | Message when no vulnerabilities are found |
| `filter_param` | `Callable` or `None` | Restricts which parameters are tested (e.g. only `url`, `host`) |

---

### `scan_tool_payloads` *(lower-level)*

Use this when `run_payload_scan` is too opinionated — e.g. when you need multiple `Vulnerability` types per tool, or custom accumulation logic. Yields `(tool, prop_name, payload)` tuples on hits.

```python
from mcp_sec.core.utils import scan_tool_payloads

async for tool, prop_name, payload in scan_tool_payloads(
    mcp_client, server_tools, payloads, check_vuln,
    filter_param=None   # optional: (prop_name, prop_details) -> bool
):
    vulnerabilities.append(Vulnerability(...))
```

**`check_vuln` signature:**
```python
def check_vuln(res_text: str | None, exc: Exception | None, is_error: bool = False) -> bool:
    ...
```

| Argument | Description |
|---|---|
| `res_text` | Raw text content of the tool response, or `None` on exception |
| `exc` | The exception object if the call raised one, otherwise `None` |
| `is_error` | `True` if the MCP server returned `isError: true` in the response |

**`filter_param`** (optional): Restricts which parameters are tested:
```python
suspect = {"url", "host", "target"}
def filter_param(prop_name, prop_details):
    return prop_name.lower() in suspect
```

---


### `build_default_args`

Builds a valid argument dictionary from a JSON Schema `properties` map, filling in sensible defaults for all types. Pass `overrides` to inject specific values.

```python
from mcp_sec.core.utils import build_default_args

args = build_default_args(tool.inputSchema["properties"], {"path": "/etc/passwd"})
```

| JSON Schema type | Default value |
|---|---|
| `string` | `"dummy"` |
| `integer` / `number` | `1` |
| `boolean` | `True` |
| `array` | `[]` |
| `object` | `{}` |

---

### `call_tool_safe`

Calls a tool and returns the plain text response. Returns `None` on error or `isError: true` — never raises.

```python
from mcp_sec.core.utils import call_tool_safe

res_text = await call_tool_safe(mcp_client, tool.name, args)
if res_text:
    ...
```

---

### Tool Classification Helpers

Use these to identify what a tool does based on its name:

```python
from mcp_sec.core.utils import is_read_tool, is_write_tool, is_delete_tool, is_config_env_tool

is_read_tool("read_file")      # True  — matches: read, view, get, fetch, list, show, cat
is_write_tool("save_config")   # True  — matches: write, save, create, update, put, touch
is_delete_tool("rm_dir")       # True  — matches: delete, remove, rm, drop, destroy
is_config_env_tool("get_env")  # True  — matches: env, config, setting, credential, secret
```

---

## Interacting with the MCP Client Directly

When `scan_tool_payloads` is not a fit (e.g. for non-injection checks), use the `mcp_client` directly:

```python
result = await mcp_client.call_tool("tool_name", arguments={"key": "value"})
await mcp_client.send_ping()
```

The `server_tools` list contains Tool objects with:
- `tool.name` — tool identifier
- `tool.description` — human-readable description
- `tool.inputSchema` — JSON schema of the expected input (`properties`, `required`, etc.)

> **Note:** Outer `try/except` blocks are **not needed** — the runner catches all uncaught exceptions globally. Use `call_tool_safe` or `scan_tool_payloads` for graceful per-call error handling.
