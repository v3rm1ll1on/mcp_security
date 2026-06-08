# MCP Security Scanner

A modular, extensible security scanning framework for Model Context Protocol (MCP) servers.

## Overview
This tool is designed to test MCP servers for common security vulnerabilities (e.g., Command Injection, Path Traversal) by simulating malicious inputs through standard MCP tool calls.

It features a "Drop-In" plugin system: just drop a Python file into the `plugins/` directory, and the scanner will pick it up automatically.

## Installation
Ensure you have Python 3.10+ installed.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage
The scanner runs as a CLI tool and connects to a target MCP server via `stdio`.

```bash
# Basic scan against a local node-based MCP server
mcp-scan --target node --server-args "path/to/server.js"

# Output in JSON format (useful for CI/CD)
mcp-scan --target npx --server-args "-y,@modelcontextprotocol/server-memory" --format json
```
## Configuration

The scanner can be configured using a `mcp-scan.json` file in the current working directory, or by specifying a path using `-c` / `--config`.

Here is an example `mcp-scan.json`:

```json
{
  "target": "python3 mock_server.py",
  "format": "text",
  "verbose": false,
  "plugin_dir": "mcp_sec/plugins",
  "global": {
    "allow_destructive": false,
    "unsafe_keywords": ["write", "delete", "remove", "drop", "destroy", "rm"],
    "env": {
      "API_KEY": "secret_token_here"
    }
  },
  "tools": {
    "exclude": ["heavy_computation_tool"],
    "include_only": []
  },
  "plugins": {
    "exclude": ["Basic Ping"]
  }
}
```

CLI arguments will always take precedence over configuration file settings.

## Playbooks

If you want to test specific tools with selected test plugins, you can create a separate **Playbook** (`playbook.json`) and pass it using `-p` / `--playbook`.

This allows you to define playbooks independently of the general configuration, e.g., to run expensive or critical tests (like SQL injection) only on appropriate input fields.

### Glob Wildcards for Tools
You can use glob patterns (wildcards like `read_*` or `*file*`) in the playbook to select multiple tools at once and assign plugins to them.

### Example `playbook.json`:

```json
{
  "mcpserver": "python3 mock_server.py",
  "tools": {
    "read_*": [
      "path_traversal"
    ],
    "execute_system_command": [
      "command_injection"
    ],
    "fetch_webpage": [
      "ssrf"
    ],
    "search_*": [
      "sqli"
    ]
  }
}
```

* When a playbook is loaded, the `mcpserver` command configured in it is selected as the target (unless `-t` is explicitly passed).
* Only the tools defined in the playbook are scanned, and only with their assigned plugins. A wildcard `"*"` can be used to allow all plugins for a tool.
* Plugins can be mapped by their name (e.g. `"sqli"`), module name (e.g. `"test_sqli"`), or their groups (e.g. `"owasp"`). Each plugin can define a list of groups in its metadata.
* Tools that are skipped or excluded from scanning due to playbook or configuration filters are transparently reported as **SKIP** in the scan summary.

### CLI Options:

* `-c`, `--config`: Path to the main configuration file (default: `mcp-scan.json`).
* `-p`, `--playbook`: Path to the playbook file (default: `playbook.json`, if present in the current directory).
* `-d`, `--plugin-dir`: Directory containing the security plugins (default: `mcp_sec/plugins`).
* `-t`, `--target`: Command to start the target MCP server (overrides `mcpserver` and `target` settings).
* `-f`, `--format`: Output format (`text`, `json`, `html`, or `markdown`).

## Output Formats & Classification

The scanner classifies detected vulnerabilities using standardized identifiers:
* **CWE (Common Weakness Enumeration)** (e.g., `CWE-89` for SQL Injection)
* **OWASP Top 10** (e.g., `A03:2021-Injection`)

### Supported Report Formats (`-f` / `--format`):
* `text`: Colorful, structured terminal output using Rich.
* `json`: Structured JSON dump (ideal for CI/CD integrations).
* `markdown`: Generates a clean Markdown report suitable for PR comments or issue trackers.
* `html`: Creates a visually premium interactive HTML report in modern dark mode, complete with filter options (PASS, FAIL, SKIP) and interactive details.

## Core Architecture
- **Loader**: Automatically discovers and validates plugins from the `mcp_sec/plugins/` directory.
- **Engine**: Handles the asynchronous `stdio` connection to the MCP target and executes all loaded plugins.
- **Reporter**: Generates a human-readable summary or JSON/HTML/Markdown output of vulnerabilities.
- **Models**: Standardized `PluginResult` and `Vulnerability` dataclasses.

## Contributing / Custom Plugins
See [docs/plugin_development.md](docs/plugin_development.md) for instructions on how to write custom tests.

## Disclaimer
Do not use this tool against targets you do not own or do not have permission to test.
