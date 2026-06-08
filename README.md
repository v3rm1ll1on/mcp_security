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

## Core Architecture
- **Loader**: Dynamically discovers and validates plugins from the `mcp_sec/plugins/` directory.
- **Engine**: Handles the asynchronous `stdio` connection to the MCP target and executes all loaded plugins.
- **Reporter**: Generates a human-readable summary or JSON output of vulnerabilities.
- **Models**: Standardized `PluginResult` and `Vulnerability` dataclasses.

## Contributing / Custom Plugins
See [docs/plugin_development.md](docs/plugin_development.md) for instructions on how to write custom tests.

## Disclaimer
Do not use this tool against targets you do not own or do not have permission to test.
