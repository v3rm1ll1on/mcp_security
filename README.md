# MCP Security Scanner

A modular, highly extensible, and AI-native security scanning framework designed specifically to audit **Model Context Protocol (MCP)** servers.

While traditional DAST scanners target REST or GraphQL APIs, MCP servers sit directly between LLMs (like Claude or GPT-4) and sensitive backend infrastructure. This creates entirely new attack vectors. **MCP Security Scanner** is built to automatically detect both traditional Web/API vulnerabilities and novel AI-specific attacks (like Agentic Hijacking or Context Flooding).

---

## Features

* **Plug-and-Play Architecture**: Drop a python file into `plugins/` and it is instantly integrated into the scanning engine.
* **15+ Built-in Security Modules**:
  * **Traditional Security**: SQLi, XXE, Command Injection, Path Traversal, SSRF, XSS, SSTI, DoS/ReDoS.
  * **AI-Specific Security**: Agentic Hijacking (Tool-Call Injection), Prompt Injection/Jailbreaking, Context Window Exhaustion.
  * **Concurrency/Fuzzing**: Mutational Type-Juggling, Race Conditions.
  * **MCP Core**: Resource Path Traversal, Schema Information Leakage.
* **CI/CD Ready**: Supports `json`, `text`, `markdown`, and `html` output. Exit codes and JSON dumps map perfectly into automated pipelines.
* **Smart Context-Aware Routing**: Define `playbooks` to map specific vulnerability checks to specific tools based on naming conventions (e.g., test SQLi only on `search_*` tools).
* **Safe Mode by Default**: Built-in AST-based keyword exclusion prevents the scanner from accidentally deleting databases or writing files unless explicitly permitted via `allow_destructive`.

---

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/v3rm1ll1on/mcp_security.git
cd mcp_security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## Usage

The scanner connects directly to a target MCP server via `stdio`.

### Basic Scans

```bash
# Scan a Node-based MCP server
mcp-scan --target "node path/to/server.js"

# Scan an NPX package server directly
mcp-scan --target "npx -y @modelcontextprotocol/server-postgres"
```

### Pipeline Integration (JSON Output)

```bash
# Output raw JSON for machine parsing
mcp-scan -p playbook.json -f json > report.json

# Use `jq` to extract only the failed security checks:
cat report.json | jq '.[] | select(.success == false)'
```

---

## Configuration & Playbooks

The scanner can be deeply customized using `mcp-scan.json` and `playbook.json`. 

### Global Configuration (`mcp-scan.json`)
Allows you to inject secure environment variables to the target process, define global tool exclusions, and enforce non-destructive operations.

```json
{
  "target": "python3 mock_server.py",
  "format": "text",
  "global": {
    "allow_destructive": false,
    "unsafe_keywords": ["write", "delete", "remove", "drop", "destroy", "rm"],
    "env": {
      "API_KEY": "secret_token_here"
    }
  }
}
```

### Playbook (`playbook.json`)
Instead of blasting every payload at every parameter, use playbooks to intelligently map plugins to tools using glob patterns. This drastically reduces scan time and noise.

```json
{
  "tools": {
    "read_*": [
      "path_traversal"
    ],
    "search_*": [
      "sqli",
      "timing_attack"
    ],
    "*": [
      "schema_leakage",
      "context_exhaustion",
      "mutational_fuzzing"
    ]
  }
}
```

---

## Included Plugins & Vulnerability Coverage

The scanner actively maps vulnerabilities against **CWE** (Common Weakness Enumeration) and **OWASP Top 10 / OWASP LLM Top 10**.

| Plugin | Attack Vector | Target |
|---|---|---|
| **SQL Injection** | `CWE-89` | Standard injection on string parameters |
| **Command Injection** | `CWE-77` | RCE via shell metacharacters |
| **Path Traversal / LFI** | `CWE-22` | Breaking out of directories via `../` |
| **Resource Traversal** | `CWE-22` | Path traversal targeting the MCP Resource API |
| **SSRF** | `CWE-918` | Server-Side Request Forgery via internal IPs |
| **XXE** | `CWE-611` | External entity parsing in XML payloads |
| **SSTI** | `CWE-1336` | Template evaluations (`{{7*7}}`) |
| **Agentic Hijacking** | `CWE-74` / `LLM02` | Unescaped tool-call structure reflection |
| **Prompt Injection** | `CWE-74` / `LLM01` | LLM persona overrides and jailbreaks |
| **Context Exhaustion** | `CWE-400` / `LLM04` | Denial of Service via massive token responses |
| **DoS / ReDoS** | `CWE-400` | Uncontrolled resource consumption via Evil Regex |
| **Timing Attack** | `CWE-208` | Blind injection detection via `sleep()` delays |
| **Race Conditions** | `CWE-362` | Concurrent state mutation crashes |
| **Mutational Fuzzing** | `CWE-20` | Type Juggling (Arrays/Dicts where Strings expected) |
| **Schema Leakage** | `CWE-200` | Exposing internal IPs/Tokens in tool JSON schemas |

---

## Writing Custom Plugins

Developing custom tests is dead simple. Read the full [Plugin Development Guide](docs/plugin_development.md) for details on the `run_payload_scan` API.

---

## Disclaimer
This tool is provided for educational and authorized security testing purposes only. Do not use this tool against targets you do not own or do not have explicit permission to test. The authors and contributors assume no liability and are not responsible for any misuse or damage caused by this program.
