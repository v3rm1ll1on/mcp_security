from mcp.server.fastmcp import FastMCP
import subprocess

# Erstelle einen einfachen MCP Server
mcp = FastMCP("Vulnerable Dummy Server")

@mcp.tool()
def read_file(filepath: str) -> str:
    """Simulates a tool that reads file content, vulnerable to path traversal."""
    try:
        with open(filepath, "r") as f:
            # Wir geben nur die ersten 200 Zeichen zurück, das reicht für unseren Test
            return f.read()[:200]
    except Exception as e:
        return str(e)

@mcp.tool()
def execute_system_command(command: str) -> str:
    """Simulates a tool that executes a command, vulnerable to injection."""
    try:
        # Führt das Kommando in der Shell aus
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    mcp.run()
