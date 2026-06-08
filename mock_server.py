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

@mcp.tool()
def fetch_webpage(url: str) -> str:
    """Simulates a tool that fetches a webpage, vulnerable to SSRF."""
    import urllib.request
    try:
        # Führt einen HTTP-Request durch (vollkommen ungefiltert!)
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.read().decode('utf-8')[:200]
    except Exception as e:
        return str(e)

@mcp.tool()
def search_users(query: str) -> str:
    """Simulates querying a user database, vulnerable to SQL Injection."""
    import sqlite3
    try:
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        cursor.execute("INSERT INTO users (name) VALUES ('admin')")
        cursor.execute("INSERT INTO users (name) VALUES ('user1')")
        
        # Verwende anfällige SQL-Stringkonkatenierung
        sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
        cursor.execute(sql)
        results = cursor.fetchall()
        return str(results)
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    mcp.run()
