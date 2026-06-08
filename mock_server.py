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

@mcp.tool()
def process_llm_prompt(prompt: str) -> str:
    """Simulates a tool that feeds into an LLM, vulnerable to prompt injection."""
    # Gibt den Text einfach zurück, wodurch ein LLM-Jailbreak simuliert wird
    return f"LLM context updated with: {prompt}"

@mcp.tool()
def parse_xml(xml_data: str) -> str:
    """Simulates an XML parser, vulnerable to XXE."""
    # Wir simulieren eine XXE, indem wir bei bestimmten Payloads fiktive Dateiinhalte zurückgeben
    if "file:///etc/passwd" in xml_data:
        return "Parsed result: root:x:0:0:root:/root:/bin/bash"
    if "file:///c:/windows/win.ini" in xml_data:
        return "Parsed result: [extensions]"
    return "XML parsed successfully"

@mcp.tool()
def render_template(template_string: str) -> str:
    """Simulates a template engine, vulnerable to SSTI."""
    # Wenn ein SSTI-Payload gesendet wird, tun wir so, als ob wir ihn auswerten
    if "7*7*7" in template_string:
        return "Template rendered: 343"
    return f"Template rendered: {template_string}"

@mcp.tool()
def generate_html_report(user_input: str) -> str:
    """Simulates generating HTML, vulnerable to XSS."""
    # Ungefilterte Rückgabe der Eingabe in einem HTML-Kontext
    return f"<html><body><h1>Report</h1><div>{user_input}</div></body></html>"


@mcp.tool()
def process_data(data: str) -> str:
    """Simulates data processing, vulnerable to ReDoS."""
    # Wir simulieren einen Timeout, wenn ReDoS Payloads kommen
    if data == "(((a.*)+)+)+b" or data == "(a+)+b":
        import time
        time.sleep(15)
    return f"Processed {len(data)} characters"

@mcp.tool()
def blind_query(query: str) -> str:
    """Simulates a database query, vulnerable to blind SQLi / Timing attack."""
    import time
    if "sleep" in query.lower() or "delay" in query.lower():
        import re
        match = re.search(r'\d+', query)
        if match:
            time.sleep(int(match.group()))
        else:
            time.sleep(12)
    return "Query executed"

_profile_lock_counter = 0

@mcp.tool()
def write_user_profile(profile_data: str) -> str:
    """Simulates a write operation, vulnerable to race conditions."""
    import time
    global _profile_lock_counter
    _profile_lock_counter += 1

        
    if _profile_lock_counter > 5:
        # Simulate a concurrency crash/lock issue
        _profile_lock_counter -= 1
        raise RuntimeError("Database lock acquired by another thread.")
        
    time.sleep(0.5)
    _profile_lock_counter -= 1
    return "Profile written successfully."

@mcp.tool()
def read_agent_command(user_command: str) -> str:
    """Simulates a tool that might reflect malicious tool calls."""
    return f"Here is the parsed command: {user_command}"

if __name__ == "__main__":
    mcp.run()
