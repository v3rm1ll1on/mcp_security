import json
import dataclasses
from enum import Enum
from mcp_sec.core.models import PluginResult, Severity
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)

class Reporter:
    def __init__(self, results: list[PluginResult], format: str = "text", target: str = "Unknown"):
        self.results = results
        self.format = format
        self.target = target
        self.console = Console()
        
    def generate(self):
        if self.format == "json":
            dict_results = [dataclasses.asdict(r) for r in self.results]
            print(json.dumps(dict_results, indent=2, cls=EnumEncoder))
            return
        elif self.format == "html":
            self.generate_html()
            return
        elif self.format == "markdown":
            self.generate_markdown()
            return
            
        # Rich Terminal Output
        self.console.print("\n")
        
        # Overview table
        table = Table(title="MCP Security Scan Report", box=box.HEAVY_EDGE, show_lines=True)
        table.add_column("Status", justify="center", style="bold")
        table.add_column("Plugin", style="cyan")
        table.add_column("Message", style="white")
        
        vulnerabilities = []
        
        for res in self.results:
            if getattr(res, "skipped", False):
                status = "[yellow]SKIP[/yellow]"
            elif res.success:
                status = "[green]PASS[/green]"
            else:
                status = "[red]FAIL[/red]"
                
            table.add_row(status, res.plugin_name, res.message)
            
            # Collect all vulnerabilities for detail output
            if res.vulnerabilities:
                vulnerabilities.extend(res.vulnerabilities)
                
        self.console.print(table)
        
        # If vulnerabilities were found, print them in colored panels
        if vulnerabilities:
            self.console.print("\n[bold red]VULNERABILITY DETAILS[/bold red]")
            for vuln in vulnerabilities:
                # Color based on severity (Critical=magenta, High=red, etc.)
                color = "red"
                if vuln.severity == Severity.CRITICAL:
                    color = "magenta"
                elif vuln.severity == Severity.MEDIUM:
                    color = "yellow"
                elif vuln.severity == Severity.LOW:
                    color = "blue"
                    
                content = (
                    f"[bold]Tool:[/bold] {vuln.tool_name}\n"
                    f"[bold]Payload:[/bold] [yellow]{vuln.payload}[/yellow]\n"
                    f"[bold]Description:[/bold] {vuln.description}"
                )
                
                title_parts = [f"[bold {color}]{vuln.severity.value} - {vuln.title}[/]"]
                meta_parts = []
                if vuln.cwe:
                    meta_parts.append(f"[bold cyan]{vuln.cwe}[/bold cyan]")
                if vuln.owasp:
                    meta_parts.append(f"[bold cyan]{vuln.owasp}[/bold cyan]")
                if meta_parts:
                    title_parts.append(f" ({', '.join(meta_parts)})")
                
                panel = Panel(
                    content,
                    title="".join(title_parts),
                    border_style=color,
                    expand=False
                )
                self.console.print(panel)
        self.console.print("\n")

    def generate_html(self):
        import html
        from datetime import datetime
        
        # Count stats
        stats_fail = 0
        stats_skip = 0
        stats_pass = 0
        
        table_rows = []
        vulnerabilities = []
        
        for res in self.results:
            if getattr(res, "skipped", False):
                status_class = "skip"
                status_label = "SKIP"
                stats_skip += 1
            elif res.success:
                status_class = "pass"
                status_label = "PASS"
                stats_pass += 1
            else:
                status_class = "fail"
                status_label = "FAIL"
                stats_fail += 1
                
            row_html = f"""
            <tr data-status="{status_class}">
                <td><span class="badge {status_class}">{status_label}</span></td>
                <td><strong>{html.escape(res.plugin_name)}</strong></td>
                <td>{html.escape(res.message)}</td>
            </tr>
            """
            table_rows.append(row_html)
            
            if res.vulnerabilities:
                vulnerabilities.extend(res.vulnerabilities)
                
        # Vulnerabilities section
        vuln_section_parts = []
        if vulnerabilities:
            vuln_section_parts.append('<div class="vulnerabilities-section"><h2>Vulnerabilities Found</h2>')
            for vuln in vulnerabilities:
                severity_class = vuln.severity.value.lower()
                cwe_badge = f'<span class="meta-badge">{html.escape(vuln.cwe)}</span>' if vuln.cwe else ''
                owasp_badge = f'<span class="meta-badge">{html.escape(vuln.owasp)}</span>' if vuln.owasp else ''
                
                vuln_card = f"""
                <div class="vuln-card {severity_class}">
                    <div class="vuln-header">
                        <div class="vuln-title">{html.escape(vuln.title)}</div>
                        <span class="vuln-severity-badge {severity_class}">{html.escape(vuln.severity.value)}</span>
                    </div>
                    <div class="vuln-meta">
                        <span>Tool: <strong>{html.escape(vuln.tool_name or "N/A")}</strong></span>
                        {cwe_badge}
                        {owasp_badge}
                    </div>
                    <div class="vuln-description">
                        {html.escape(vuln.description)}
                    </div>
                    <div class="payload-box">{html.escape(vuln.payload or "N/A")}</div>
                </div>
                """
                vuln_section_parts.append(vuln_card)
            vuln_section_parts.append('</div>')
            
        vuln_section_html = "\n".join(vuln_section_parts)
        
        # Replace template placeholders
        html_template = self._get_html_template()
        html_output = (
            html_template
            .replace("$TARGET$", html.escape(self.target))
            .replace("$DATE$", datetime.now().strftime("%d. %B %Y, %H:%M:%S"))
            .replace("$PLUGINS_COUNT$", str(len(self.results)))
            .replace("$STATS_FAIL$", str(stats_fail))
            .replace("$STATS_SKIP$", str(stats_skip))
            .replace("$STATS_PASS$", str(stats_pass))
            .replace("$TABLE_ROWS$", "\n".join(table_rows))
            .replace("$VULNERABILITIES_SECTION$", vuln_section_html)
        )
        
        print(html_output)

    def generate_markdown(self):
        from datetime import datetime
        
        stats_fail = 0
        stats_skip = 0
        stats_pass = 0
        
        table_rows = []
        vulnerabilities = []
        
        for res in self.results:
            if getattr(res, "skipped", False):
                status_lbl = "🟡 SKIP"
                stats_skip += 1
            elif res.success:
                status_lbl = "🟢 PASS"
                stats_pass += 1
            else:
                status_lbl = "🔴 FAIL"
                stats_fail += 1
                
            table_rows.append(f"| {status_lbl} | {res.plugin_name} | {res.message} |")
            if res.vulnerabilities:
                vulnerabilities.extend(res.vulnerabilities)
                
        vuln_md = []
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity_str = f"**{vuln.severity.value}**"
                cwe_str = f" (`{vuln.cwe}`)" if vuln.cwe else ""
                owasp_str = f" (`{vuln.owasp}`)" if vuln.owasp else ""
                
                vuln_md.append(f"### {severity_str} - {vuln.title}{cwe_str}{owasp_str}")
                vuln_md.append(f"- **Tool:** `{vuln.tool_name or 'N/A'}`")
                vuln_md.append(f"- **Description:** {vuln.description}")
                vuln_md.append(f"- **Payload:**")
                vuln_md.append(f"  ```\n  {vuln.payload or 'N/A'}\n  ```")
                vuln_md.append("")
        else:
            vuln_md.append("*No vulnerabilities found.*")
            
        md_output = f"""# MCP Security Scanner Report
 
 **Target:** `{self.target}`
 **Scan Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 **Plugins:** {len(self.results)}
 
 ---
 
 ## Scan Overview
 
 | Status | Plugin / Check | Result / Details |
 |---|---|---|
 {"\n".join(table_rows)}
 
 ---
 
 ## Vulnerabilities Found ({len(vulnerabilities)})
 
 {"\n".join(vuln_md)}
 """
        print(md_output)

    def _get_html_template(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Security Scanner Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f111a;
            --card-bg: rgba(22, 25, 41, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #f1f2f6;
            --text-muted: #8b92b6;
            --primary-color: #4f46e5;
            --color-pass: #10b981;
            --color-fail: #ef4444;
            --color-skip: #f59e0b;
            --color-critical: #d946ef;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            padding: 2rem;
            min-height: 100vh;
            background-image: 
                radial-gradient(at 0% 0%, rgba(79, 70, 229, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(217, 70, 239, 0.1) 0px, transparent 50%);
            background-attachment: fixed;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        header {
            margin-bottom: 3rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }
        h1 {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a5b4fc, #e9d5ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }
        .meta-info {
            color: var(--text-muted);
            font-size: 0.95rem;
        }
        .meta-info code {
            background: rgba(255, 255, 255, 0.05);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #c7d2fe;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s ease, border-color 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: rgba(255, 255, 255, 0.15);
        }
        .stat-val {
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 0.2rem;
        }
        .stat-lbl {
            font-size: 0.9rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .stat-card.pass { border-left: 4px solid var(--color-pass); }
        .stat-card.pass .stat-val { color: var(--color-pass); }
        .stat-card.fail { border-left: 4px solid var(--color-fail); }
        .stat-card.fail .stat-val { color: var(--color-fail); }
        .stat-card.skip { border-left: 4px solid var(--color-skip); }
        .stat-card.skip .stat-val { color: var(--color-skip); }
        
        .filters {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }
        .filter-btn {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-family: inherit;
            font-weight: 600;
            transition: all 0.2s ease;
        }
        .filter-btn:hover {
            background: rgba(255, 255, 255, 0.1);
        }
        .filter-btn.active {
            background: var(--primary-color);
            border-color: var(--primary-color);
            box-shadow: 0 0 12px rgba(79, 70, 229, 0.4);
        }
        
        table.report-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            margin-bottom: 3rem;
        }
        .report-table th, .report-table td {
            padding: 1.2rem;
            text-align: left;
        }
        .report-table th {
            background: rgba(255, 255, 255, 0.03);
            font-weight: 600;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }
        .report-table tr:not(:last-child) td {
            border-bottom: 1px solid var(--border-color);
        }
        .report-table tr {
            transition: background-color 0.2s ease;
        }
        .report-table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        .badge {
            display: inline-block;
            padding: 0.35rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            text-align: center;
        }
        .badge.pass {
            background: rgba(16, 185, 129, 0.15);
            color: var(--color-pass);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .badge.fail {
            background: rgba(239, 68, 68, 0.15);
            color: var(--color-fail);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .badge.skip {
            background: rgba(245, 158, 171, 0.15);
            color: var(--color-skip);
            border: 1px solid rgba(245, 158, 171, 0.3);
        }
        .vulnerabilities-section {
            margin-top: 4rem;
        }
        .vulnerabilities-section h2 {
            font-size: 1.75rem;
            font-weight: 800;
            margin-bottom: 1.5rem;
            color: #ef4444;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .vuln-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.8rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            border-left: 4px solid var(--color-fail);
            transition: transform 0.2s ease;
        }
        .vuln-card.critical {
            border-left-color: var(--color-critical);
        }
        .vuln-card.medium {
            border-left-color: var(--color-skip);
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }
        .vuln-title {
            font-size: 1.25rem;
            font-weight: 700;
        }
        .vuln-severity-badge {
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-weight: 600;
            color: #fff;
        }
        .vuln-severity-badge.critical { background: var(--color-critical); }
        .vuln-severity-badge.high { background: var(--color-fail); }
        .vuln-severity-badge.medium { background: var(--color-skip); }
        .vuln-severity-badge.low { background: #3b82f6; }
        
        .vuln-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1.2rem;
            font-size: 0.9rem;
            color: var(--text-muted);
        }
        .vuln-meta span strong {
            color: var(--text-color);
        }
        .meta-badge {
            background: rgba(255, 255, 255, 0.05);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            border: 1px solid var(--border-color);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: #818cf8;
        }
        .vuln-description {
            margin-bottom: 1rem;
            font-size: 1rem;
        }
        .payload-box {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            color: #fca5a5;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>MCP Security Scanner</h1>
                <div class="meta-info">Target: <code>$TARGET$</code> &bull; Scan Date: <code>$DATE$</code></div>
            </div>
            <div style="font-size: 1.1rem; font-weight: 600; color: var(--text-muted);">
                Plugins: <span style="color: var(--text-color);">$PLUGINS_COUNT$</span>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card fail">
                <div class="stat-val">$STATS_FAIL$</div>
                <div class="stat-lbl">Failed</div>
            </div>
            <div class="stat-card skip">
                <div class="stat-val">$STATS_SKIP$</div>
                <div class="stat-lbl">Skipped</div>
            </div>
            <div class="stat-card pass">
                <div class="stat-val">$STATS_PASS$</div>
                <div class="stat-lbl">Passed</div>
            </div>
        </div>
        
        <div class="filters">
            <button class="filter-btn active" onclick="filterTable('all')">Show All</button>
            <button class="filter-btn" onclick="filterTable('fail')">FAIL only</button>
            <button class="filter-btn" onclick="filterTable('skip')">SKIP only</button>
            <button class="filter-btn" onclick="filterTable('pass')">PASS only</button>
        </div>
        
        <table class="report-table">
            <thead>
                <tr>
                    <th style="width: 15%;">Status</th>
                    <th style="width: 35%;">Plugin / Check</th>
                    <th style="width: 50%;">Result / Details</th>
                </tr>
            </thead>
            <tbody id="report-rows">
                $TABLE_ROWS$
            </tbody>
        </table>
        
        $VULNERABILITIES_SECTION$
    </div>
    
    <script>
        function filterTable(status) {
            // Update active state of buttons
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            
            // Find the event-target button or select the matching one
            if (event && event.target) {
                event.target.classList.add('active');
            }
            
            // Filter table rows
            const rows = document.querySelectorAll('#report-rows tr');
            rows.forEach(row => {
                if (status === 'all') {
                    row.style.display = '';
                } else {
                    const rowStatus = row.getAttribute('data-status');
                    if (rowStatus === status) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
            });
        }
    </script>
</body>
</html>"""
