import argparse
import asyncio
import logging
import os
import shlex
import contextlib
import sys

@contextlib.contextmanager
def suppress_stderr(verbose: bool):
    if verbose:
        yield
        return
        
    null_fd = os.open(os.devnull, os.O_RDWR)
    save_fd = os.dup(2)
    os.dup2(null_fd, 2)
    try:
        yield
    finally:
        os.dup2(save_fd, 2)
        os.close(null_fd)
        os.close(save_fd)

from .core.loader import PluginLoader
from .core.engine import Runner
from .core.reporter import Reporter
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

console = Console(stderr=True)

async def async_main(target: str, plugin_dir: str, output_format: str, verbose: bool, env_dict: dict, config, playbook_dict: dict = None):
    console.print(f"[bold blue][*][/bold blue] Starting MCP Security Scanner against target: [bold]{target}[/bold]")
    
    loader = PluginLoader(plugin_dir, exclude_plugins=config.exclude_plugins)
    plugins = loader.load_plugins()
    active_plugins = [p for p in plugins if not getattr(p, "_excluded", False)]
    console.print(f"[bold blue][*][/bold blue] Loaded [bold green]{len(active_plugins)}[/bold green] plugins.\n")
    
    command_parts = shlex.split(target)
    if not command_parts:
        console.print("[bold red][!][/bold red] Error: Empty target command.")
        return
        
    target_cmd = command_parts[0]
    target_args = command_parts[1:]
    
    runner = Runner(
        target=target_cmd,
        args=target_args,
        plugins=plugins,
        env=env_dict,
        allow_destructive=config.allow_destructive,
        unsafe_keywords=config.unsafe_keywords,
        exclude_tools=config.exclude_tools,
        include_only_tools=config.include_only_tools,
        playbook=playbook_dict,
        call_timeout=config.call_timeout,
        max_concurrent_calls=config.max_concurrent_calls
    )
    results = []
    
    # Nutze Rich Progress für eine stylische Lade-Animation
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Connecting & running security scans...", total=None)
        
        def handle_discovery(tools):
            if not tools:
                progress.console.print("[yellow]No tools discovered on target.[/yellow]\n")
                return
            
            table = Table(title="Discovered MCP Tools", box=box.SIMPLE, show_header=True)
            table.add_column("Tool Name", style="bold green")
            table.add_column("Arguments", style="cyan")
            table.add_column("Description", style="white")
            
            for t in tools:
                # Argumente aus dem JSON Schema extrahieren
                args_list = []
                if t.inputSchema and "properties" in t.inputSchema:
                    args_list = list(t.inputSchema["properties"].keys())
                
                args_str = ", ".join(args_list) if args_list else "None"
                
                # Beschreibung kürzen falls zu lang
                desc = t.description or "No description provided."
                if len(desc) > 60:
                    desc = desc[:57] + "..."
                table.add_row(t.name, args_str, desc)
                
            progress.console.print(table)
            progress.console.print("") # spacing
        
        # Unterdrücke STDERR auf OS-Ebene (für alle Kind-Prozesse)
        with suppress_stderr(verbose):
            results = await runner.run(on_discovery=handle_discovery)
    
    console.print("[bold green]Scans completed![/bold green]\n")
    
    reporter = Reporter(results, format=output_format, target=target)
    reporter.generate()

def main():
    default_plugins = os.path.join(os.path.dirname(__file__), "plugins")
    
    parser = argparse.ArgumentParser(description="MCP Security Scanner")
    parser.add_argument("-t", "--target", help='Full command including arguments (e.g. "python mock_server.py")')
    parser.add_argument("-d", "--plugin-dir", help="Directory containing plugins")
    parser.add_argument("-f", "--format", help="Output format (text, json, html, markdown)", choices=["text", "json", "html", "markdown"])
    parser.add_argument("-v", "--verbose", help="Show raw server output (stderr)", action="store_true", default=None)
    parser.add_argument("-e", "--env", action="append", help="Environment variables to pass to the MCP server (format: KEY=VALUE)", default=[])
    parser.add_argument("-c", "--config", help="Path to config file (default: mcp-scan.json)", default=None)
    parser.add_argument("-p", "--playbook", help="Path to playbook file (default: playbook.json)", default=None)
    
    args = parser.parse_args()
    
    # Config laden & validieren
    from .core.config import Config, ConfigValidationError
    # Playbook laden & validieren
    from .core.playbook import Playbook, PlaybookValidationError
    
    config_obj = None
    config_path = args.config
    
    # If no config path given, check if mcp-scan.json exists in CWD
    if not config_path:
        default_config = "mcp-scan.json"
        if os.path.exists(default_config):
            config_path = default_config
            
    if config_path:
        try:
            config_obj = Config.load_and_validate(config_path)
            console.print(f"[bold blue][*][/bold blue] Config loaded from: [bold]{config_path}[/bold]")
        except ConfigValidationError as e:
            console.print(f"[bold red][!][/bold red] Config error in '{config_path}': {str(e)}")
            sys.exit(1)
            
    # If no config exists, use empty defaults
    if not config_obj:
        config_obj = Config()

    playbook_obj = None
    playbook_path = args.playbook
    if not playbook_path:
        default_playbook = "playbook.json"
        if os.path.exists(default_playbook):
            playbook_path = default_playbook
            
    if playbook_path:
        try:
            playbook_obj = Playbook.load_and_validate(playbook_path)
            console.print(f"[bold blue][*][/bold blue] Playbook loaded from: [bold]{playbook_path}[/bold]")
        except PlaybookValidationError as e:
            console.print(f"[bold red][!][/bold red] Playbook error in '{playbook_path}': {str(e)}")
            sys.exit(1)
        
    # CLI arguments override config/playbook values
    target = args.target
    if target is None:
        if playbook_obj and playbook_obj.mcpserver:
            target = playbook_obj.mcpserver
        else:
            target = config_obj.target

    if not target:
        if os.path.exists("mock_server.py"):
            target = f"{sys.executable} mock_server.py"
            console.print(f"[bold yellow][*][/bold yellow] No target specified. Using found mock server as default: [bold]{target}[/bold]")
        else:
            console.print("[bold red][!][/bold red] Error: No target specified. Please provide one via -t/--target, playbook, or config.")
            sys.exit(1)
        
    plugin_dir = args.plugin_dir if args.plugin_dir is not None else (config_obj.plugin_dir or default_plugins)
    output_format = args.format if args.format is not None else config_obj.format
    verbose = args.verbose if args.verbose is not None else config_obj.verbose
    
    # CLI env mit Config env mergen
    env_dict = {}
    if config_obj.env:
        env_dict.update(config_obj.env)
    if args.env:
        for env_var in args.env:
            if "=" in env_var:
                k, v = env_var.split("=", 1)
                env_dict[k.strip()] = v.strip()
            else:
                env_dict[env_var.strip()] = os.environ.get(env_var.strip(), "")
                
    # Configure logging: verbose -> DEBUG, else config_obj.log_level (default WARNING)
    log_level_str = "DEBUG" if verbose else config_obj.log_level
    log_level = getattr(logging, log_level_str.upper(), logging.WARNING)
    logging.basicConfig(format="[%(levelname)s] %(name)s: %(message)s", level=log_level)
    logging.getLogger("mcp_sec").setLevel(log_level)

    asyncio.run(async_main(
        target=target,
        plugin_dir=plugin_dir,
        output_format=output_format,
        verbose=verbose,
        env_dict=env_dict,
        config=config_obj,
        playbook_dict=playbook_obj.tools if playbook_obj else None
    ))

if __name__ == "__main__":
    main()
