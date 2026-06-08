import argparse
import asyncio
from .core.loader import PluginLoader
from .core.engine import Runner
from .core.reporter import Reporter

async def async_main(args):
    print(f"[*] Starting MCP Security Scanner against target: {args.target}")
    
    loader = PluginLoader(args.plugin_dir)
    plugins = loader.load_plugins()
    print(f"[*] Loaded {len(plugins)} plugins.")
    
    server_args = [a.strip() for a in args.server_args.split(',')] if args.server_args else []
    
    runner = Runner(args.target, server_args, plugins)
    results = await runner.run()
    
    reporter = Reporter(results, format=args.format)
    reporter.generate()

def main():
    parser = argparse.ArgumentParser(description="MCP Security Scanner")
    parser.add_argument("-t", "--target", help="Target executable (e.g. node, npx, python)", required=True)
    parser.add_argument("-a", "--server-args", help="Arguments for the server, comma separated", default="")
    parser.add_argument("-p", "--plugin-dir", help="Directory containing plugins", default="mcp_sec/plugins")
    parser.add_argument("-f", "--format", help="Output format (text, json)", choices=["text", "json"], default="text")
    
    args = parser.parse_args()
    asyncio.run(async_main(args))

if __name__ == "__main__":
    main()
