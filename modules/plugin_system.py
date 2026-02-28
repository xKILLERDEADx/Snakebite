"""Plugin System — auto-load custom scan modules from plugins/ directory."""

import os
import importlib.util
import asyncio
from modules.core import console

PLUGINS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'plugins')

def discover_plugins():
    """Discover all .py plugin files in the plugins/ directory."""
    plugins = []

    if not os.path.exists(PLUGINS_DIR):
        return plugins

    for filename in sorted(os.listdir(PLUGINS_DIR)):
        if filename.endswith('.py') and not filename.startswith('_'):
            filepath = os.path.join(PLUGINS_DIR, filename)
            plugin_name = filename[:-3]

            try:
                spec = importlib.util.spec_from_file_location(f"plugins.{plugin_name}", filepath)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                scan_func = None
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if callable(attr) and attr_name.startswith('scan_'):
                        scan_func = attr
                        break

                if scan_func:
                    plugins.append({
                        'name': plugin_name,
                        'path': filepath,
                        'module': module,
                        'scan_func': scan_func,
                        'description': getattr(module, '__doc__', '') or plugin_name,
                        'author': getattr(module, '__author__', 'Unknown'),
                        'version': getattr(module, '__version__', '1.0'),
                    })
            except Exception as e:
                console.print(f"  [yellow]Plugin load error ({filename}): {e}[/yellow]")

    return plugins


async def run_plugins(session, url):
    """Discover and run all plugins."""
    console.print(f"\n[bold cyan]--- Plugin System ---[/bold cyan]")

    if not os.path.exists(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR, exist_ok=True)
        console.print(f"  [dim]Created plugins/ directory[/dim]")

        example_path = os.path.join(PLUGINS_DIR, '_example_plugin.py')
        if not os.path.exists(example_path):
            with open(example_path, 'w') as f:
                f.write('''"""Example Snakebite Plugin — copy and modify this template."""

__author__ = "Your Name"
__version__ = "1.0"


async def scan_example(session, url):
    """Your custom scan logic here."""
    # session = aiohttp.ClientSession
    # url = target URL string
    results = []
    
    # Example: check for a specific endpoint
    # async with session.get(f"{url}/custom-endpoint") as resp:
    #     if resp.status == 200:
    #         results.append({"url": url, "finding": "Custom endpoint exposed"})
    
    return results
''')
        console.print(f"  [dim]Example plugin created: plugins/_example_plugin.py[/dim]")

    plugins = discover_plugins()

    if not plugins:
        console.print(f"  [dim]No plugins found in plugins/ directory[/dim]")
        console.print(f"  [dim]Drop .py files with scan_* functions into plugins/ to extend Snakebite[/dim]")
        return {}

    console.print(f"  [green]Found {len(plugins)} plugins[/green]")
    all_results = {}

    for plugin in plugins:
        console.print(f"\n  [bold yellow]Running: {plugin['name']}[/bold yellow]")
        console.print(f"  [dim]{plugin['description'][:100]}[/dim]")

        try:
            scan_func = plugin['scan_func']
            if asyncio.iscoroutinefunction(scan_func):
                result = await scan_func(session, url)
            else:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, scan_func, session, url
                )
            all_results[plugin['name']] = result

            if result:
                if isinstance(result, list):
                    console.print(f"  [green]✓ {len(result)} findings[/green]")
                elif isinstance(result, dict):
                    console.print(f"  [green]✓ Results collected[/green]")
            else:
                console.print(f"  [dim]No findings[/dim]")

        except Exception as e:
            console.print(f"  [red]Plugin error: {e}[/red]")
            all_results[plugin['name']] = {'error': str(e)}

    console.print(f"\n  [green]Completed {len(plugins)} plugins[/green]")
    return all_results
