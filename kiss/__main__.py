import argparse
import asyncio
import sys
from rich.console import Console
from .core import KissEngine
from .config import get_config
from .ui import print_banner, print_results

console = Console()

def main():
    parser = argparse.ArgumentParser(description="KISS - Keep It Simple Scanner")
    parser.add_argument("target", nargs="?", help="Target to scan")
    parser.add_argument("--list", "-l", action="store_true", help="List supported input types and API key status")
    parser.add_argument("--list-modules", nargs="?", const="all", metavar="TYPE", help="List modules for an input type (e.g. --list-modules email)")
    parser.add_argument("--set-key", nargs=2, metavar=("SERVICE", "KEY"), help="Set an API key (e.g. --set-key hibp YOUR_KEY)")
    parser.add_argument("--proxy", metavar="URL", help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--set-proxy", metavar="URL", help="Save a default proxy URL")

    args = parser.parse_args()

    if args.set_key:
        service, key = args.set_key
        config = get_config()
        config.set(f"{service.lower()}_key", key)
        console.print(f"[bold green]API key for '{service}' saved.[/bold green]")
        return

    if args.set_proxy is not None:
        config = get_config()
        if args.set_proxy.lower() in ("", "off", "none", "clear"):
            config.set("proxy", None)
            console.print("[bold green]Proxy cleared.[/bold green]")
        else:
            config.set("proxy", args.set_proxy)
            console.print(f"[bold green]Proxy saved: {args.set_proxy}[/bold green]")
        return

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user.[/bold red]")
        sys.exit(1)


def _print_type_modules(type_name, modules):
    """Print module list for a single type with status indicators."""
    active = sum(1 for m in modules if m["status"] == "active")
    total = len(modules)
    count = f"{active}/{total}" if active < total else str(total)
    console.print(f"[bold cyan]{type_name.upper()}[/bold cyan] [dim]{count} modules[/dim]")

    for mod in modules:
        returns = ", ".join(mod["returns"]) if mod["returns"] else ""
        if mod["status"] == "locked":
            console.print(f"  [dim]x {mod['name']}: {returns} (requires {mod['api_key']} key)[/dim]")
        else:
            console.print(f"  [green]+[/green] {mod['name']}: {returns}")


async def async_main(args):
    engine = KissEngine(proxy=getattr(args, 'proxy', None))

    # Handle --list-modules [TYPE]
    if args.list_modules:
        caps = engine.get_capabilities()
        type_filter = args.list_modules.lower()

        if type_filter == "all":
            for type_name, modules in caps.items():
                _print_type_modules(type_name, modules)
        elif type_filter in caps:
            _print_type_modules(type_filter, caps[type_filter])
        else:
            valid = ", ".join(caps.keys())
            console.print(f"[yellow]Unknown type '{type_filter}'. Available: {valid}[/yellow]")
        await engine.close()
        return

    # Handle --list
    if args.list:
        print_banner()
        config = get_config()
        caps = engine.get_capabilities()

        # Deduplicate module names across types for total count
        all_names = set()
        for modules in caps.values():
            for mod in modules:
                all_names.add(mod["name"])
        console.print(f"[bold green]Supported Input Types: {len(caps)} | Total Modules: {len(all_names)}[/bold green]\n")

        keys = {}
        for type_name, modules in caps.items():
            active = sum(1 for m in modules if m["status"] == "active")
            total = len(modules)
            count = f"{active}/{total}" if active < total else str(total)
            console.print(f"  [bold cyan]{type_name.upper()}[/bold cyan] [dim]{count} modules[/dim]")
            for mod in modules:
                if mod["api_key"] and mod["api_key"] not in keys:
                    keys[mod["api_key"]] = config.get_api_key(mod["api_key"]) is not None

        if keys:
            console.print()
            console.print("[bold cyan]API KEYS[/bold cyan]")
            for service, is_set in keys.items():
                status = "[green]set[/green]" if is_set else "[red]missing[/red]"
                console.print(f"  {service} {status}")
        await engine.close()
        return

    # Handle Missing Target
    if not args.target:
        print_banner()
        console.print("[yellow]Usage: kiss <target>[/yellow]")
        console.print("[dim]Example: kiss user:admin[/dim]")
        await engine.close()
        return

    # Handle Scan
    print_banner()

    with console.status(f"[bold green]Scanning {args.target}...[/bold green]", spinner="dots"):
        report = await engine.scan(args.target)

    print_results(report)
    await engine.close()

if __name__ == "__main__":
    main()
