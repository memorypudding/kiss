import os
import shutil
import subprocess
import sys

# --- Bootstrap: handle --setup before any third-party imports ---
# This lets `python3.13 -m xsint --setup` work even when deps aren't installed yet.

def _run_setup():
    """Install xsint dependencies, ghunt, and gitfive."""
    major, minor = sys.version_info[:2]
    print(f"Current Python: {sys.executable} ({major}.{minor})\n")

    if not (10 <= minor <= 13 and major == 3):
        reason = "too old" if minor < 10 else "too new — deps don't support it yet"
        print(f"[!] Python {major}.{minor} is {reason}.")
        print("    GHunt and GitFive require Python 3.10 to 3.13.")
        print("\n    Install a compatible version:")
        print("      brew install python@3.13")
        print("\n    Then re-run xsint under it:")
        print("      python3.13 -m xsint --setup")
        return

    # Step 1: Install xsint's own requirements
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "requirements.txt")
    req_path = os.path.normpath(req_path)
    if os.path.exists(req_path):
        print("Installing xsint dependencies...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", req_path],
            capture_output=False,
        )
        if result.returncode != 0:
            print("\n[!] Failed to install xsint dependencies.")
            return
        print()

    # Step 2: Install ghunt via pipx (for the `ghunt login` CLI)
    pipx = shutil.which("pipx")
    if not pipx:
        print("[!] pipx is not installed.")
        print("    Install it with: pip install pipx")
        print("    Skipping pipx install of ghunt (CLI only).\n")
    else:
        print("Installing ghunt CLI (via pipx)...")
        subprocess.run(
            [pipx, "install", "ghunt", "--python", sys.executable, "--force"],
            capture_output=False,
        )
        print()

    # Step 3: Install ghunt + gitfive as libraries (via pip)
    print("Installing ghunt + gitfive libraries (via pip)...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "ghunt", "gitfive"],
        capture_output=False,
    )
    if result.returncode != 0:
        print("\n[!] Failed to install ghunt/gitfive libraries.")
        return
    print()

    # Step 4: Prompt to log in
    login_cmds = [
        ("ghunt", ["ghunt", "login"]),
        ("gitfive", ["gitfive", "login"]),
    ]
    for name, cmd in login_cmds:
        try:
            answer = input(f"Log in to {name} now? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if answer in ("y", "yes"):
            subprocess.run(cmd)


if "--setup" in sys.argv:
    _run_setup()
    sys.exit(0)


# --- Normal imports (require installed deps) ---
import argparse
import asyncio
from rich.console import Console
from .core import XsintEngine
from .config import get_config
from .ui import print_banner, print_results

# Import modules that have special setup routines
from .modules import haxalot_module

console = Console()


def main():
    parser = argparse.ArgumentParser(description="XSINT - OSINT Switchblade")
    parser.add_argument("target", nargs="?", help="Target to scan")
    parser.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List supported input types and API key status",
    )
    parser.add_argument(
        "--list-modules",
        nargs="?",
        const="all",
        metavar="TYPE",
        help="List modules for an input type (e.g. --list-modules email)",
    )

    # UPDATED: Changed nargs to '+' to allow 1 arg (setup) or 2 args (api key)
    parser.add_argument(
        "--set-key",
        nargs='+',
        metavar="ARGS",
        help="Set an API key (e.g. 'hibp YOUR_KEY') or setup a module (e.g. 'haxalot')",
    )

    parser.add_argument(
        "--setup",
        action="store_true",
        help="Install dependencies and external tools (GHunt, GitFive)",
    )
    parser.add_argument(
        "--proxy", metavar="URL", help="Proxy URL (e.g. socks5://127.0.0.1:9050)"
    )
    parser.add_argument("--set-proxy", metavar="URL", help="Save a default proxy URL")

    args = parser.parse_args()

    # Validate proxy URL if provided
    if hasattr(args, "proxy") and args.proxy:
        from urllib.parse import urlparse

        try:
            parsed = urlparse(args.proxy)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid proxy URL format: {args.proxy}")
            if ":" in parsed.netloc:
                host_port = parsed.netloc.rsplit(":", 1)
                if len(host_port) == 2:
                    try:
                        port = int(host_port[1])
                        if not (1 <= port <= 65535):
                            raise ValueError(f"Proxy port out of range: {port}")
                    except ValueError:
                        raise ValueError(f"Invalid proxy port: {host_port[1]}")
        except ValueError as e:
            console.print(f"[bold red][!] Proxy error: {e}[/bold red]")
            console.print("[yellow]Example formats:[/yellow]")
            console.print("  --proxy http://127.0.0.1:8080")
            console.print("  --proxy socks5://127.0.0.1:9050")
            sys.exit(1)

    # --- HANDLER: --set-key ---
    if args.set_key:
        # Case 1: Module Setup (1 argument)
        if len(args.set_key) == 1:
            service = args.set_key[0].lower()

            if service == "haxalot":
                try:
                    asyncio.run(haxalot_module.setup())
                except KeyboardInterrupt:
                    console.print("\n[bold yellow]Setup aborted.[/bold yellow]")
                except Exception as e:
                    console.print(f"\n[bold red]Setup failed: {e}[/bold red]")
                return
            else:
                console.print(f"[bold red]Unknown module for setup: {service}[/bold red]")
                console.print("Did you mean to provide a key? Usage: --set-key SERVICE KEY")
                return

        # Case 2: API Key Set (2 arguments)
        elif len(args.set_key) == 2:
            service, key = args.set_key
            config = get_config()
            config.set(f"{service.lower()}_key", key)
            console.print(f"[bold green]API key for '{service}' saved.[/bold green]")
            return

        else:
            console.print("[bold red]Invalid arguments for --set-key[/bold red]")
            console.print("Usage: --set-key SERVICE KEY  (or)  --set-key MODULE")
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
    console.print(
        f"[bold cyan]{type_name.upper()}[/bold cyan] [dim]{count} modules[/dim]"
    )

    for mod in modules:
        returns = ", ".join(mod["returns"]) if mod["returns"] else ""
        if mod["status"] == "locked":
            console.print(
                f"  [dim]x {mod['name']}: {returns} (requires {mod['api_key']} key)[/dim]"
            )
        else:
            console.print(f"  [green]+[/green] {mod['name']}: {returns}")


async def async_main(args):
    # If a proxy is passed via CLI, inject it into the global config memory
    # so that independent modules (like GHunt/httpx) can find it.
    if args.proxy:
        get_config().data["proxy"] = args.proxy

    engine = XsintEngine(proxy=getattr(args, "proxy", None))

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
            console.print(
                f"[yellow]Unknown type '{type_filter}'. Available: {valid}[/yellow]"
            )
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
        console.print(
            f"[bold green]Supported Input Types: {len(caps)} | Total Modules: {len(all_names)}[/bold green]\n"
        )

        keys = {}
        for type_name, modules in caps.items():
            active = sum(1 for m in modules if m["status"] == "active")
            total = len(modules)
            count = f"{active}/{total}" if active < total else str(total)
            console.print(
                f"  [bold cyan]{type_name.upper()}[/bold cyan] [dim]{count} modules[/dim]"
            )
            for mod in modules:
                if mod["api_key"] and mod["api_key"] not in keys:
                    keys[mod["api_key"]] = (
                        config.get_api_key(mod["api_key"]) is not None
                    )

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
        console.print("[yellow]Usage: xsint <target>[/yellow]")
        console.print("[dim]Example: xsint user:admin[/dim]")
        await engine.close()
        return

    # Handle Scan
    print_banner()

    with console.status(
        f"[bold green]Scanning {args.target}...[/bold green]", spinner="dots"
    ):
        report = await engine.scan(args.target)

    print_results(report)
    await engine.close()


if __name__ == "__main__":
    main()
