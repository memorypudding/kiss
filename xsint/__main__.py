import os
import shutil
import subprocess
import sys
import importlib


# --- Normal imports (require installed deps) ---
import argparse
import asyncio
import getpass
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from .core import XsintEngine
from .config import get_config
from .ui import print_banner, print_results

console = Console()

try:
    from rich_argparse import RichHelpFormatter
except Exception:
    RichHelpFormatter = argparse.HelpFormatter


API_KEY_SERVICES = {"hibp", "intelx", "9ghz"}
LOGIN_SERVICES = {"ghunt", "gitfive"}
SETUP_SERVICES = {"haxalot"}


def _normalize_service_name(service):
    s = service.strip().lower()
    if s in {"nineghz", "9ghz"}:
        return "9ghz"
    return s


def _run_external_login(service):
    service = _normalize_service_name(service)
    which_path = shutil.which(service)
    candidates = []
    if which_path:
        candidates.append([which_path, "login"])

    # Fallback to a direct pipx venv binary if present.
    candidates.append([os.path.expanduser(f"~/.local/pipx/venvs/{service}/bin/{service}"), "login"])

    # Fall back to module CLI in current runtime.
    candidates.append([sys.executable, "-m", service, "login"])

    for cmd in candidates:
        exe = cmd[0]
        if os.path.sep in exe and not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
            continue
        try:
            result = subprocess.run(cmd)
            if result.returncode == 0:
                return True
        except Exception:
            continue
    return False


def _print_auth_status():
    """Show auth status for key, login, and setup-gated modules."""
    config = get_config()
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=None,
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("module")
    table.add_column("auth")
    table.add_column("status")
    table.add_column("source")
    table.add_column("hint")

    api_auth_types = {
        "9ghz": "api_key(optional)",
        "hibp": "api_key",
        "intelx": "api_key",
    }

    for service in sorted(api_auth_types.keys()):
        env_key = os.environ.get(f"XSINT_{service.upper()}_API_KEY", "").strip()
        cfg_key = (config.get(f"{service}_key", "") or "").strip()
        if env_key:
            status = "[green]set[/green]"
            source = "env"
            hint = "-"
        elif cfg_key:
            status = "[green]set[/green]"
            source = "config"
            hint = "-"
        else:
            status = "[red]missing[/red]"
            source = "-"
            hint = f"xsint --auth {service} <value>"
        table.add_row(service, api_auth_types[service], status, source, hint)

    ready_checks = [
        ("ghunt", "login", "ghunt_lookup", "xsint --auth ghunt"),
        ("gitfive", "login", "gitfive_module", "xsint --auth gitfive"),
        ("haxalot", "setup(optional)", "haxalot_module", "xsint --auth haxalot"),
    ]
    for service, auth_type, module_name, setup_hint in ready_checks:
        status = "[red]missing[/red]"
        source = "-"
        hint = setup_hint

        try:
            imported = importlib.import_module(f"xsint.modules.{module_name}")
            checker = getattr(imported, "is_ready", None)
            if callable(checker):
                result = checker()
                if isinstance(result, tuple):
                    ready = bool(result[0]) if len(result) > 0 else False
                    reason = str(result[1]) if len(result) > 1 and result[1] else ""
                else:
                    ready = bool(result)
                    reason = ""
                if ready:
                    status = "[green]set[/green]"
                    source = "session"
                    hint = "-"
                elif reason == "not installed":
                    status = "[yellow]not installed[/yellow]"
                    source = "-"
                    hint = "install dependency"
                elif reason and reason != setup_hint:
                    hint = reason
            else:
                status = "[green]set[/green]"
                source = "-"
                hint = "-"
        except Exception:
            status = "[yellow]not installed[/yellow]"
            source = "-"
            hint = "install dependency"

        table.add_row(service, auth_type, status, source, hint)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        prog="xsint",
        description="XSINT - OSINT Switchblade",
        formatter_class=RichHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Target to scan")
    parser.add_argument(
        "--modules",
        "-m",
        nargs="?",
        const="all",
        metavar="TYPE",
        help="List modules for an input type (e.g. --modules email)",
    )

    parser.add_argument(
        "--auth",
        nargs="*",
        metavar="ARGS",
        help="Configure module credentials (e.g. --auth hibp KEY, --auth ghunt, --auth haxalot). Run --auth to show auth status.",
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

    # --- HANDLER: --auth ---
    if args.auth is not None:
        if len(args.auth) == 0:
            _print_auth_status()
            return

        service = _normalize_service_name(args.auth[0])

        if service in {"status", "list", "ls"}:
            _print_auth_status()
            return

        if service in API_KEY_SERVICES:
            config = get_config()
            if len(args.auth) >= 2:
                key = " ".join(args.auth[1:]).strip()
            else:
                key = getpass.getpass("Credential value: ").strip()

            if not key:
                console.print("[bold red]No credential value provided.[/bold red]")
                return

            config.set(f"{service}_key", key)
            console.print(f"[bold green]Saved credential:[/bold green] {service}")
            return

        if service in LOGIN_SERVICES:
            ok = _run_external_login(service)
            if not ok:
                console.print(
                    f"[bold red]Failed to run {service} login.[/bold red]\n"
                    f"[dim]Install {service} and run '{service} login' manually.[/dim]"
                )
            return

        if service in SETUP_SERVICES:
            try:
                from .modules import haxalot_module
                asyncio.run(haxalot_module.setup())
            except ModuleNotFoundError as e:
                missing = getattr(e, "name", "dependency")
                console.print(
                    f"\n[bold red]Haxalot setup unavailable: missing '{missing}'.[/bold red]"
                )
                console.print(
                    "[dim]Reinstall or update dependencies, then retry: "
                    "pip install -r requirements.txt[/dim]"
                )
            except KeyboardInterrupt:
                console.print("\n[bold yellow]Setup aborted.[/bold yellow]")
            except Exception as e:
                console.print(f"\n[bold red]Setup failed: {e}[/bold red]")
            return

        supported = ", ".join(
            sorted(API_KEY_SERVICES | LOGIN_SERVICES | SETUP_SERVICES)
        )
        console.print(
            Panel(
                f"[bold red]Unknown module:[/bold red] {service}\n"
                f"[dim]Supported: {supported}[/dim]",
                title="Invalid --auth usage",
                border_style="red",
            )
        )
        return

    if args.set_proxy is not None:
        config = get_config()
        if args.set_proxy.lower() in ("", "off", "none", "clear"):
            config.set("proxy", None)
            console.print("[bold green]Proxy cleared[/bold green]")
        else:
            config.set("proxy", args.set_proxy)
            console.print(f"[bold green]Proxy saved:[/bold green] {args.set_proxy}")
        return

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user.[/bold red]")
        sys.exit(1)


def _build_modules_plain_table(caps, type_filter="all"):
    """
    Build a module-centric borderless table.
    Columns: module, status, types.
    """
    def _ordered_add(target, values):
        for v in values:
            if v not in target:
                target.append(v)

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=None,
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("module")
    table.add_column("status")
    table.add_column("types")

    if type_filter == "all":
        selected_types = sorted(caps.keys())
    else:
        selected_types = [type_filter]

    by_module = {}
    for type_name in selected_types:
        for mod in caps.get(type_name, []):
            name = mod["name"]
            if name not in by_module:
                by_module[name] = {
                    "statuses": [],
                    "types": [],
                }
            row = by_module[name]
            _ordered_add(row["statuses"], [mod["status"]])
            _ordered_add(row["types"], [type_name.upper()])

    for module_name in sorted(by_module.keys()):
        row = by_module[module_name]
        effective_status = "active" if "active" in row["statuses"] else "locked"
        status_text = (
            "[green]active[/green]"
            if effective_status == "active"
            else "[red]locked[/red]"
        )
        table.add_row(
            module_name,
            status_text,
            "|".join(row["types"]) if row["types"] else "-",
        )

    return table


async def async_main(args):
    # If a proxy is passed via CLI, inject it into the global config memory
    # so that independent modules (like GHunt/httpx) can find it.
    if args.proxy:
        get_config().data["proxy"] = args.proxy

    engine = XsintEngine(proxy=getattr(args, "proxy", None))

    # Handle --modules [TYPE]
    if args.modules:
        caps = engine.get_capabilities()
        type_filter = args.modules.lower()

        if type_filter == "all":
            console.print(_build_modules_plain_table(caps, "all"))
        elif type_filter in caps:
            console.print(_build_modules_plain_table(caps, type_filter))
        else:
            valid = ", ".join(sorted(caps.keys()))
            console.print(
                f"[yellow]Unknown type '{type_filter}'. Available: {valid}[/yellow]"
            )
        await engine.close()
        return

    # Handle Missing Target
    if not args.target:
        print_banner()
        console.print(
            Panel(
                "[yellow]Missing target[/yellow]\n"
                "[dim]Example: xsint user:admin[/dim]\n"
                "[dim]Tip: run xsint --help for full usage.[/dim]",
                border_style="yellow",
            )
        )
        await engine.close()
        return

    # Handle Scan
    print_banner()

    progress = Progress(
        TextColumn("[bold cyan]{task.fields[kind]:<6}[/]"),
        SpinnerColumn(style="bold green"),
        TextColumn("{task.description}"),
        BarColumn(
            bar_width=22,
            complete_style="green",
            finished_style="green",
            pulse_style="green",
        ),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

    detect_task_id = None
    load_task_id = None
    run_task_id = None
    module_task_ids = {}

    with progress:
        detect_task_id = progress.add_task("detect target type", total=1, kind="STAGE")
        load_task_id = progress.add_task("load eligible modules", total=1, kind="STAGE")

        def on_progress(event):
            nonlocal run_task_id
            event_type = event.get("event")

            if event_type == "detect_done":
                target_type = event.get("target_type")
                if target_type:
                    progress.update(
                        detect_task_id,
                        completed=1,
                        description=f"target type: {str(target_type).upper()}",
                    )
                else:
                    progress.update(
                        detect_task_id,
                        completed=1,
                        description="target type: AMBIGUOUS",
                    )
                    progress.update(
                        load_task_id, completed=1, description="load modules (skipped)"
                    )
                return

            if event_type == "modules_loaded":
                count = int(event.get("count", 0))
                names = event.get("modules", [])
                skipped = event.get("skipped", []) or []
                skipped_count = len(skipped)
                if skipped_count:
                    description = f"eligible modules: {count} (skipped: {skipped_count})"
                else:
                    description = f"eligible modules: {count}"
                progress.update(
                    load_task_id, completed=1, description=description
                )
                run_task_id = progress.add_task(
                    "execute modules",
                    total=max(count, 1),
                    completed=0,
                    kind="STAGE",
                )
                for name in names:
                    module_task_ids[name] = progress.add_task(
                        f"{name}: queued", total=None, kind="MODULE"
                    )
                if count == 0:
                    progress.update(
                        run_task_id, completed=1, description="execute modules (none)"
                    )
                return

            if event_type == "module_start":
                name = str(event.get("module", "module"))
                if run_task_id is not None:
                    progress.update(run_task_id, description=f"execute: {name}")
                task_id = module_task_ids.get(name)
                if task_id is not None:
                    progress.update(task_id, description=f"{name}: running")
                return

            if event_type == "module_done":
                name = str(event.get("module", "module"))
                status = str(event.get("status", "ok"))
                task_id = module_task_ids.get(name)
                if task_id is not None:
                    if status == "ok":
                        progress.update(
                            task_id,
                            total=1,
                            completed=1,
                            description=f"{name}: done",
                        )
                    elif status == "timeout":
                        progress.update(
                            task_id,
                            total=1,
                            completed=1,
                            description=f"{name}: timeout",
                        )
                    else:
                        progress.update(
                            task_id,
                            total=1,
                            completed=1,
                            description=f"{name}: error",
                        )
                if run_task_id is not None:
                    progress.advance(run_task_id, 1)
                return

            if event_type == "scan_done" and run_task_id is not None:
                progress.update(run_task_id, description="modules complete")

        report = await engine.scan(args.target, progress_cb=on_progress)

    console.print()
    console.print("[dim]" + ("-" * 72) + "[/dim]")
    console.print()
    print_results(report)
    await engine.close()


if __name__ == "__main__":
    main()
