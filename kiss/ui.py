import os
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

def print_banner():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(base_dir, "logo.txt")
    
    console.print()
    console.print("[bold white]Keeping Identity Search Simple.[/bold white]")

    if not os.path.exists(logo_path):
        logo_path = os.path.join(base_dir, "..", "logo.txt")

    if os.path.exists(logo_path):
        try:
            with open(logo_path, "r", encoding="utf-8") as f:
                console.print(Text(f.read().rstrip(), style="bold green"))
        except:
            pass

    console.print("[dim white]An OSINT Essential.[/dim white]")
    console.print()

def print_results(report):
    target_type = report.get("type", "UNKNOWN").upper()
    results = report.get("results", [])
    error = report.get("error")

    if error:
        console.print(f"[bold red]![/bold red] {error}")
        return

    if not results:
        console.print("[dim italic]No intelligence gathered.[/dim italic]")
        console.print("")
        return

    # Group results by source
    groups = {}
    for item in results:
        source = item.get("source", "unknown")
        groups.setdefault(source, []).append(item)

    for source, items in groups.items():
        console.print(f"[bold cyan]{source}[/bold cyan]")
        for item in items:
            label = item.get("label", "N/A")
            value = str(item.get("value", "N/A"))
            console.print(f"  [green]{label}[/green]  {value}")
        console.print()