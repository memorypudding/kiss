from rich.console import Console
from rich.text import Text

console = Console()

def print_banner():
    # Banner intentionally suppressed for cleaner output.
    return

def print_results(report):
    results = report.get("results", [])
    target_type = str(report.get("type", "unknown")).upper()
    error = report.get("error")

    if error:
        console.print("[bold]REPORT[/bold]")
        console.print(f"  type   : {target_type}")
        console.print("  status : aborted")
        console.print(f"  error  : {error}")
        console.print()
        return

    if not results:
        console.print("[bold]REPORT[/bold]")
        console.print(f"  type     : {target_type}")
        console.print("  status   : completed")
        console.print("  findings : 0")
        console.print("  sources  : 0")
        console.print()
        return

    source_groups = {}
    for item in results:
        src = item.get("source", "unknown")
        source_groups.setdefault(src, []).append(item)

    total_findings = len(results)
    total_sources = len(source_groups)

    console.print("[bold]REPORT[/bold]")
    console.print(f"  type      : {target_type}")
    console.print("  status    : completed")
    console.print(f"  findings  : {total_findings}")
    console.print(f"  sources   : {total_sources}")
    console.print()

    for source in sorted(source_groups.keys()):
        items = source_groups[source]
        console.print(f"[bold]{source}[/bold] [dim]({len(items)} findings)[/dim]")
        max_label = max(len(_display_label(item)) for item in items)

        for item in items:
            _print_item(item, max_label)
        console.print()

def _normalize_risk(risk):
    val = str(risk or "low").lower()
    if val in {"critical", "high"}:
        return "high"
    if val == "medium":
        return "medium"
    return "low"

def _display_label(item):
    label = str(item.get("label", "N/A"))
    group = item.get("group")
    if group:
        return f"{group} / {label}"
    return label

def _print_item(item, max_label):
    """Print one report finding line."""
    label = _display_label(item)
    value = str(item.get("value", "N/A"))
    risk = _normalize_risk(item.get("risk", "low"))

    marker = "-"
    val_style = "white"
    if risk == "high":
        marker = "!"
        val_style = "bold red"
    elif risk == "medium":
        marker = "~"
        val_style = "yellow"

    line = Text()
    line.append(f"  {marker} ", style="dim white")
    line.append(f"{label.ljust(max_label)}", style="dim white")
    line.append(" : ", style="dim white")
    line.append(value, style=val_style)
    console.print(line)
