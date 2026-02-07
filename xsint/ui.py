import os
from rich.console import Console
from rich.text import Text

console = Console()

DEFAULT_THEME = {"color": "white", "icon": "●"}

def print_banner():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    logo_path = os.path.join(base_dir, "..", "logo.txt")
    console.print()
    if os.path.exists(logo_path):
        try:
            with open(logo_path, "r", encoding="utf-8") as f:
                for line in f:
                    console.print(Text(f" {line.rstrip()}", style="bold sea_green3"))
        except:
            pass
    else:
        console.print(" [bold sea_green3]X S I N T[/] [dim]OSINT Switchblade[/]")
    console.print(Text(" ╭─ [ SYSTEM ONLINE ]", style="dim white"))
    console.print(Text(" │", style="dim white"))

def print_results(report):
    results = report.get("results", [])
    themes = report.get("themes", {})
    error = report.get("error")

    if error:
        console.print(f" ├─ [bold red]![/bold red] [red]{error}[/red]")
        console.print(Text(" ╰─ [ ABORTED ]", style="dim white"))
        console.print()
        return

    if not results:
        console.print(Text(" ├─ [?] No intelligence gathered.", style="dim yellow"))
        console.print(Text(" ╰─ [ COMPLETED ]", style="dim white"))
        console.print()
        return

    # 1. Group by Main Source (e.g., "GHunt", "DNS")
    source_groups = {}
    for item in results:
        src = item.get("source", "unknown")
        source_groups.setdefault(src, []).append(item)

    sources = list(source_groups.keys())
    total_sources = len(sources)

    for i, source in enumerate(sources):
        items = source_groups[source]
        theme = themes.get(source, DEFAULT_THEME)
        color = theme.get("color", "white")
        icon = theme.get("icon", "●")

        # Tree connectors for Main Source
        is_last_source = (i == total_sources - 1)
        src_connector = " ╰─" if is_last_source else " ├─"
        src_pipe      = "   " if is_last_source else " │ "

        # Print Main Source Header
        header = Text()
        header.append(src_connector, style="dim white")
        header.append(f" {icon} ", style=f"bold {color}")
        header.append(f"{source}", style=f"bold {color}")
        console.print(header)

        # 2. Check for Sub-Groups (e.g., "Account", "Chat")
        # We split items into "grouped" and "ungrouped"
        sub_groups = {}
        ungrouped_items = []
        for item in items:
            grp = item.get("group")
            if grp:
                sub_groups.setdefault(grp, []).append(item)
            else:
                ungrouped_items.append(item)

        # A. Print Ungrouped Items (Standard Flat Style)
        if ungrouped_items:
            max_label = max([len(x.get("label", "")) for x in ungrouped_items])
            for item in ungrouped_items:
                _print_item(item, max_label, src_pipe, indent="    ")

        # B. Print Sub-Groups (Nested Style)
        group_names = list(sub_groups.keys())
        total_groups = len(group_names)
        
        for j, grp_name in enumerate(group_names):
            grp_items = sub_groups[grp_name]
            
            # Sub-tree connectors
            is_last_group = (j == total_groups - 1)
            # If we have subgroups, we indent deeper
            grp_connector = " ╰─" if is_last_group else " ├─"
            grp_pipe      = "   " if is_last_group else " │ "
            
            # Print Sub-Group Header
            grp_header = Text()
            grp_header.append(src_pipe, style="dim white")
            grp_header.append("    ") # Indent from Source
            grp_header.append(grp_connector, style="dim white")
            grp_header.append(f" {grp_name}", style="bold white") # Sub-group title
            console.print(grp_header)

            # Print Items inside Sub-Group
            max_label = max([len(x.get("label", "")) for x in grp_items])
            for item in grp_items:
                # We need to carry the pipes down: Source Pipe -> Indent -> Group Pipe -> Indent
                prefix = src_pipe + "    " + grp_pipe
                _print_item(item, max_label, prefix, indent="    ")
            
            # Add spacer between groups if needed
            if not is_last_group:
                console.print(Text(src_pipe + "    " + " │", style="dim white"))

        # Spacer between Sources
        if not is_last_source:
            console.print(Text(" │", style="dim white"))

    console.print()

def _print_item(item, max_label, pipe_prefix, indent="    "):
    """Helper to print a single key-value line with correct pipes"""
    label = item.get("label", "N/A")
    value = str(item.get("value", "N/A"))
    risk = item.get("risk", "low").lower()

    val_style = "white"
    if risk == "high": val_style = "bold red"
    elif risk == "medium": val_style = "yellow"

    line = Text()
    line.append(pipe_prefix, style="dim white")
    line.append(indent)
    line.append(f"{label.ljust(max_label)}", style="dim white")
    line.append(" : ", style="dim white")
    line.append(value, style=val_style)
    console.print(line)