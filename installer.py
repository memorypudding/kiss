#!/usr/bin/env python3
"""Cross-platform installer for xsint."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

MIN_MINOR = 10
MAX_MINOR = 13
RICH_CONSOLE = None
RICH_ERR_CONSOLE = None
RICH_PANEL = None


def info(message: str) -> None:
    if not message:
        print("")
        return
    if RICH_CONSOLE is not None:
        RICH_CONSOLE.print(message)
    else:
        print(message)


def section(message: str) -> None:
    if RICH_CONSOLE is not None:
        RICH_CONSOLE.print(f"[bold cyan]{message}[/bold cyan]")
    else:
        print(message)


def success(message: str) -> None:
    if RICH_CONSOLE is not None:
        RICH_CONSOLE.print(f"[bold green]{message}[/bold green]")
    else:
        print(message)


def warn(message: str) -> None:
    if RICH_CONSOLE is not None:
        RICH_CONSOLE.print(f"[yellow]{message}[/yellow]")
    else:
        print(message)


def fail(message: str) -> None:
    if RICH_ERR_CONSOLE is not None:
        RICH_ERR_CONSOLE.print(f"[bold red]{message}[/bold red]")
    else:
        print(message, file=sys.stderr)
    raise SystemExit(1)


def setup_rich(force: bool = False) -> None:
    global RICH_CONSOLE, RICH_ERR_CONSOLE, RICH_PANEL
    if RICH_CONSOLE is not None and not force:
        return
    try:
        from rich.console import Console
        from rich.panel import Panel
    except Exception:
        return
    RICH_CONSOLE = Console()
    RICH_ERR_CONSOLE = Console(stderr=True)
    RICH_PANEL = Panel


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_capture(command: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(command, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def run(command: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(command, cwd=str(cwd) if cwd else None)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def find_python() -> str:
    candidates: list[list[str]] = []
    if sys.executable:
        candidates.append([sys.executable])

    for version in ("3.13", "3.12", "3.11", "3.10"):
        candidates.append([f"python{version}"])
        candidates.append(["py", f"-{version}"])

    candidates.extend([["python3"], ["python"], ["py", "-3"]])

    checked: set[tuple[str, ...]] = set()
    for cmd in candidates:
        key = tuple(cmd)
        if key in checked:
            continue
        checked.add(key)

        binary = cmd[0]
        if not Path(binary).is_file() and not command_exists(binary):
            continue

        probe = cmd + [
            "-c",
            "import sys; print(sys.version_info.minor); print(sys.executable)",
        ]
        code, out, _ = run_capture(probe)
        if code != 0:
            continue
        lines = out.splitlines()
        if len(lines) < 2:
            continue
        try:
            minor = int(lines[0].strip())
        except ValueError:
            continue
        if MIN_MINOR <= minor <= MAX_MINOR:
            return lines[1].strip()

    fail(
        f"[!] No compatible Python 3.{MIN_MINOR}-3.{MAX_MINOR} interpreter found.\n"
        "Install Python and rerun this installer."
    )
    return ""


def ensure_pip(python: str) -> None:
    if run_capture([python, "-m", "pip", "--version"])[0] == 0:
        return
    run_capture([python, "-m", "ensurepip", "--upgrade"])
    if run_capture([python, "-m", "pip", "--version"])[0] != 0:
        fail(
            f"[!] pip is not available for {python}.\n"
            "Install pip for your Python interpreter and rerun."
        )


def pip_install(python: str, args: list[str]) -> None:
    cmd = [python, "-m", "pip", "install", "--user", "--no-warn-script-location"] + args
    code, out, err = run_capture(cmd)
    if code == 0:
        return

    text = f"{out}\n{err}".lower()
    if "externally-managed-environment" in text or "externally managed" in text:
        run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--break-system-packages",
                "--user",
                "--no-warn-script-location",
            ]
            + args
        )
        return

    if out:
        info(out)
    if err:
        if RICH_ERR_CONSOLE is not None:
            RICH_ERR_CONSOLE.print(err)
        else:
            print(err, file=sys.stderr)
    raise SystemExit(code)


def copy_tree(src: Path, dst: Path) -> None:
    ignore = shutil.ignore_patterns(
        ".git",
        ".venv",
        "__pycache__",
        ".claude",
        "*.pyc",
    )
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=ignore)


def write_unix_wrapper(path: Path, python: str, module: str, is_gitfive: bool = False) -> None:
    if is_gitfive:
        content = (
            "#!/usr/bin/env sh\n"
            f'exec "{python}" -c "from gitfive.lib.cli import parse_args; parse_args()" "$@"\n'
        )
    else:
        content = f'#!/usr/bin/env sh\nexec "{python}" -m {module} "$@"\n'
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def write_windows_wrapper(path: Path, python: str, module: str, is_gitfive: bool = False) -> None:
    if is_gitfive:
        content = f'@echo off\r\n"{python}" -c "from gitfive.lib.cli import parse_args; parse_args()" %*\r\n'
    else:
        content = f'@echo off\r\n"{python}" -m {module} %*\r\n'
    path.write_text(content, encoding="utf-8")


def default_install_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "xsint"
    return Path.home() / ".local" / "share" / "xsint"


def default_bin_dir(python: str) -> Path:
    if os.name == "nt":
        code, out, _ = run_capture([python, "-c", "import site; print(site.getuserbase())"])
        if code == 0 and out.strip():
            return Path(out.strip()) / "Scripts"
        return Path.home() / "AppData" / "Roaming" / "Python" / "Scripts"
    return Path.home() / ".local" / "bin"


def path_has_dir(target: Path) -> bool:
    raw = os.environ.get("PATH", "")
    sep = ";" if os.name == "nt" else ":"
    resolved_target = str(target.resolve())
    for entry in raw.split(sep):
        if not entry:
            continue
        try:
            if str(Path(entry).resolve()) == resolved_target:
                return True
        except OSError:
            continue
    return False


def suggested_shell_rc() -> str:
    shell = Path(os.environ.get("SHELL", "")).name.lower()
    if "zsh" in shell:
        return "~/.zshrc"
    return "~/.bashrc"


def maybe_configure_auth(python: str, install_dir: Path, skip_prompt: bool) -> None:
    if skip_prompt:
        return
    for tool in ("ghunt", "gitfive", "haxalot"):
        answer = input(f"Configure {tool} now? (y/n): ").strip().lower()
        if answer.startswith("y"):
            run([python, "-m", "xsint", "--auth", tool], cwd=install_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install xsint.")
    parser.add_argument(
        "--install-dir",
        default=os.environ.get("XSINT_INSTALL_DIR"),
        help="Install location for project files.",
    )
    parser.add_argument(
        "--bin-dir",
        default=os.environ.get("XSINT_BIN_DIR"),
        help="Install location for wrapper commands.",
    )
    parser.add_argument(
        "--no-auth-prompt",
        action="store_true",
        help="Skip post-install auth prompts.",
    )
    return parser.parse_args()


def main() -> None:
    setup_rich()
    args = parse_args()
    python = find_python()

    py_ver = run_capture([python, "--version"])[1] or run_capture([python, "--version"])[2]
    section(f"Using: {python} ({py_ver})")
    info("")

    script_dir = Path(__file__).resolve().parent
    install_dir = Path(args.install_dir).expanduser() if args.install_dir else default_install_dir()
    bin_dir = Path(args.bin_dir).expanduser() if args.bin_dir else default_bin_dir(python)

    install_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)

    ensure_pip(python)
    pip_install(python, ["--upgrade", "pip", "--quiet"])

    section(f"Copying xsint into {install_dir}...")
    copy_tree(script_dir, install_dir)
    info("")

    section("Installing xsint and dependencies...")
    pip_install(python, ["-e", str(install_dir), "--quiet"])
    setup_rich(force=True)
    info("")

    section("Installing ghunt + gitfive...")
    pip_install(python, ["ghunt", "gitfive", "--quiet"])
    info("")

    if os.name == "nt":
        write_windows_wrapper(bin_dir / "xsint.cmd", python, "xsint")
        write_windows_wrapper(bin_dir / "ghunt.cmd", python, "ghunt")
        write_windows_wrapper(bin_dir / "gitfive.cmd", python, "gitfive", is_gitfive=True)
        success(f"Installed xsint wrapper to: {bin_dir / 'xsint.cmd'}")
        success(f"Installed ghunt wrapper to: {bin_dir / 'ghunt.cmd'}")
        success(f"Installed gitfive wrapper to: {bin_dir / 'gitfive.cmd'}")
    else:
        write_unix_wrapper(bin_dir / "xsint", python, "xsint")
        write_unix_wrapper(bin_dir / "ghunt", python, "ghunt")
        write_unix_wrapper(bin_dir / "gitfive", python, "gitfive", is_gitfive=True)
        success(f"Installed xsint wrapper to: {bin_dir / 'xsint'}")
        success(f"Installed ghunt wrapper to: {bin_dir / 'ghunt'}")
        success(f"Installed gitfive wrapper to: {bin_dir / 'gitfive'}")
    info("")

    if not path_has_dir(bin_dir):
        if os.name == "nt":
            warn("Add this directory to your PATH, then reopen your terminal:")
            warn(f"  {bin_dir}")
        else:
            rc_file = suggested_shell_rc()
            warn("Run this now for the current shell:")
            warn(f"  export PATH=\"{bin_dir}:$PATH\"")
            warn("")
            warn(f"Persist it for new shells ({rc_file}):")
            warn(f"  echo 'export PATH=\"{bin_dir}:$PATH\"' >> {rc_file}")
        info("")

    maybe_configure_auth(python, install_dir, args.no_auth_prompt)

    info("")
    if RICH_CONSOLE is not None and RICH_PANEL is not None:
        run_cmd = "xsint <target>" if path_has_dir(bin_dir) else f"{bin_dir / 'xsint'} <target>"
        panel_text = (
            f"[bold]Install dir:[/bold] {install_dir}\n"
            f"[bold]Bin dir:[/bold] {bin_dir}\n"
            f"[bold]Run:[/bold] {run_cmd}"
        )
        RICH_CONSOLE.print(RICH_PANEL.fit(panel_text, title="Setup complete", border_style="green"))
    else:
        success("Setup complete!")
        if path_has_dir(bin_dir):
            info("  Run: xsint <target>")
        else:
            info(f"  Run: {bin_dir / 'xsint'} <target>")


if __name__ == "__main__":
    main()
