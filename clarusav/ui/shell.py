"""
clarusav/ui/shell.py
────────────────────
Interactive  clarus >  shell powered by prompt_toolkit.

Features
--------
• History (persisted to ~/.clarusav_history)
• Tab completion for built-in commands
• Colour prompt: bold bright-blue  clarus >
• Graceful Ctrl-C / Ctrl-D / EOF handling
• Dispatches to the Typer CLI app for every command typed
• '!' prefix escapes to the system shell  (e.g. !docker info)
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from prompt_toolkit                         import PromptSession
from prompt_toolkit.auto_suggest            import AutoSuggestFromHistory
from prompt_toolkit.completion              import WordCompleter
from prompt_toolkit.formatted_text          import HTML
from prompt_toolkit.history                 import FileHistory
from prompt_toolkit.styles                  import Style

# ── built-in commands known to the shell ─────────────────────────────────────
_COMMANDS = [
    "scan",
    "train",
    "report",
    "sandbox",
    "model",
    "audit",
    "help",
    "version",
    "exit",
    "quit",
]

_HISTORY_FILE = Path.home() / ".clarusav_history"

_STYLE = Style.from_dict(
    {
        "prompt":        "bold ansibrightblue",
        "prompt.clarus": "bold ansicyan",
        "prompt.gt":     "bold ansibrightblue",
    }
)


def _build_prompt() -> HTML:
    return HTML('<ansibrightblue><b>clarus</b></ansibrightblue> <b>&gt;</b> ')


def _run_system_command(cmd_str: str) -> None:
    """Run a raw system shell command and stream its output."""
    from rich.console import Console
    c = Console()
    try:
        result = subprocess.run(
            cmd_str, shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.stdout:
            c.print(result.stdout, end="")
        if result.returncode != 0:
            c.print(f"[dim red]exit code {result.returncode}[/dim red]")
    except Exception as exc:  # noqa: BLE001
        c.print(f"[bold red][!] Shell error:[/bold red] {exc}")


def _dispatch(line: str) -> bool:
    """
    Parse `line` and dispatch to the Typer CLI.
    Returns False if the shell should exit.

    Lines starting with '!' are forwarded directly to the system shell,
    e.g.  !docker info   or  !ls -la
    """
    from rich.console import Console
    c = Console()

    # ── system shell escape ────────────────────────────────────────────────
    if line.startswith("!"):
        _run_system_command(line[1:].strip())
        return True

    parts = shlex.split(line)
    if not parts:
        return True

    cmd = parts[0].lower()
    if cmd in ("exit", "quit"):
        return False

    if cmd == "help":
        from rich.table import Table
        t = Table(title="Available commands", style="bold cyan")
        t.add_column("Command", style="bold bright_blue", no_wrap=True)
        t.add_column("Description", style="white")
        descriptions = {
            "scan":    "Scan a file or directory for malware",
            "train":   "Train or retrain the model bundle",
            "doctor":  "Health-check environment, models, and Docker",
            "explain": "SHAP feature attribution for a PE file",
            "sandbox": "Manage the sandbox backend",
            "audit":   "Show the audit log",
            "version": "Print ClarusAV version",
            "!<cmd>":  "Run a system shell command  (e.g. !docker info)",
            "exit":    "Exit the shell",
        }
        for name, desc in descriptions.items():
            t.add_row(name, desc)
        c.print(t)
        return True

    # Delegate to the Typer CLI
    try:
        from clarusav.cli.main import app
        app(args=parts, standalone_mode=False)
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        c.print(
            f"[bold red][!] Error:[/bold red] {exc}\n"
            f"[dim]Tip: to run system commands use  [bold]!{line}[/bold][/dim]"
        )

    return True


def run_shell() -> None:
    """Start the interactive  clarus >  shell."""
    completer = WordCompleter(_COMMANDS, ignore_case=True)
    session: PromptSession = PromptSession(
        history=FileHistory(str(_HISTORY_FILE)),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
        style=_STYLE,
        mouse_support=False,
    )

    while True:
        try:
            line = session.prompt(_build_prompt()).strip()
        except KeyboardInterrupt:
            # Ctrl-C clears the line — do not exit
            continue
        except EOFError:
            # Ctrl-D exits
            break

        if line:
            keep_going = _dispatch(line)
            if not keep_going:
                break

    from rich.console import Console
    Console().print("[dim cyan]Goodbye.[/dim cyan]")
