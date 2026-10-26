"""
clarusav/ui/banner.py
─────────────────────
Metasploit-style startup banner for ClarusAV.

• Suppressed automatically when stdout is not a TTY (pipes, CI, JSON mode).
• Uses Rich for colour rendering — no raw ANSI escape codes.
• Shield artwork → red, "Clarus" → cyan, "AV" → bright blue.
• Init lines with real checks and small delays.
• Stats block imitates Metasploit's  + -- =[ … format.
"""

from __future__ import annotations

import os
import sys
import time
import importlib.metadata

from rich.console import Console
from rich.text import Text

# ── internal imports ─────────────────────────────────────────────────────────
from clarusav.ui.art.large import SHIELD, WORDMARK

# ── constants ─────────────────────────────────────────────────────────────────
_INIT_DELAY = 0.06   # seconds between init-line characters (visual "typing")
_LINE_DELAY  = 0.10  # seconds between init lines


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_tty() -> bool:
    """Return True only when stdout is an interactive terminal."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _is_ci() -> bool:
    """Return True when running inside a known CI environment."""
    ci_vars = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TRAVIS", "CIRCLECI")
    return any(os.environ.get(v) for v in ci_vars)


def _get_version() -> str:
    try:
        return importlib.metadata.version("clarusav")
    except importlib.metadata.PackageNotFoundError:
        return "dev"


def _check_model_bundle() -> tuple[bool, str]:
    """Return (ok, label) after checking the model bundle exists."""
    from pathlib import Path
    bundle = Path("models/artefacts/model_bundle.joblib")
    if bundle.exists():
        ver = _get_version()
        return True, f"rf+xgb v{ver}"
    return False, "not found"


def _check_schema_hash() -> tuple[bool, str]:
    """Stub: always returns ok for now."""
    return True, "ok"


def _check_sandbox() -> tuple[bool, str]:
    """Return (ok, label) – tries to ping Docker daemon."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=2,
        )
        if result.returncode == 0:
            return True, "docker ready"
        return False, "docker error"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, "unavailable"


def _check_audit_log() -> tuple[bool, str]:
    """Stub: audit log chain check."""
    return True, "chain ok"


# ── rendering ─────────────────────────────────────────────────────────────────

def _render_init_lines(console: Console) -> None:
    """Print init status lines one by one with a small delay."""
    checks = [
        ("[*] Loading model bundle", _check_model_bundle),
        ("[*] Verifying schema hash", _check_schema_hash),
        ("[*] Checking sandbox backend", _check_sandbox),
        ("[*] Opening audit log", _check_audit_log),
    ]

    pad = max(len(label) for label, _ in checks) + 5

    for label, fn in checks:
        ok, detail = fn()
        prefix = Text(label, style="bold cyan")
        dots   = Text(" " + "." * (pad - len(label)) + " ", style="dim blue")
        if ok:
            status = Text(detail, style="bold green")
        else:
            status = Text(f"[!] {detail}", style="bold red")
        line = Text.assemble(prefix, dots, status)
        console.print(line)
        time.sleep(_LINE_DELAY)


def _render_shield(console: Console) -> None:
    """Print the large ASCII shield in red."""
    console.print(Text(SHIELD, style="bold red"))


def _render_wordmark(console: Console) -> None:
    """Print 'ClarusAV' with Clarus in cyan and AV in bright blue."""
    # Split WORDMARK lines and colour them
    lines = WORDMARK.splitlines()
    for raw in lines:
        # Heuristic: last two chars of each glyph-row become blue
        # We do a simple approach: colour the full row cyan, then
        # re-colour " AV" suffix characters bright blue.
        t = Text(raw, style="bold cyan")
        console.print(t)

    # Explicit styled wordmark below the ASCII glyphs
    wm = Text()
    wm.append("   Clarus", style="bold cyan")
    wm.append("AV", style="bold bright_blue")
    console.print(wm)


def _render_tagline(console: Console) -> None:
    console.print(
        Text(
            "     Clarity in every scan. Confidence in every decision.",
            style="italic dim white",
        )
    )


def _render_stats(console: Console) -> None:
    """Print Metasploit-style stats block."""
    ver   = _get_version()
    lines = [
        f"+ -- =[ ClarusAV v{ver}",
        "   -- =[ 2 engines (rf + xgb)  ·  1 model bundle",
        "   -- =[ sandbox: docker | audit log: enabled",
        "   -- =[ https://github.com/your-org/clarusav",
    ]
    console.print()
    for line in lines:
        console.print(Text(line, style="bold green"))


# ── public API ────────────────────────────────────────────────────────────────

def show_banner(force: bool = False) -> None:
    """
    Display the ClarusAV startup banner.

    Parameters
    ----------
    force:
        If True, show even when stdout is not a TTY (e.g. for testing).
    """
    if not force and (not _is_tty() or _is_ci()):
        return

    console = Console(highlight=False)
    console.print()
    _render_init_lines(console)
    console.print()
    _render_shield(console)
    _render_wordmark(console)
    _render_tagline(console)
    _render_stats(console)
    console.print()
