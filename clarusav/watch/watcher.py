"""Live filesystem watcher and Rich TUI monitor for ClarusAV.

Watches a directory for new or modified PE files, runs scans through a bounded
concurrency worker pool with debouncing, updates a live Rich dashboard,
and automatically isolates malicious files if quarantine is enabled.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


@dataclass
class WatchEventRecord:
    timestamp: float
    file_path: str
    verdict: str
    score: float
    action: str


class ScanWorkerPool:
    """Thread pool with debounced queuing and maximum concurrency."""

    def __init__(
        self,
        scan_fn: Callable[[Path], dict[str, Any]],
        max_workers: int = 2,
        debounce_seconds: float = 1.0,
    ) -> None:
        self.scan_fn = scan_fn
        self.max_workers = max_workers
        self.debounce_seconds = debounce_seconds
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="clarus-watcher"
        )
        self._pending_files: dict[str, float] = {}
        self._lock = threading.Lock()
        self._recent_events: deque[WatchEventRecord] = deque(maxlen=20)
        self.total_scanned = 0
        self.total_malicious = 0
        self.total_quarantined = 0
        self.total_errors = 0

    def enqueue(self, path: Path) -> None:
        """Enqueue path with timestamp debouncing."""
        now = time.time()
        with self._lock:
            self._pending_files[str(path.resolve())] = now

    def process_pending(self) -> None:
        """Schedule files whose debounce window has elapsed."""
        now = time.time()
        to_schedule: list[str] = []
        with self._lock:
            for p_str, ts in list(self._pending_files.items()):
                if now - ts >= self.debounce_seconds:
                    to_schedule.append(p_str)
                    del self._pending_files[p_str]

        for p_str in to_schedule:
            self.executor.submit(self._run_scan, Path(p_str))

    def _run_scan(self, path: Path) -> None:
        try:
            if not path.exists() or not path.is_file():
                return
            result = self.scan_fn(path)
            verdict = result.get("verdict", "UNKNOWN")
            score = result.get("score", 0.0)
            action = result.get("action", "None")

            with self._lock:
                self.total_scanned += 1
                if verdict == "MALICIOUS":
                    self.total_malicious += 1
                if "quarantine" in action.lower():
                    self.total_quarantined += 1

                self._recent_events.append(
                    WatchEventRecord(
                        timestamp=time.time(),
                        file_path=path.name,
                        verdict=str(verdict),
                        score=score,
                        action=action,
                    )
                )
        except Exception as e:
            logger.error("Scan worker error on %s: %s", path, e)
            with self._lock:
                self.total_errors += 1

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "scanned": self.total_scanned,
                "malicious": self.total_malicious,
                "quarantined": self.total_quarantined,
                "errors": self.total_errors,
                "pending": len(self._pending_files),
                "recent": list(self._recent_events),
            }

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)


class WatchEventHandler(FileSystemEventHandler):
    """Watches for file creations and modifications."""

    WATCHED_EXTENSIONS = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx", ".cpl"}

    def __init__(self, pool: ScanWorkerPool) -> None:
        super().__init__()
        self.pool = pool

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            p = Path(event.src_path)
            if p.suffix.lower() in self.WATCHED_EXTENSIONS or not p.suffix:
                self.pool.enqueue(p)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            p = Path(event.src_path)
            if p.suffix.lower() in self.WATCHED_EXTENSIONS or not p.suffix:
                self.pool.enqueue(p)


class DirectoryWatcher:
    """Orchestrates filesystem watcher, worker pool, and Rich live dashboard."""

    def __init__(
        self,
        watch_dir: Path,
        scan_fn: Callable[[Path], dict[str, Any]],
        max_workers: int = 2,
        debounce_seconds: float = 0.5,
    ) -> None:
        self.watch_dir = watch_dir.resolve()
        self.pool = ScanWorkerPool(
            scan_fn=scan_fn, max_workers=max_workers, debounce_seconds=debounce_seconds
        )
        self.handler = WatchEventHandler(self.pool)
        self.observer = Observer()
        self.observer.schedule(self.handler, str(self.watch_dir), recursive=True)
        self._running = False

    def build_dashboard(self) -> Layout:
        stats = self.pool.get_stats()
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
        )

        header_table = Table.grid(expand=True)
        header_table.add_column(justify="left")
        header_table.add_column(justify="right")
        header_table.add_row(
            f"[bold cyan]ClarusAV Active Guard[/bold cyan] -> Watching: [yellow]{self.watch_dir}[/yellow]",
            f"Scanned: [bold white]{stats['scanned']}[/bold white] | "
            f"Malicious: [bold red]{stats['malicious']}[/bold red] | "
            f"Quarantined: [bold yellow]{stats['quarantined']}[/bold yellow] | "
            f"Queue: [cyan]{stats['pending']}[/cyan]",
        )
        layout["header"].update(Panel(header_table, style="blue"))

        events_table = Table(expand=True, box=None)
        events_table.add_column("Time", style="dim", width=10)
        events_table.add_column("Filename", style="bold white", width=25)
        events_table.add_column("Verdict", width=14)
        events_table.add_column("Score", width=10)
        events_table.add_column("Action Taken", width=20)

        for ev in reversed(stats["recent"]):
            time_str = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            if ev.verdict == "MALICIOUS":
                v_style = "[bold red]MALICIOUS[/bold red]"
            elif ev.verdict == "BENIGN":
                v_style = "[bold green]BENIGN[/bold green]"
            else:
                v_style = "[bold yellow]" + ev.verdict + "[/bold yellow]"

            events_table.add_row(
                time_str,
                ev.file_path,
                v_style,
                f"{ev.score:.3f}",
                ev.action,
            )

        layout["body"].update(Panel(events_table, title="Recent Events", border_style="dim"))
        return layout

    def start(self, poll_interval: float = 0.2, interactive: bool = True) -> None:
        """Start watcher observer and event loop."""
        self.observer.start()
        self._running = True
        console = Console()

        if not interactive:
            return

        try:
            with Live(self.build_dashboard(), refresh_per_second=4, console=console) as live:
                while self._running:
                    self.pool.process_pending()
                    live.update(self.build_dashboard())
                    time.sleep(poll_interval)
        except (KeyboardInterrupt, SystemExit):
            self.stop()

    def stop(self) -> None:
        self._running = False
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=1.0)
        self.pool.shutdown()
