"""File system watcher for continuous skill monitoring.

Uses the watchdog library to monitor skill directories for changes
and trigger automatic re-scans when files are modified.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Callable

try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler,
        FileCreatedEvent,
        FileModifiedEvent,
        FileDeletedEvent,
    )

    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

logger = logging.getLogger(__name__)


class SkillChangeHandler:
    """Handles file system events for monitored skill directories.

    If watchdog is not available, provides a polling-based fallback.
    """

    def __init__(
        self,
        on_change: Callable[[str, str], Any] | None = None,
        debounce_seconds: float = 2.0,
    ) -> None:
        self._on_change = on_change
        self._debounce_seconds = debounce_seconds
        self._pending_changes: dict[str, str] = {}
        self._debounce_task: asyncio.Task[None] | None = None

    def notify_change(self, file_path: str, event_type: str) -> None:
        """Record a file change to be processed after debounce period."""
        self._pending_changes[file_path] = event_type

    async def process_pending(self) -> list[tuple[str, str]]:
        """Process and return pending changes, clearing the queue."""
        changes = list(self._pending_changes.items())
        self._pending_changes.clear()
        return changes


class _WatchdogHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):  # type: ignore[misc]
    """Watchdog event handler that bridges to SkillChangeHandler."""

    def __init__(self, change_handler: SkillChangeHandler) -> None:
        self._change_handler = change_handler

    def on_created(self, event: Any) -> None:
        if not event.is_directory:
            self._change_handler.notify_change(event.src_path, "created")

    def on_modified(self, event: Any) -> None:
        if not event.is_directory:
            self._change_handler.notify_change(event.src_path, "modified")

    def on_deleted(self, event: Any) -> None:
        if not event.is_directory:
            self._change_handler.notify_change(event.src_path, "deleted")


class SkillDirectoryWatcher:
    """Watches skill directories for changes and triggers re-scans.

    Uses watchdog for efficient filesystem monitoring when available,
    or falls back to polling-based change detection.
    """

    def __init__(
        self,
        on_change: Callable[[str, str], Any] | None = None,
        debounce_seconds: float = 2.0,
    ) -> None:
        self._change_handler = SkillChangeHandler(
            on_change=on_change,
            debounce_seconds=debounce_seconds,
        )
        self._observer: Any = None
        self._watched_paths: set[str] = set()
        self._running = False
        self._poll_interval = 5.0  # seconds for fallback polling

    @property
    def is_available(self) -> bool:
        """Check if native filesystem watching is available."""
        return WATCHDOG_AVAILABLE

    def watch(self, path: str | Path) -> bool:
        """Start watching a directory for changes.

        Returns True if watching started successfully.
        """
        path_str = str(Path(path).resolve())
        if not Path(path_str).is_dir():
            logger.error(f"Cannot watch non-directory: {path_str}")
            return False

        if path_str in self._watched_paths:
            return True

        self._watched_paths.add(path_str)

        if WATCHDOG_AVAILABLE and self._observer is None:
            self._observer = Observer()

        if WATCHDOG_AVAILABLE and self._observer is not None:
            handler = _WatchdogHandler(self._change_handler)
            self._observer.schedule(handler, path_str, recursive=True)
            if not self._observer.is_alive():
                self._observer.start()

        self._running = True
        logger.info(f"Watching directory: {path_str}")
        return True

    def unwatch(self, path: str | Path) -> bool:
        """Stop watching a directory."""
        path_str = str(Path(path).resolve())
        self._watched_paths.discard(path_str)

        if not self._watched_paths and self._observer is not None:
            self.stop()

        return True

    def stop(self) -> None:
        """Stop all file watching."""
        self._running = False
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
            self._observer = None

    async def get_changes(self) -> list[tuple[str, str]]:
        """Get pending file changes since last check."""
        return await self._change_handler.process_pending()

    @property
    def watched_paths(self) -> set[str]:
        """Return the set of currently watched paths."""
        return self._watched_paths.copy()

    @property
    def is_running(self) -> bool:
        return self._running

    async def poll_once(self) -> list[tuple[str, str]]:
        """Single poll cycle for fallback mode.

        When watchdog is not available, this can be called periodically
        to check for file modifications using stat-based detection.
        """
        changes: list[tuple[str, str]] = []

        if not hasattr(self, "_last_mtimes"):
            self._last_mtimes: dict[str, float] = {}

        current_mtimes: dict[str, float] = {}
        for watched_path in self._watched_paths:
            try:
                for file_path in Path(watched_path).rglob("*"):
                    if file_path.is_file():
                        key = str(file_path)
                        mtime = file_path.stat().st_mtime
                        current_mtimes[key] = mtime

                        if key not in self._last_mtimes:
                            changes.append((key, "created"))
                        elif self._last_mtimes[key] != mtime:
                            changes.append((key, "modified"))
            except OSError:
                continue

        # Detect deletions
        for key in self._last_mtimes:
            if key not in current_mtimes:
                changes.append((key, "deleted"))

        self._last_mtimes = current_mtimes
        return changes
