"""Tests for the monitoring module (file watcher + drift detector)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from skillguard.monitoring.drift_detector import DriftDetector
from skillguard.monitoring.file_watcher import SkillDirectoryWatcher, SkillChangeHandler


class TestDriftDetector:
    @pytest.fixture
    def detector(self):
        return DriftDetector()

    @pytest.fixture
    def skill_dir(self, tmp_path):
        """Create a temporary skill directory for testing."""
        skill_md = tmp_path / "SKILL.md"
        skill_md.write_text("# Test Skill\n\nA test skill.", encoding="utf-8")
        helper = tmp_path / "helper.py"
        helper.write_text("def hello(): pass\n", encoding="utf-8")
        return str(tmp_path)

    async def test_capture_baseline(self, detector, skill_dir):
        baseline = await detector.capture_baseline(skill_dir)
        assert baseline.skill_path == str(Path(skill_dir).resolve())
        assert baseline.skill_sha256 != ""
        assert len(baseline.file_hashes) >= 2

    async def test_no_drift_after_baseline(self, detector, skill_dir):
        await detector.capture_baseline(skill_dir)
        drift = await detector.check_drift(skill_dir)
        assert drift.has_drift is False

    async def test_drift_on_file_modification(self, detector, skill_dir):
        await detector.capture_baseline(skill_dir)

        # Modify a file
        skill_md = Path(skill_dir) / "SKILL.md"
        skill_md.write_text("# Modified Skill\n\nChanged content.", encoding="utf-8")

        drift = await detector.check_drift(skill_dir)
        assert drift.has_drift is True
        assert len(drift.modified_files) > 0

    async def test_drift_on_file_addition(self, detector, skill_dir):
        await detector.capture_baseline(skill_dir)

        # Add a new file
        new_file = Path(skill_dir) / "new_file.py"
        new_file.write_text("# new file\n", encoding="utf-8")

        drift = await detector.check_drift(skill_dir)
        assert drift.has_drift is True
        assert len(drift.added_files) > 0

    async def test_drift_on_file_deletion(self, detector, skill_dir):
        await detector.capture_baseline(skill_dir)

        # Delete a file
        helper = Path(skill_dir) / "helper.py"
        helper.unlink()

        drift = await detector.check_drift(skill_dir)
        assert drift.has_drift is True
        assert len(drift.removed_files) > 0

    async def test_no_baseline_no_drift(self, detector, skill_dir):
        """With no baseline captured, there's nothing to compare against."""
        drift = await detector.check_drift(skill_dir)
        assert drift.has_drift is False

    async def test_list_monitored(self, detector, skill_dir):
        assert len(await detector.list_monitored()) == 0
        await detector.capture_baseline(skill_dir)
        monitored = await detector.list_monitored()
        assert len(monitored) == 1

    async def test_remove_baseline(self, detector, skill_dir):
        await detector.capture_baseline(skill_dir)
        assert await detector.remove_baseline(skill_dir) is True
        assert len(await detector.list_monitored()) == 0

    async def test_remove_nonexistent_baseline(self, detector):
        assert await detector.remove_baseline("/nonexistent") is False

    async def test_get_baseline(self, detector, skill_dir):
        await detector.capture_baseline(skill_dir, verdict="clean", score=0)
        baseline = await detector.get_baseline(skill_dir)
        assert baseline is not None
        assert baseline.verdict == "clean"
        assert baseline.score == 0


class TestFileWatcher:
    def test_watcher_creation(self):
        watcher = SkillDirectoryWatcher()
        assert watcher.is_running is False
        assert len(watcher.watched_paths) == 0

    def test_watch_directory(self, tmp_path):
        watcher = SkillDirectoryWatcher()
        assert watcher.watch(str(tmp_path)) is True
        assert str(tmp_path.resolve()) in watcher.watched_paths
        watcher.stop()

    def test_watch_nonexistent_directory(self):
        watcher = SkillDirectoryWatcher()
        assert watcher.watch("/nonexistent/path/12345") is False

    def test_unwatch(self, tmp_path):
        watcher = SkillDirectoryWatcher()
        watcher.watch(str(tmp_path))
        watcher.unwatch(str(tmp_path))
        assert str(tmp_path.resolve()) not in watcher.watched_paths

    def test_stop(self, tmp_path):
        watcher = SkillDirectoryWatcher()
        watcher.watch(str(tmp_path))
        watcher.stop()
        assert watcher.is_running is False


class TestChangeHandler:
    def test_notify_change(self):
        handler = SkillChangeHandler()
        handler.notify_change("/path/to/file.py", "modified")
        assert "/path/to/file.py" in handler._pending_changes

    async def test_process_pending(self):
        handler = SkillChangeHandler()
        handler.notify_change("/file1.py", "modified")
        handler.notify_change("/file2.py", "created")

        changes = await handler.process_pending()
        assert len(changes) == 2
        # Queue should be cleared
        changes2 = await handler.process_pending()
        assert len(changes2) == 0

    async def test_poll_once(self, tmp_path):
        watcher = SkillDirectoryWatcher()
        watcher._watched_paths.add(str(tmp_path))

        # First poll captures initial state
        changes1 = await watcher.poll_once()

        # Create a new file
        (tmp_path / "newfile.txt").write_text("hello")

        # Second poll should detect the new file
        changes2 = await watcher.poll_once()
        assert any("newfile.txt" in path for path, _ in changes2)
