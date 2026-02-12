"""Tests for the hasher module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from skillguard.core.hasher import hash_content, hash_file, hash_skill


class TestHashContent:
    def test_deterministic(self):
        assert hash_content("hello") == hash_content("hello")

    def test_different_content(self):
        assert hash_content("hello") != hash_content("world")

    def test_sha256_length(self):
        assert len(hash_content("test")) == 64

    def test_empty_string(self):
        h = hash_content("")
        assert len(h) == 64


class TestHashFile:
    def test_hash_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = hash_file(f)
        assert len(h) == 64

    def test_hash_matches_content(self, tmp_path: Path):
        content = "test content"
        f = tmp_path / "test.txt"
        f.write_text(content)
        assert hash_file(f) == hash_content(content)


class TestHashSkill:
    def test_deterministic(self):
        files = [("a.md", "abc123"), ("b.py", "def456")]
        assert hash_skill(files) == hash_skill(files)

    def test_order_independent(self):
        files_a = [("a.md", "abc"), ("b.py", "def")]
        files_b = [("b.py", "def"), ("a.md", "abc")]
        assert hash_skill(files_a) == hash_skill(files_b)

    def test_different_files(self):
        files_a = [("a.md", "abc")]
        files_b = [("a.md", "xyz")]
        assert hash_skill(files_a) != hash_skill(files_b)
