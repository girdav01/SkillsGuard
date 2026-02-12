"""Tests for the skill parser module."""

from __future__ import annotations

from pathlib import Path

import pytest

from skillguard.core.models import FileType
from skillguard.core.skill_parser import (
    classify_file,
    parse_frontmatter,
    parse_skill_directory,
)


class TestClassifyFile:
    def test_skill_md(self):
        assert classify_file(Path("SKILL.md")) == FileType.SKILL_MD

    def test_skill_md_case_insensitive(self):
        assert classify_file(Path("skill.md")) == FileType.SKILL_MD

    def test_readme_md(self):
        assert classify_file(Path("README.md")) == FileType.SKILL_MD

    def test_python_script(self):
        assert classify_file(Path("script.py")) == FileType.SCRIPT_PYTHON

    def test_bash_script(self):
        assert classify_file(Path("install.sh")) == FileType.SCRIPT_BASH

    def test_javascript(self):
        assert classify_file(Path("index.js")) == FileType.SCRIPT_JS

    def test_typescript(self):
        assert classify_file(Path("index.ts")) == FileType.SCRIPT_TS

    def test_yaml_config(self):
        assert classify_file(Path("config.yml")) == FileType.CONFIG

    def test_json_config(self):
        assert classify_file(Path("package.json")) == FileType.CONFIG

    def test_template(self):
        assert classify_file(Path("report.j2")) == FileType.TEMPLATE

    def test_unknown_extension(self):
        assert classify_file(Path("data.xyz")) == FileType.OTHER


class TestParseFrontmatter:
    def test_with_frontmatter(self):
        content = """---
name: test-skill
version: 1.0.0
---

# Body content here
"""
        fm, body = parse_frontmatter(content)
        assert fm["name"] == "test-skill"
        assert fm["version"] == "1.0.0"
        assert "Body content" in body

    def test_no_frontmatter(self):
        content = "# Just a heading\n\nSome text."
        fm, body = parse_frontmatter(content)
        assert fm == {}
        assert body == content

    def test_empty_frontmatter(self):
        content = "---\n---\n\nBody"
        fm, body = parse_frontmatter(content)
        assert fm == {}
        assert "Body" in body

    def test_invalid_yaml_frontmatter(self):
        content = "---\n: invalid: yaml: {{{\n---\n\nBody"
        fm, body = parse_frontmatter(content)
        assert fm == {}
        assert "Body" in body

    def test_frontmatter_with_list(self):
        content = """---
name: test
tools:
  - Read
  - Edit
  - Bash
---

Body
"""
        fm, body = parse_frontmatter(content)
        assert fm["tools"] == ["Read", "Edit", "Bash"]


class TestParseSkillDirectory:
    def test_parse_clean_skill(self, clean_skill_path: Path):
        files = parse_skill_directory(clean_skill_path)
        assert len(files) >= 2  # SKILL.md + format.py

        paths = [f.path for f in files]
        assert "SKILL.md" in paths
        assert "format.py" in paths

        skill_md = next(f for f in files if f.path == "SKILL.md")
        assert skill_md.file_type == FileType.SKILL_MD
        assert skill_md.content is not None
        assert skill_md.sha256 != ""
        assert skill_md.size_bytes > 0

    def test_parse_malicious_skill(self, malicious_skill_path: Path):
        files = parse_skill_directory(malicious_skill_path)
        assert len(files) >= 3

        paths = [f.path for f in files]
        assert "SKILL.md" in paths
        assert "payload.py" in paths
        assert "install.sh" in paths

    def test_parse_single_file(self, clean_skill_path: Path):
        files = parse_skill_directory(clean_skill_path / "SKILL.md")
        assert len(files) == 1
        assert files[0].file_type == FileType.SKILL_MD

    def test_nonexistent_path(self):
        with pytest.raises(FileNotFoundError):
            parse_skill_directory("/nonexistent/path")

    def test_all_files_have_hashes(self, clean_skill_path: Path):
        files = parse_skill_directory(clean_skill_path)
        for f in files:
            assert f.sha256 != ""
            assert len(f.sha256) == 64  # SHA256 hex length
