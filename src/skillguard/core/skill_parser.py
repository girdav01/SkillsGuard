"""Parser for AI Agent Skill packages.

Handles SKILL.md files with YAML frontmatter, enumerates all files
in a skill directory, and classifies them by type.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from skillguard.core.hasher import hash_content, hash_file
from skillguard.core.models import FileType, SkillFile

# YAML frontmatter delimiter pattern
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# File extension to FileType mapping
_EXT_MAP: dict[str, FileType] = {
    ".py": FileType.SCRIPT_PYTHON,
    ".sh": FileType.SCRIPT_BASH,
    ".bash": FileType.SCRIPT_BASH,
    ".js": FileType.SCRIPT_JS,
    ".mjs": FileType.SCRIPT_JS,
    ".ts": FileType.SCRIPT_TS,
    ".mts": FileType.SCRIPT_TS,
    ".json": FileType.CONFIG,
    ".yaml": FileType.CONFIG,
    ".yml": FileType.CONFIG,
    ".toml": FileType.CONFIG,
    ".ini": FileType.CONFIG,
    ".cfg": FileType.CONFIG,
    ".j2": FileType.TEMPLATE,
    ".jinja": FileType.TEMPLATE,
    ".jinja2": FileType.TEMPLATE,
    ".tmpl": FileType.TEMPLATE,
    ".hbs": FileType.TEMPLATE,
}

# Filenames recognized as the primary skill markdown
_SKILL_MD_NAMES = {
    "skill.md",
    "readme.md",
    "instructions.md",
    "prompt.md",
    "system.md",
}

# Maximum file size to read content (10 MB)
_MAX_FILE_SIZE = 10 * 1024 * 1024


def classify_file(path: Path) -> FileType:
    """Classify a file by its name and extension."""
    if path.name.lower() in _SKILL_MD_NAMES:
        return FileType.SKILL_MD
    return _EXT_MAP.get(path.suffix.lower(), FileType.OTHER)


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter and body from a markdown file.

    Returns:
        Tuple of (frontmatter_dict, body_text). If no frontmatter
        is found, returns ({}, original_content).
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}, content

    raw_yaml = match.group(1)
    body = content[match.end() :]

    try:
        frontmatter = yaml.safe_load(raw_yaml)
        if not isinstance(frontmatter, dict):
            frontmatter = {}
    except yaml.YAMLError:
        frontmatter = {}

    return frontmatter, body


def parse_skill_directory(skill_path: str | Path) -> list[SkillFile]:
    """Parse a skill directory and return all files with metadata.

    Args:
        skill_path: Path to the skill directory or a single file.

    Returns:
        List of SkillFile objects with content loaded for scannable files.
    """
    path = Path(skill_path)
    if not path.exists():
        raise FileNotFoundError(f"Skill path does not exist: {path}")

    files: list[SkillFile] = []

    if path.is_file():
        sf = _parse_single_file(path, path.parent)
        if sf:
            files.append(sf)
        return files

    # Walk the directory, skip hidden dirs and common non-skill dirs
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    for child in sorted(path.rglob("*")):
        if child.is_dir():
            continue
        if any(part in skip_dirs for part in child.parts):
            continue
        sf = _parse_single_file(child, path)
        if sf:
            files.append(sf)

    return files


def _parse_single_file(file_path: Path, base_path: Path) -> SkillFile | None:
    """Parse a single file into a SkillFile."""
    try:
        stat = file_path.stat()
    except OSError:
        return None

    size = stat.st_size
    if size > _MAX_FILE_SIZE:
        # Hash it but don't load content
        return SkillFile(
            path=str(file_path.relative_to(base_path)),
            file_type=classify_file(file_path),
            sha256=hash_file(file_path),
            size_bytes=size,
            content=None,
        )

    file_type = classify_file(file_path)

    # Try to read as text
    content: str | None = None
    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        # Binary file - hash only
        pass

    file_hash = hash_file(file_path) if content is None else hash_content(content)

    return SkillFile(
        path=str(file_path.relative_to(base_path)),
        file_type=file_type,
        sha256=file_hash,
        size_bytes=size,
        content=content,
    )
