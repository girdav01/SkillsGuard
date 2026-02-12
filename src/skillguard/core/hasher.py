"""SHA256 hashing utilities for skill files and content."""

from __future__ import annotations

import hashlib
from pathlib import Path


def hash_content(content: str) -> str:
    """Compute SHA256 hash of text content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def hash_file(path: str | Path) -> str:
    """Compute SHA256 hash of a file by reading in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def hash_skill(files: list[tuple[str, str]]) -> str:
    """Compute a composite hash for an entire skill package.

    Args:
        files: List of (relative_path, file_sha256) tuples, will be sorted.

    Returns:
        SHA256 hash of the concatenated sorted path:hash pairs.
    """
    parts = sorted(f"{path}:{sha}" for path, sha in files)
    combined = "\n".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()
