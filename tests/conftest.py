"""Pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CLEAN_SKILL_DIR = FIXTURES_DIR / "clean_skill"
MALICIOUS_SKILL_DIR = FIXTURES_DIR / "malicious_skill"
EDGE_CASES_DIR = FIXTURES_DIR / "edge_cases"


@pytest.fixture
def clean_skill_path() -> Path:
    return CLEAN_SKILL_DIR


@pytest.fixture
def malicious_skill_path() -> Path:
    return MALICIOUS_SKILL_DIR


@pytest.fixture
def edge_cases_path() -> Path:
    return EDGE_CASES_DIR
