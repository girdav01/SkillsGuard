"""JSON report generator."""

from __future__ import annotations

import json

from skillguard.core.models import ScanResult


def generate_json_report(result: ScanResult) -> str:
    """Generate a JSON report from scan results.

    Returns:
        Pretty-printed JSON string.
    """
    return result.model_dump_json(indent=2)


def generate_json_summary(result: ScanResult) -> str:
    """Generate a concise JSON summary (no findings detail)."""
    data = result.model_dump()
    # Remove detailed findings for summary
    for er in data.get("engine_results", []):
        er["findings"] = []
        er["findings_count"] = len(result.engine_results)
    return json.dumps(data, indent=2, default=str)
