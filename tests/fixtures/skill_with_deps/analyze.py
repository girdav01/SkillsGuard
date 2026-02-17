"""Data analysis helper script."""

import csv
from pathlib import Path


def load_csv(path: str) -> list[dict]:
    """Load a CSV file and return rows as dicts."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def compute_mean(values: list[float]) -> float:
    """Compute the arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)
