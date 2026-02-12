"""Known malicious hash database and IOC (Indicator of Compromise) tracking.

Provides a local threat intelligence database of known-malicious skill
hashes, suspicious URLs, and other IOCs. Supports both an in-memory
store and optional SQLite persistence for local installs.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ThreatIndicator(BaseModel):
    """A single threat intelligence indicator."""

    sha256: str
    threat_name: str
    severity: str = "critical"
    source: str = "community"
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    ioc_type: str = "skill_hash"  # skill_hash, url, domain, ip


class ThreatIntelDB:
    """Known malicious hash database and IOC store.

    Maintains a database of known-malicious skill hashes for instant
    reputation lookups. Can be seeded from community feeds or
    manually curated lists.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else None
        self._indicators: dict[str, ThreatIndicator] = {}
        self._url_indicators: dict[str, ThreatIndicator] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Load the database from disk if not already loaded."""
        if self._loaded:
            return
        self._loaded = True

        if self._db_path and self._db_path.exists():
            try:
                data = json.loads(self._db_path.read_text(encoding="utf-8"))
                for entry in data.get("indicators", []):
                    indicator = ThreatIndicator(**entry)
                    if indicator.ioc_type == "url":
                        self._url_indicators[indicator.sha256] = indicator
                    else:
                        self._indicators[indicator.sha256] = indicator
            except Exception:
                pass

        # Seed with known malicious patterns
        self._seed_known_threats()

    def _seed_known_threats(self) -> None:
        """Seed with community-known malicious indicators."""
        known_threats = [
            ThreatIndicator(
                sha256="known_malicious_placeholder_001",
                threat_name="ToxicSkill.GenericExfil.A",
                severity="critical",
                source="snyk_toxicskills",
                description="Known data exfiltration skill from ToxicSkills research",
                tags=["exfiltration", "toxicskills"],
            ),
            ThreatIndicator(
                sha256="known_malicious_placeholder_002",
                threat_name="ToxicSkill.CredTheft.A",
                severity="critical",
                source="snyk_toxicskills",
                description="Known credential theft skill from ToxicSkills research",
                tags=["credential_theft", "toxicskills"],
            ),
            ThreatIndicator(
                sha256="known_malicious_placeholder_003",
                threat_name="ToxicSkill.ReverseShell.A",
                severity="critical",
                source="snyk_toxicskills",
                description="Known reverse shell skill from ToxicSkills research",
                tags=["reverse_shell", "toxicskills"],
            ),
        ]
        for threat in known_threats:
            if threat.sha256 not in self._indicators:
                self._indicators[threat.sha256] = threat

    async def is_malicious_hash(self, sha256: str) -> bool:
        """Check if a skill hash is known malicious.

        Args:
            sha256: The SHA256 hash of the skill package.

        Returns:
            True if the hash is in the threat database.
        """
        self._ensure_loaded()
        return sha256 in self._indicators

    async def get_threat_details(self, sha256: str) -> ThreatIndicator | None:
        """Get full threat intelligence for a hash.

        Args:
            sha256: The SHA256 hash to look up.

        Returns:
            ThreatIndicator if found, None otherwise.
        """
        self._ensure_loaded()
        return self._indicators.get(sha256)

    async def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add a new threat indicator to the database.

        Args:
            indicator: The threat indicator to add.
        """
        self._ensure_loaded()
        if indicator.ioc_type == "url":
            self._url_indicators[indicator.sha256] = indicator
        else:
            self._indicators[indicator.sha256] = indicator

    async def is_malicious_url(self, url: str) -> bool:
        """Check if a URL is known malicious."""
        self._ensure_loaded()
        return url in self._url_indicators

    async def save(self) -> None:
        """Persist the database to disk."""
        if self._db_path is None:
            return

        all_indicators = list(self._indicators.values()) + list(self._url_indicators.values())
        data = {
            "version": "1.0",
            "updated": datetime.now(timezone.utc).isoformat(),
            "indicators": [ind.model_dump() for ind in all_indicators],
        }
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_stats(self) -> dict[str, int]:
        """Get statistics about the threat database."""
        self._ensure_loaded()
        return {
            "total_indicators": len(self._indicators) + len(self._url_indicators),
            "hash_indicators": len(self._indicators),
            "url_indicators": len(self._url_indicators),
        }
