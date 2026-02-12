"""Tests for the threat intelligence module."""

from __future__ import annotations

import pytest

from skillguard.intelligence.threat_db import ThreatIntelDB, ThreatIndicator
from skillguard.intelligence.mitre_mapper import MitreMapper, TECHNIQUE_DB
from skillguard.intelligence.community import (
    CommunityVerdicts,
    CommunityVerdict,
    CommunityComment,
)


class TestThreatIntelDB:
    @pytest.fixture
    def db(self):
        return ThreatIntelDB()

    async def test_unknown_hash_not_malicious(self, db):
        assert await db.is_malicious_hash("unknown_hash_12345") is False

    async def test_seeded_threats_exist(self, db):
        # Known seeded placeholder
        assert await db.is_malicious_hash("known_malicious_placeholder_001") is True
        assert await db.is_malicious_hash("known_malicious_placeholder_002") is True

    async def test_get_threat_details(self, db):
        details = await db.get_threat_details("known_malicious_placeholder_001")
        assert details is not None
        assert details.threat_name == "ToxicSkill.GenericExfil.A"
        assert details.severity == "critical"

    async def test_get_nonexistent_details(self, db):
        details = await db.get_threat_details("nonexistent")
        assert details is None

    async def test_add_indicator(self, db):
        indicator = ThreatIndicator(
            sha256="custom_hash_123",
            threat_name="TestThreat",
            severity="high",
            source="test",
        )
        await db.add_indicator(indicator)
        assert await db.is_malicious_hash("custom_hash_123") is True

    async def test_stats(self, db):
        stats = db.get_stats()
        assert stats["hash_indicators"] >= 3  # seeded threats
        assert stats["total_indicators"] >= 3

    async def test_malicious_url(self, db):
        indicator = ThreatIndicator(
            sha256="http://evil.example.com",
            threat_name="EvilURL",
            ioc_type="url",
        )
        await db.add_indicator(indicator)
        assert await db.is_malicious_url("http://evil.example.com") is True
        assert await db.is_malicious_url("http://safe.example.com") is False


class TestMitreMapper:
    @pytest.fixture
    def mapper(self):
        return MitreMapper()

    def test_technique_lookup(self, mapper):
        tech = mapper.get_technique("T1059")
        assert tech is not None
        assert tech["name"] == "Command and Scripting Interpreter"
        assert tech["tactic"] == "Execution"

    def test_unknown_technique(self, mapper):
        tech = mapper.get_technique("T9999.999")
        assert tech is None

    def test_technique_db_has_entries(self):
        assert len(TECHNIQUE_DB) > 10

    def test_techniques_from_empty_results(self, mapper):
        techniques = mapper.get_techniques_from_results([])
        assert techniques == []

    def test_tactics_summary_empty(self, mapper):
        summary = mapper.get_tactics_summary([])
        assert summary == {}


class TestCommunityVerdicts:
    @pytest.fixture
    def community(self):
        return CommunityVerdicts()

    async def test_no_verdicts(self, community):
        rep = await community.get_reputation("unknown_hash")
        assert rep.total_verdicts == 0
        assert rep.consensus_verdict is None

    async def test_add_verdict(self, community):
        verdict = CommunityVerdict(
            analyst_id="analyst-1",
            verdict="malicious",
            confidence=0.9,
            comment="Clearly malicious",
        )
        await community.add_verdict("test_hash", verdict)

        rep = await community.get_reputation("test_hash")
        assert rep.total_verdicts == 1
        assert rep.malicious_count == 1

    async def test_consensus_calculation(self, community):
        for i in range(5):
            await community.add_verdict(
                "hash_1",
                CommunityVerdict(
                    analyst_id=f"analyst-{i}",
                    verdict="malicious",
                    confidence=0.8,
                ),
            )
        for i in range(2):
            await community.add_verdict(
                "hash_1",
                CommunityVerdict(
                    analyst_id=f"analyst-clean-{i}",
                    verdict="clean",
                    confidence=0.6,
                ),
            )

        rep = await community.get_reputation("hash_1")
        assert rep.total_verdicts == 7
        assert rep.consensus_verdict == "malicious"
        assert rep.consensus_confidence > 0.5

    async def test_add_comment(self, community):
        comment = CommunityComment(
            author_id="user-1",
            text="This skill steals credentials.",
        )
        await community.add_comment("hash_2", comment)

        rep = await community.get_reputation("hash_2")
        assert len(rep.comments) == 1
        assert rep.comments[0].text == "This skill steals credentials."

    async def test_verdict_count(self, community):
        assert await community.get_verdict_count("empty_hash") == 0
