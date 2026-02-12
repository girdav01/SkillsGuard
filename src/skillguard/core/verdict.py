"""Verdict aggregation and risk scoring algorithm.

Combines results from multiple scanning engines into a composite
risk score (0-100) and a final verdict.
"""

from __future__ import annotations

from skillguard.core.models import EngineResult, EngineVerdict, Finding, Severity, Verdict

# Points per finding severity
_SEVERITY_POINTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# Score thresholds for verdicts
_VERDICT_THRESHOLDS: list[tuple[int, Verdict]] = [
    (81, Verdict.MALICIOUS),
    (61, Verdict.HIGH_RISK),
    (41, Verdict.SUSPICIOUS),
    (21, Verdict.LOW_RISK),
    (0, Verdict.CLEAN),
]


def calculate_risk_score(
    engine_results: list[EngineResult],
    threat_intel_match: bool = False,
    trusted_publisher: bool = False,
) -> tuple[int, Verdict]:
    """Calculate composite risk score from engine results.

    Scoring:
    - CRITICAL finding: +40 points each (capped at 100)
    - HIGH finding: +20 points each
    - MEDIUM finding: +10 points each
    - LOW finding: +3 points each

    Modifiers:
    - Engine consensus: if 3+ engines say MALICIOUS, score = max(score, 90)
    - Threat intel match: instant 100
    - Trusted publisher: -10 points
    - Behavioral sandbox C2/exfil: instant 100

    Returns:
        Tuple of (score 0-100, verdict).
    """
    # Instant 100 for threat intel match
    if threat_intel_match:
        return 100, Verdict.MALICIOUS

    # Collect all findings from all engines
    all_findings: list[Finding] = []
    for result in engine_results:
        all_findings.extend(result.findings)

    # Calculate base score from findings
    score = 0
    for finding in all_findings:
        score += _SEVERITY_POINTS.get(finding.severity, 0)

    # Cap at 100
    score = min(score, 100)

    # Engine consensus modifier
    malicious_count = sum(
        1 for r in engine_results if r.verdict == EngineVerdict.MALICIOUS
    )
    if malicious_count >= 3:
        score = max(score, 90)

    # Trusted publisher modifier
    if trusted_publisher and score > 0:
        score = max(0, score - 10)

    # Cap at 100 again after modifiers
    score = min(score, 100)

    # Determine verdict from score
    verdict = _score_to_verdict(score)

    return score, verdict


def _score_to_verdict(score: int) -> Verdict:
    """Map a numeric score to a verdict."""
    for threshold, verdict in _VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return Verdict.CLEAN


def aggregate_findings_by_severity(
    engine_results: list[EngineResult],
) -> dict[str, int]:
    """Count findings grouped by severity across all engines."""
    counts: dict[str, int] = {}
    for result in engine_results:
        for finding in result.findings:
            key = finding.severity.value
            counts[key] = counts.get(key, 0) + 1
    return counts


def collect_owasp_coverage(engine_results: list[EngineResult]) -> list[str]:
    """Collect all unique OWASP LLM references from findings."""
    refs: set[str] = set()
    for result in engine_results:
        for finding in result.findings:
            refs.update(finding.owasp_llm)
    return sorted(refs)
