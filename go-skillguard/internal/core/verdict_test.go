package core

import "testing"

func TestScoreToVerdict(t *testing.T) {
	tests := []struct {
		score int
		want  Verdict
	}{
		{0, VerdictClean},
		{20, VerdictClean},
		{21, VerdictLowRisk},
		{40, VerdictLowRisk},
		{41, VerdictSuspicious},
		{60, VerdictSuspicious},
		{61, VerdictHighRisk},
		{80, VerdictHighRisk},
		{81, VerdictMalicious},
		{100, VerdictMalicious},
	}
	for _, tt := range tests {
		got := ScoreToVerdict(tt.score)
		if got != tt.want {
			t.Errorf("ScoreToVerdict(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestCalculateRiskScoreEmpty(t *testing.T) {
	score, verdict := CalculateRiskScore(nil, false, false)
	if score != 0 {
		t.Errorf("Empty score = %d, want 0", score)
	}
	if verdict != VerdictClean {
		t.Errorf("Empty verdict = %q, want %q", verdict, VerdictClean)
	}
}

func TestCalculateRiskScoreThreatIntel(t *testing.T) {
	score, verdict := CalculateRiskScore(nil, true, false)
	if score != 100 {
		t.Errorf("Threat intel score = %d, want 100", score)
	}
	if verdict != VerdictMalicious {
		t.Errorf("Threat intel verdict = %q, want %q", verdict, VerdictMalicious)
	}
}

func TestCalculateRiskScoreWithFindings(t *testing.T) {
	results := []EngineResult{
		{
			EngineName: "test",
			Verdict:    EngineVerdictSuspicious,
			Findings: []Finding{
				{Severity: SeverityCritical, Confidence: 0.9},
				{Severity: SeverityHigh, Confidence: 0.8},
			},
		},
	}
	score, verdict := CalculateRiskScore(results, false, false)
	if score != 60 { // 40 + 20
		t.Errorf("Score = %d, want 60", score)
	}
	if verdict != VerdictSuspicious {
		t.Errorf("Verdict = %q, want %q", verdict, VerdictSuspicious)
	}
}

func TestCalculateRiskScoreConsensus(t *testing.T) {
	results := []EngineResult{
		{Verdict: EngineVerdictMalicious, Findings: []Finding{{Severity: SeverityLow, Confidence: 0.5}}},
		{Verdict: EngineVerdictMalicious, Findings: []Finding{{Severity: SeverityLow, Confidence: 0.5}}},
		{Verdict: EngineVerdictMalicious, Findings: []Finding{{Severity: SeverityLow, Confidence: 0.5}}},
	}
	score, verdict := CalculateRiskScore(results, false, false)
	if score < 90 {
		t.Errorf("Consensus score = %d, want >= 90", score)
	}
	if verdict != VerdictMalicious {
		t.Errorf("Consensus verdict = %q, want %q", verdict, VerdictMalicious)
	}
}

func TestCalculateRiskScoreTrustedPublisher(t *testing.T) {
	results := []EngineResult{
		{
			Findings: []Finding{
				{Severity: SeverityMedium, Confidence: 0.7},
				{Severity: SeverityMedium, Confidence: 0.7},
				{Severity: SeverityMedium, Confidence: 0.7},
			},
		},
	}
	score, _ := CalculateRiskScore(results, false, true)
	expected := 20 // 30 - 10
	if score != expected {
		t.Errorf("Trusted publisher score = %d, want %d", score, expected)
	}
}

func TestCalculateRiskScoreCapped(t *testing.T) {
	results := []EngineResult{
		{
			Findings: []Finding{
				{Severity: SeverityCritical}, {Severity: SeverityCritical},
				{Severity: SeverityCritical}, {Severity: SeverityCritical},
			},
		},
	}
	score, _ := CalculateRiskScore(results, false, false)
	if score > 100 {
		t.Errorf("Score = %d, should be capped at 100", score)
	}
}

func TestAggregateFindingsBySeverity(t *testing.T) {
	results := []EngineResult{
		{Findings: []Finding{
			{Severity: SeverityCritical},
			{Severity: SeverityHigh},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
		}},
	}
	counts := AggregateFindingsBySeverity(results)
	if counts["critical"] != 1 {
		t.Errorf("critical = %d, want 1", counts["critical"])
	}
	if counts["high"] != 2 {
		t.Errorf("high = %d, want 2", counts["high"])
	}
	if counts["medium"] != 1 {
		t.Errorf("medium = %d, want 1", counts["medium"])
	}
}

func TestCollectOWASPCoverage(t *testing.T) {
	results := []EngineResult{
		{Findings: []Finding{
			{OWASPLLM: []string{"LLM01", "LLM06"}},
			{OWASPLLM: []string{"LLM01", "LLM07"}},
		}},
	}
	coverage := CollectOWASPCoverage(results)
	if len(coverage) != 3 {
		t.Errorf("Coverage length = %d, want 3", len(coverage))
	}
}
