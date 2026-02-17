package core

// VerdictThreshold maps a minimum score to a verdict.
type VerdictThreshold struct {
	MinScore int
	Verdict  Verdict
}

var verdictThresholds = []VerdictThreshold{
	{81, VerdictMalicious},
	{61, VerdictHighRisk},
	{41, VerdictSuspicious},
	{21, VerdictLowRisk},
	{0, VerdictClean},
}

// CalculateRiskScore computes the composite risk score from engine results.
//
// Scoring:
//   - CRITICAL finding: +40 points each (capped at 100)
//   - HIGH finding: +20 points each
//   - MEDIUM finding: +10 points each
//   - LOW finding: +3 points each
//
// Modifiers:
//   - Engine consensus: if 3+ engines say MALICIOUS, score = max(score, 90)
//   - Threat intel match: instant 100
//   - Trusted publisher: -10 points
func CalculateRiskScore(engineResults []EngineResult, threatIntelMatch bool, trustedPublisher bool) (int, Verdict) {
	if threatIntelMatch {
		return 100, VerdictMalicious
	}

	// Collect all findings
	score := 0
	for _, er := range engineResults {
		for _, f := range er.Findings {
			score += SeverityPoints[f.Severity]
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	// Engine consensus modifier
	maliciousCount := 0
	for _, r := range engineResults {
		if r.Verdict == EngineVerdictMalicious {
			maliciousCount++
		}
	}
	if maliciousCount >= 3 && score < 90 {
		score = 90
	}

	// Trusted publisher modifier
	if trustedPublisher && score > 0 {
		score -= 10
		if score < 0 {
			score = 0
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	verdict := ScoreToVerdict(score)
	return score, verdict
}

// ScoreToVerdict maps a numeric score to a verdict.
func ScoreToVerdict(score int) Verdict {
	for _, t := range verdictThresholds {
		if score >= t.MinScore {
			return t.Verdict
		}
	}
	return VerdictClean
}

// AggregateFindingsBySeverity counts findings grouped by severity.
func AggregateFindingsBySeverity(engineResults []EngineResult) map[string]int {
	counts := make(map[string]int)
	for _, er := range engineResults {
		for _, f := range er.Findings {
			counts[string(f.Severity)]++
		}
	}
	return counts
}

// CollectOWASPCoverage collects unique OWASP LLM references from findings.
func CollectOWASPCoverage(engineResults []EngineResult) []string {
	refs := make(map[string]bool)
	for _, er := range engineResults {
		for _, f := range er.Findings {
			for _, ref := range f.OWASPLLM {
				refs[ref] = true
			}
		}
	}
	result := make([]string, 0, len(refs))
	for ref := range refs {
		result = append(result, ref)
	}
	// Sort for consistency
	sortStrings(result)
	return result
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
