package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type isolPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    core.Severity
	Desc        string
	OWASPAST    []string
	MITREAttack []string
}

var isolPatterns []isolPattern

func init() {
	rawIsol := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
		owaspAST      []string
		mitreAttack   []string
	}{
		{"Host Network Mode", `(?i)(--network[=\s]+host|network_mode:\s*host|hostNetwork:\s*true)`, core.SeverityCritical, "Container configured with host network mode, breaking network isolation.", []string{"AST06"}, []string{"T1610"}},
		{"Privileged Container", `(?i)(--privileged|privileged:\s*true)`, core.SeverityCritical, "Container running in privileged mode with full host access.", []string{"AST06"}, []string{"T1610"}},
		{"Sensitive Port Exposure", `(?i)(?:ports:|EXPOSE|--publish|-p)\s*[:\s]*(?:22|3306|5432|6379|27017|2375|9200)\b`, core.SeverityHigh, "Sensitive service port exposed that could allow unauthorized access.", []string{"AST06"}, []string{"T1190"}},
		{"Dangerous Volume Mount", `(?i)(?:volumes:|-v\s+|--volume\s+).*(?:/:|/etc[:/]|/var/run/docker\.sock|/proc[:/]|/sys[:/])`, core.SeverityCritical, "Dangerous host volume mount that could expose sensitive host resources.", []string{"AST06"}, []string{"T1610"}},
	}
	for _, ri := range rawIsol {
		compiled, err := regexp.Compile(ri.pattern)
		if err != nil {
			continue
		}
		isolPatterns = append(isolPatterns, isolPattern{ri.name, compiled, ri.severity, ri.desc, ri.owaspAST, ri.mitreAttack})
	}
}

// IsolationChecker detects container and runtime isolation violations.
type IsolationChecker struct{}

func NewIsolationChecker() *IsolationChecker { return &IsolationChecker{} }

func (ic *IsolationChecker) Name() string    { return "isolation_checker" }
func (ic *IsolationChecker) Version() string { return "0.4.0" }

func (ic *IsolationChecker) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		for i, ip := range isolPatterns {
			matches := ip.Pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				lineStart := strings.Count(content[:match[0]], "\n") + 1
				snippet := content[match[0]:match[1]]
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				ruleID := fmt.Sprintf("SG-ISOL-%03d", i+1)
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    ip.Name,
					Severity:    ip.Severity,
					Category:    "isolation",
					Description: ip.Desc,
					FilePath:    sf.Path,
					LineStart:   &lineStart,
					Snippet:     &snippet,
					OWASPAST:    ip.OWASPAST,
					MITREAttack: ip.MITREAttack,
					Confidence:  0.85,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    ic.Name(),
			EngineVersion: ic.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.8,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	det := "Isolation Violation"

	return &core.EngineResult{
		EngineName:    ic.Name(),
		EngineVersion: ic.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (ic *IsolationChecker) HealthCheck() bool { return true }
