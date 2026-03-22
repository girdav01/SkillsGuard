package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type depPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    core.Severity
	Desc        string
	OWASPAST    []string
	MITREAttack []string
}

var depPatterns []depPattern

func init() {
	rawDep := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
		owaspAST      []string
		mitreAttack   []string
	}{
		{"Unpinned Dependency", `(?m)^[a-zA-Z][\w.-]*\s*[><!~]=`, core.SeverityMedium, "Unpinned dependency version detected that could allow supply chain attacks.", []string{"AST07"}, nil},
		{"Mutable Git Reference", `(?i)git\+https?://[^\s]+@(?:main|master|develop|dev)\b`, core.SeverityHigh, "Dependency pinned to a mutable git branch reference instead of a commit hash.", []string{"AST07"}, []string{"T1195"}},
		{"Latest Tag Usage", `(?i)(?::latest\b|"version":\s*"\*"|"version":\s*"latest")`, core.SeverityMedium, "Dependency uses 'latest' tag or wildcard version, risking unexpected updates.", []string{"AST07"}, nil},
	}
	for _, rd := range rawDep {
		compiled, err := regexp.Compile(rd.pattern)
		if err != nil {
			continue
		}
		depPatterns = append(depPatterns, depPattern{rd.name, compiled, rd.severity, rd.desc, rd.owaspAST, rd.mitreAttack})
	}
}

// DependencyChecker detects insecure or unpinned dependency patterns.
type DependencyChecker struct{}

func NewDependencyChecker() *DependencyChecker { return &DependencyChecker{} }

func (d *DependencyChecker) Name() string    { return "dependency_checker" }
func (d *DependencyChecker) Version() string { return "0.4.0" }

func (d *DependencyChecker) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		for i, dp := range depPatterns {
			matches := dp.Pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				lineStart := strings.Count(content[:match[0]], "\n") + 1
				snippet := content[match[0]:match[1]]
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				ruleID := fmt.Sprintf("SG-DEP-%03d", i+1)
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    dp.Name,
					Severity:    dp.Severity,
					Category:    "dependency",
					Description: dp.Desc,
					FilePath:    sf.Path,
					LineStart:   &lineStart,
					Snippet:     &snippet,
					OWASPAST:    dp.OWASPAST,
					MITREAttack: dp.MITREAttack,
					Confidence:  0.80,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    d.Name(),
			EngineVersion: d.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.8,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	det := "Dependency Issue"

	return &core.EngineResult{
		EngineName:    d.Name(),
		EngineVersion: d.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (d *DependencyChecker) HealthCheck() bool { return true }
