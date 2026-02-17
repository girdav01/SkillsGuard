package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// nlTargets are file types scanned for natural-language injection.
var nlTargets = map[core.FileType]bool{
	core.FileTypeSkillMD:      true,
	core.FileTypeFrontmatter:  true,
	core.FileTypeTemplate:     true,
}

// scriptTargets are script file types.
var scriptTargets = map[core.FileType]bool{
	core.FileTypeScriptPython: true,
	core.FileTypeScriptBash:   true,
	core.FileTypeScriptJS:     true,
	core.FileTypeScriptTS:     true,
}

// targetMap maps rule target strings to file types.
var targetMap map[string]map[core.FileType]bool

func init() {
	anyTargets := make(map[core.FileType]bool)
	for k, v := range nlTargets {
		anyTargets[k] = v
	}
	for k, v := range scriptTargets {
		anyTargets[k] = v
	}
	anyTargets[core.FileTypeConfig] = true
	anyTargets[core.FileTypeOther] = true

	targetMap = map[string]map[core.FileType]bool{
		"SKILL_MD":    {core.FileTypeSkillMD: true},
		"FRONTMATTER": {core.FileTypeFrontmatter: true},
		"SCRIPT":      scriptTargets,
		"ANY":         anyTargets,
		"CONFIG":      {core.FileTypeConfig: true},
	}
}

// RegexScanner is a regex-based pattern matching engine.
type RegexScanner struct {
	rulesDir string
	rules    []core.DetectionRule
	loaded   bool
}

// NewRegexScanner creates a new RegexScanner.
func NewRegexScanner(rulesDir string) *RegexScanner {
	return &RegexScanner{rulesDir: rulesDir}
}

func (r *RegexScanner) Name() string    { return "regex_scanner" }
func (r *RegexScanner) Version() string { return "0.1.0" }

func (r *RegexScanner) getRules() []core.DetectionRule {
	if !r.loaded {
		rules, _ := core.LoadRules(r.rulesDir, "REGEX", "", true)
		r.rules = rules
		r.loaded = true
	}
	return r.rules
}

func (r *RegexScanner) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	activeRules := rules
	if activeRules == nil {
		activeRules = r.getRules()
	}

	var allFindings []core.Finding
	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		for _, rule := range activeRules {
			if !fileMatchesTarget(sf, rule.Target) {
				continue
			}
			findings := applyRule(rule, sf)
			allFindings = append(allFindings, findings...)
		}
	}

	elapsed := time.Since(start).Milliseconds()
	verdict := computeVerdict(allFindings)
	confidence := computeConfidence(allFindings)
	detName := topDetectionName(allFindings)

	result := &core.EngineResult{
		EngineName:    r.Name(),
		EngineVersion: r.Version(),
		Verdict:       verdict,
		Confidence:    confidence,
		DetectionName: detName,
		Findings:      allFindings,
		DurationMs:    elapsed,
	}
	if result.Findings == nil {
		result.Findings = []core.Finding{}
	}
	return result, nil
}

func (r *RegexScanner) HealthCheck() bool { return true }

func fileMatchesTarget(sf core.SkillFile, target string) bool {
	upper := strings.ToUpper(target)
	allowed, ok := targetMap[upper]
	if !ok {
		return true
	}
	return allowed[sf.FileType]
}

func applyRule(rule core.DetectionRule, sf core.SkillFile) []core.Finding {
	if sf.Content == nil {
		return nil
	}
	content := *sf.Content
	patterns := extractPatterns(rule.Pattern)
	var findings []core.Finding
	lines := strings.Split(content, "\n")

	for _, patternStr := range patterns {
		compiled, err := regexp.Compile("(?i)" + patternStr)
		if err != nil {
			continue
		}
		matches := compiled.FindAllStringIndex(content, -1)
		for _, match := range matches {
			lineStart := strings.Count(content[:match[0]], "\n") + 1
			lineEnd := strings.Count(content[:match[1]], "\n") + 1

			snippetStart := lineStart - 2
			if snippetStart < 0 {
				snippetStart = 0
			}
			snippetEnd := lineEnd + 1
			if snippetEnd > len(lines) {
				snippetEnd = len(lines)
			}
			snippet := strings.Join(lines[snippetStart:snippetEnd], "\n")
			if len(snippet) > 500 {
				snippet = snippet[:500] + "..."
			}

			conf := 0.8
			findings = append(findings, core.Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Description: rule.Description,
				FilePath:    sf.Path,
				LineStart:   &lineStart,
				LineEnd:     &lineEnd,
				Snippet:     &snippet,
				OWASPLLM:    rule.OWASPLLM,
				MITREAttack: rule.MITREAttack,
				Confidence:  conf,
				Remediation: strPtr(rule.Remediation),
			})
		}
	}
	return findings
}

func extractPatterns(pattern any) []string {
	switch v := pattern.(type) {
	case string:
		return []string{v}
	case map[string]any:
		if anyList, ok := v["any"]; ok {
			return toStringSlice(anyList)
		}
		if allList, ok := v["all"]; ok {
			return toStringSlice(allList)
		}
		if p, ok := v["pattern"]; ok {
			if s, ok := p.(string); ok {
				return []string{s}
			}
		}
	}
	return nil
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func computeVerdict(findings []core.Finding) core.EngineVerdict {
	if len(findings) == 0 {
		return core.EngineVerdictClean
	}
	for _, f := range findings {
		if f.Severity == core.SeverityCritical || f.Severity == core.SeverityHigh {
			return core.EngineVerdictMalicious
		}
	}
	for _, f := range findings {
		if f.Severity == core.SeverityMedium {
			return core.EngineVerdictSuspicious
		}
	}
	return core.EngineVerdictClean
}

func computeConfidence(findings []core.Finding) float64 {
	if len(findings) == 0 {
		return 1.0
	}
	maxConf := 0.0
	for _, f := range findings {
		if f.Confidence > maxConf {
			maxConf = f.Confidence
		}
	}
	return maxConf
}

func topDetectionName(findings []core.Finding) *string {
	if len(findings) == 0 {
		return nil
	}
	order := []core.Severity{core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityInfo}
	for _, sev := range order {
		for _, f := range findings {
			if f.Severity == sev {
				return &f.RuleName
			}
		}
	}
	return &findings[0].RuleName
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func intPtr(i int) *int {
	return &i
}

func fmtStr(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
