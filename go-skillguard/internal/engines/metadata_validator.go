package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type metaPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity core.Severity
	Desc     string
}

var metaPatterns []metaPattern

func init() {
	rawMeta := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
	}{
		{"Author Impersonation", `(?i)author:\s*["']?(anthr[o0]p[i1l]c|[o0]pen[a@]i|micr[o0]s[o0]ft|g[o0]{2}gle|m[e3]ta|curs[o0]r|[o0]pencl[a@]w)`, core.SeverityHigh, "Skill metadata impersonates a well-known vendor as the author."},
		{"Suspicious Homepage", `(?i)(?:homepage|url):\s*["']?https?://(?:.*(?:ngrok|localtunnel|serveo)|localhost|127\.0\.0\.1|0\.0\.0\.0)`, core.SeverityMedium, "Skill metadata references a suspicious or ephemeral homepage URL."},
		{"Misleading Description Safe Claim", `(?i)description:.*(?:safe|read.only|harmless|no.side.effect|sandboxed)`, core.SeverityMedium, "Skill description contains safety claims that may be misleading (simple heuristic)."},
	}
	for _, rm := range rawMeta {
		compiled, err := regexp.Compile(rm.pattern)
		if err != nil {
			continue
		}
		metaPatterns = append(metaPatterns, metaPattern{rm.name, compiled, rm.severity, rm.desc})
	}
}

// MetadataValidator validates skill file metadata (YAML frontmatter) for suspicious patterns.
type MetadataValidator struct{}

func NewMetadataValidator() *MetadataValidator { return &MetadataValidator{} }

func (m *MetadataValidator) Name() string    { return "metadata_validator" }
func (m *MetadataValidator) Version() string { return "0.4.0" }

func (m *MetadataValidator) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		for i, mp := range metaPatterns {
			matches := mp.Pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				lineStart := strings.Count(content[:match[0]], "\n") + 1
				snippet := content[match[0]:match[1]]
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				ruleID := fmt.Sprintf("SG-META-%03d", i+1)
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    mp.Name,
					Severity:    mp.Severity,
					Category:    "metadata",
					Description: mp.Desc,
					FilePath:    sf.Path,
					LineStart:   &lineStart,
					Snippet:     &snippet,
					OWASPAST:    []string{"AST04"},
					Confidence:  0.80,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    m.Name(),
			EngineVersion: m.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.8,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	det := "Metadata Validation"

	return &core.EngineResult{
		EngineName:    m.Name(),
		EngineVersion: m.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (m *MetadataValidator) HealthCheck() bool { return true }
