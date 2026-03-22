package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type xplatPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    core.Severity
	Desc        string
	OWASPAST    []string
	MITREAttack []string
}

var xplatPatterns []xplatPattern

func init() {
	rawXplat := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
		owaspAST      []string
		mitreAttack   []string
	}{
		{"Platform-Specific API", `(?i)(Bash\s*\(|execute_command|run_terminal|computer_use|browser_use)`, core.SeverityMedium, "Platform-specific API usage detected that may not be portable across agent platforms.", []string{"AST10"}, nil},
		{"Hardcoded Platform Path", `(?i)(~/\.claude/|~/\.cursor/|~/\.windsurf/|~/\.openclaw/)`, core.SeverityLow, "Hardcoded platform-specific path detected that reduces portability.", []string{"AST10"}, nil},
		{"Transport Mismatch", `(?i)(transport:\s*stdio|transport:\s*sse|StdioServerTransport|SSEServerTransport)`, core.SeverityMedium, "Transport protocol specification detected — verify compatibility across target platforms.", []string{"AST10"}, nil},
		{"Sandbox Escalation Risk", `(?i)(host_mode:\s*true|sandbox:\s*false|disable_sandbox|no.?sandbox|unrestricted_mode)`, core.SeverityHigh, "Sandbox escape or disable directive detected that could compromise platform security.", []string{"AST10"}, []string{"T1190"}},
	}
	for _, rx := range rawXplat {
		compiled, err := regexp.Compile(rx.pattern)
		if err != nil {
			continue
		}
		xplatPatterns = append(xplatPatterns, xplatPattern{rx.name, compiled, rx.severity, rx.desc, rx.owaspAST, rx.mitreAttack})
	}
}

// CrossPlatformAnalyzer detects platform-specific patterns and portability issues.
type CrossPlatformAnalyzer struct{}

func NewCrossPlatformAnalyzer() *CrossPlatformAnalyzer { return &CrossPlatformAnalyzer{} }

func (c *CrossPlatformAnalyzer) Name() string    { return "cross_platform_analyzer" }
func (c *CrossPlatformAnalyzer) Version() string { return "0.4.0" }

func (c *CrossPlatformAnalyzer) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		for i, xp := range xplatPatterns {
			matches := xp.Pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				lineStart := strings.Count(content[:match[0]], "\n") + 1
				snippet := content[match[0]:match[1]]
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				ruleID := fmt.Sprintf("SG-XPLAT-%03d", i+1)
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    xp.Name,
					Severity:    xp.Severity,
					Category:    "cross_platform",
					Description: xp.Desc,
					FilePath:    sf.Path,
					LineStart:   &lineStart,
					Snippet:     &snippet,
					OWASPAST:    xp.OWASPAST,
					MITREAttack: xp.MITREAttack,
					Confidence:  0.75,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    c.Name(),
			EngineVersion: c.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.8,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	det := "Cross-Platform Issue"

	return &core.EngineResult{
		EngineName:    c.Name(),
		EngineVersion: c.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (c *CrossPlatformAnalyzer) HealthCheck() bool { return true }
