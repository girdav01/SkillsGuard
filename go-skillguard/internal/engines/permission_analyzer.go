package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type permPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity core.Severity
	Desc     string
}

var permPatterns []permPattern

func init() {
	rawPerms := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
	}{
		{"Filesystem Write", `(?i)(?:write_file|create_file|fs\.write|writeFile|open\s*\(.*?['"]w)`, core.SeverityMedium, "Skill requests filesystem write permissions."},
		{"Filesystem Delete", `(?i)(?:delete_file|remove_file|unlink|rmtree|rmdir)`, core.SeverityHigh, "Skill requests filesystem delete permissions."},
		{"Network Outbound", `(?i)(?:requests\.(?:get|post|put|delete)|fetch\s*\(|http\.request|urllib|httpx)`, core.SeverityMedium, "Skill makes outbound network requests."},
		{"Shell Execution", `(?i)(?:subprocess|os\.system|exec\s*\(|child_process|spawn|popen)`, core.SeverityHigh, "Skill executes shell commands."},
		{"Environment Access", `(?i)(?:os\.environ|process\.env|getenv|ENV\[)`, core.SeverityMedium, "Skill accesses environment variables."},
		{"Database Access", `(?i)(?:sqlite|psycopg|mysql|mongodb|redis|sqlalchemy)`, core.SeverityMedium, "Skill accesses databases."},
		{"Crypto Operations", `(?i)(?:hashlib|hmac|crypto\.subtle|bcrypt|scrypt)`, core.SeverityLow, "Skill performs cryptographic operations."},
		{"Email Sending", `(?i)(?:smtplib|sendmail|nodemailer|send_email)`, core.SeverityMedium, "Skill sends emails."},
	}
	for _, rp := range rawPerms {
		compiled, err := regexp.Compile(rp.pattern)
		if err != nil {
			continue
		}
		permPatterns = append(permPatterns, permPattern{rp.name, compiled, rp.severity, rp.desc})
	}
}

// PermissionAnalyzer analyzes permissions and capabilities requested by skills.
type PermissionAnalyzer struct{}

func NewPermissionAnalyzer() *PermissionAnalyzer { return &PermissionAnalyzer{} }

func (p *PermissionAnalyzer) Name() string    { return "permission_analyzer" }
func (p *PermissionAnalyzer) Version() string { return "0.3.0" }

func (p *PermissionAnalyzer) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		for _, pp := range permPatterns {
			matches := pp.Pattern.FindAllStringIndex(content, -1)
			if len(matches) > 0 {
				lineStart := strings.Count(content[:matches[0][0]], "\n") + 1
				snippet := content[matches[0][0]:matches[0][1]]
				ruleID := fmt.Sprintf("SG-PERM-%s", strings.ToUpper(strings.ReplaceAll(pp.Name, " ", "-"))[:min(15, len(strings.ReplaceAll(pp.Name, " ", "-")))])
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    pp.Name,
					Severity:    pp.Severity,
					Category:    "permissions",
					Description: pp.Desc,
					FilePath:    sf.Path,
					LineStart:   &lineStart,
					Snippet:     &snippet,
					OWASPLLM:    []string{"LLM06"},
					Confidence:  0.70,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    p.Name(),
			EngineVersion: p.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.7,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	return &core.EngineResult{
		EngineName:    p.Name(),
		EngineVersion: p.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (p *PermissionAnalyzer) HealthCheck() bool { return true }
