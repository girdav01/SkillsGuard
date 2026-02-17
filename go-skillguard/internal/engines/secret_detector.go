package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type secretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity core.Severity
}

var secretPatterns []secretPattern

func init() {
	rawPatterns := []struct {
		name     string
		pattern  string
		severity core.Severity
	}{
		{"AWS Access Key", `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, core.SeverityCritical},
		{"AWS Secret Key", `(?i)aws[_\-\s]*secret[_\-\s]*(?:access)?[_\-\s]*key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})`, core.SeverityCritical},
		{"GitHub Token", `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`, core.SeverityCritical},
		{"GitHub Fine-grained PAT", `github_pat_[A-Za-z0-9_]{22,}`, core.SeverityCritical},
		{"Slack Token", `xox[bporas]-[0-9]{10,}-[A-Za-z0-9-]+`, core.SeverityHigh},
		{"Slack Webhook", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`, core.SeverityHigh},
		{"OpenAI API Key", `sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`, core.SeverityCritical},
		{"Anthropic API Key", `sk-ant-[A-Za-z0-9\-_]{40,}`, core.SeverityCritical},
		{"Google API Key", `AIza[0-9A-Za-z\-_]{35}`, core.SeverityHigh},
		{"Stripe Secret Key", `sk_(?:live|test)_[0-9a-zA-Z]{24,}`, core.SeverityCritical},
		{"Stripe Publishable Key", `pk_(?:live|test)_[0-9a-zA-Z]{24,}`, core.SeverityMedium},
		{"Twilio API Key", `SK[a-f0-9]{32}`, core.SeverityHigh},
		{"SendGrid API Key", `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`, core.SeverityHigh},
		{"Mailgun API Key", `key-[0-9a-zA-Z]{32}`, core.SeverityHigh},
		{"RSA Private Key", `-----BEGIN (?:RSA )?PRIVATE KEY-----`, core.SeverityCritical},
		{"SSH Private Key EC", `-----BEGIN EC PRIVATE KEY-----`, core.SeverityCritical},
		{"SSH Private Key OpenSSH", `-----BEGIN OPENSSH PRIVATE KEY-----`, core.SeverityCritical},
		{"PGP Private Key", `-----BEGIN PGP PRIVATE KEY BLOCK-----`, core.SeverityCritical},
		{"Generic Secret Assignment", `(?i)(?:secret|password|passwd|pwd|token|auth_token|api_key|apikey|access_key)\s*[=:]\s*['"][A-Za-z0-9+/=_\-]{16,}['"]`, core.SeverityHigh},
		{"Basic Auth in URL", `https?://[^:]+:[^@]+@[^\s]+`, core.SeverityHigh},
		{"JWT Token", `eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`, core.SeverityHigh},
		{"Connection String", `(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s'"]+`, core.SeverityHigh},
	}
	for _, rp := range rawPatterns {
		compiled, err := regexp.Compile(rp.pattern)
		if err != nil {
			continue
		}
		secretPatterns = append(secretPatterns, secretPattern{
			Name:     rp.name,
			Pattern:  compiled,
			Severity: rp.severity,
		})
	}
}

// SecretDetector detects hardcoded credentials and API keys.
type SecretDetector struct{}

func NewSecretDetector() *SecretDetector { return &SecretDetector{} }

func (s *SecretDetector) Name() string    { return "secret_detector" }
func (s *SecretDetector) Version() string { return "0.1.0" }

func (s *SecretDetector) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		lines := strings.Split(content, "\n")

		for _, sp := range secretPatterns {
			matches := sp.Pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				lineNum := strings.Count(content[:match[0]], "\n") + 1
				matched := content[match[0]:match[1]]
				redacted := matched
				if len(redacted) > 12 {
					redacted = redacted[:8] + "..." + redacted[len(redacted)-4:]
				}

				snippetLine := ""
				if lineNum <= len(lines) {
					snippetLine = redactLine(lines[lineNum-1])
				}

				ruleID := fmt.Sprintf("SG-SECRET-%s", strings.ToUpper(strings.ReplaceAll(sp.Name, " ", "_")))
				cwe := "CWE-798"
				remediation := "Remove hardcoded secrets and use environment variables or a secret manager instead."
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    "Hardcoded " + sp.Name,
					Severity:    sp.Severity,
					Category:    "credential_theft",
					Description: fmt.Sprintf("Potential %s found in file. Hardcoded secrets can be extracted and misused.", sp.Name),
					FilePath:    sf.Path,
					LineStart:   &lineNum,
					LineEnd:     &lineNum,
					Snippet:     &snippetLine,
					CWE:         &cwe,
					OWASPLLM:    []string{"LLM06"},
					Confidence:  0.75,
					Remediation: &remediation,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    s.Name(),
			EngineVersion: s.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    1.0,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	maxConf := computeConfidence(findings)

	return &core.EngineResult{
		EngineName:    s.Name(),
		EngineVersion: s.Version(),
		Verdict:       verdict,
		Confidence:    maxConf,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (s *SecretDetector) HealthCheck() bool { return true }

func redactLine(line string) string {
	if len(line) > 200 {
		return line[:100] + " [REDACTED] " + line[len(line)-50:]
	}
	return line
}
