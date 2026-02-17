package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type obfPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity core.Severity
	Desc     string
}

var obfPatterns []obfPattern

func init() {
	rawObf := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
	}{
		{"Base64 Encoded Payload", `(?i)(?:atob|btoa|base64\.b64decode|base64\.decode|Buffer\.from)\s*\(`, core.SeverityMedium, "Potential base64 encoded payload detected."},
		{"Hex Encoded String", `(?i)(?:bytes\.fromhex|Buffer\.from\s*\([^)]*,\s*['"]hex['"]\)|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,})`, core.SeverityMedium, "Hex-encoded strings detected that may hide malicious content."},
		{"Chr/Char Construction", `(?i)(?:chr\s*\(\s*\d+\s*\)\s*\+\s*chr|String\.fromCharCode\s*\([\d,\s]+\)|pack\s*\(\s*['"]C)`, core.SeverityHigh, "Character code construction detected, commonly used for obfuscation."},
		{"Eval of Constructed String", `(?i)(?:eval\s*\(\s*(?:chr|join|decode|decompress|unhexlify)|exec\s*\(\s*(?:compile|bytes|decode))`, core.SeverityCritical, "Eval/exec of dynamically constructed string detected."},
		{"ROT13/Caesar Cipher", `(?i)(?:codecs\.decode\s*\(.*?['\"]rot.?13['\"]|rot13|caesar.?cipher)`, core.SeverityMedium, "ROT13 or Caesar cipher usage detected."},
		{"Compressed/Packed Code", `(?i)(?:zlib\.decompress|gzip\.decompress|bz2\.decompress|lzma\.decompress)`, core.SeverityMedium, "Compressed/packed code that may hide malicious payload."},
		{"Dynamic Import", `(?i)(?:__import__\s*\(|importlib\.import_module|require\s*\(\s*[^'"]\s*\+)`, core.SeverityHigh, "Dynamic import that may load malicious modules at runtime."},
		{"String Reversal", `(?i)(?:\[::\s*-1\s*\]|\.reverse\(\)|split\s*\(\s*['"]{2}\s*\)\s*\.reverse)`, core.SeverityMedium, "String reversal technique for obfuscation."},
		{"Unicode Escape", `(?i)(?:\\u[0-9a-f]{4}){4,}`, core.SeverityMedium, "Multiple Unicode escape sequences that may hide content."},
		{"Multi-layer Encoding", `(?i)(?:decode.*?decode|decompress.*?decode|b64decode.*?decompress)`, core.SeverityHigh, "Multi-layer encoding detected — commonly used in malware."},
	}
	for _, ro := range rawObf {
		compiled, err := regexp.Compile(ro.pattern)
		if err != nil {
			continue
		}
		obfPatterns = append(obfPatterns, obfPattern{ro.name, compiled, ro.severity, ro.desc})
	}
}

// ObfuscationDetector detects code obfuscation techniques.
type ObfuscationDetector struct{}

func NewObfuscationDetector() *ObfuscationDetector { return &ObfuscationDetector{} }

func (o *ObfuscationDetector) Name() string    { return "obfuscation_detector" }
func (o *ObfuscationDetector) Version() string { return "0.3.0" }

func (o *ObfuscationDetector) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		content := *sf.Content
		for _, op := range obfPatterns {
			matches := op.Pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				lineStart := strings.Count(content[:match[0]], "\n") + 1
				snippet := content[match[0]:match[1]]
				if len(snippet) > 300 {
					snippet = snippet[:300]
				}
				ruleID := fmt.Sprintf("SG-OBF-%s", strings.ToUpper(strings.ReplaceAll(op.Name, " ", "-"))[:min(15, len(strings.ReplaceAll(op.Name, " ", "-")))])
				findings = append(findings, core.Finding{
					RuleID:      ruleID,
					RuleName:    op.Name,
					Severity:    op.Severity,
					Category:    "obfuscation",
					Description: op.Desc,
					FilePath:    sf.Path,
					LineStart:   &lineStart,
					Snippet:     &snippet,
					OWASPLLM:    []string{"LLM06"},
					Confidence:  0.75,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    o.Name(),
			EngineVersion: o.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.7,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	det := "Code Obfuscation"

	return &core.EngineResult{
		EngineName:    o.Name(),
		EngineVersion: o.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (o *ObfuscationDetector) HealthCheck() bool { return true }
