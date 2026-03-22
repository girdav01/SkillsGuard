package engines

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

// SchemaValidator validates MCP tool schemas and skill structure.
type SchemaValidator struct{}

func NewSchemaValidator() *SchemaValidator { return &SchemaValidator{} }

func (s *SchemaValidator) Name() string    { return "schema_validator" }
func (s *SchemaValidator) Version() string { return "0.3.0" }

func (s *SchemaValidator) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	hasSkillMD := false
	for _, sf := range skillFiles {
		if sf.FileType == core.FileTypeSkillMD {
			hasSkillMD = true
		}
		if sf.Content == nil {
			continue
		}
		if sf.FileType == core.FileTypeConfig || strings.HasSuffix(sf.Path, ".json") {
			findings = append(findings, s.validateJSON(sf)...)
		}
		if sf.FileType == core.FileTypeSkillMD {
			findings = append(findings, s.validateSkillMD(sf)...)
		}
	}

	// Check deserialization safety for script files
	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		if sf.FileType == core.FileTypeScriptPython || sf.FileType == core.FileTypeScriptBash || sf.FileType == core.FileTypeScriptJS || sf.FileType == core.FileTypeScriptTS {
			findings = append(findings, s.checkDeserializationSafety(sf)...)
		}
	}

	if !hasSkillMD && len(skillFiles) > 0 {
		remediation := "Add a SKILL.md file with proper metadata and description."
		findings = append(findings, core.Finding{
			RuleID:      "SG-SCHEMA-001",
			RuleName:    "Missing SKILL.md",
			Severity:    core.SeverityLow,
			Category:    "schema",
			Description: "Skill package does not contain a SKILL.md file with metadata.",
			FilePath:    ".",
			Confidence:  0.95,
			Remediation: &remediation,
		})
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    s.Name(),
			EngineVersion: s.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.9,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	verdict := computeVerdict(findings)
	return &core.EngineResult{
		EngineName:    s.Name(),
		EngineVersion: s.Version(),
		Verdict:       verdict,
		Confidence:    computeConfidence(findings),
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (s *SchemaValidator) HealthCheck() bool { return true }

func (s *SchemaValidator) validateJSON(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	var data any
	if err := json.Unmarshal([]byte(*sf.Content), &data); err != nil {
		lineNum := 1
		snippet := err.Error()
		remediation := "Fix the JSON syntax error."
		findings = append(findings, core.Finding{
			RuleID:      "SG-SCHEMA-002",
			RuleName:    "Invalid JSON",
			Severity:    core.SeverityMedium,
			Category:    "schema",
			Description: fmt.Sprintf("JSON file '%s' has syntax errors.", sf.Path),
			FilePath:    sf.Path,
			LineStart:   &lineNum,
			Snippet:     &snippet,
			Confidence:  0.95,
			Remediation: &remediation,
		})
	}
	return findings
}

func (s *SchemaValidator) validateSkillMD(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content

	fm, _ := core.ParseFrontmatter(content)
	if len(fm) == 0 {
		remediation := "Add YAML frontmatter with metadata (name, version, description)."
		findings = append(findings, core.Finding{
			RuleID:      "SG-SCHEMA-003",
			RuleName:    "Missing Frontmatter",
			Severity:    core.SeverityLow,
			Category:    "schema",
			Description: "SKILL.md file is missing YAML frontmatter with metadata.",
			FilePath:    sf.Path,
			Confidence:  0.90,
			Remediation: &remediation,
		})
	}
	return findings
}

func (s *SchemaValidator) checkDeserializationSafety(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content

	// SG-STRUCT-DS-001: Unsafe XML parsing
	xmlPattern := regexp.MustCompile(`(?i)(xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|lxml\.etree)`)
	defusedPattern := regexp.MustCompile(`(?i)defusedxml`)
	for _, match := range xmlPattern.FindAllStringIndex(content, -1) {
		// Check if defusedxml appears on the same line
		lineStart := strings.LastIndex(content[:match[0]], "\n") + 1
		lineEnd := strings.Index(content[match[1]:], "\n")
		if lineEnd < 0 {
			lineEnd = len(content)
		} else {
			lineEnd += match[1]
		}
		line := content[lineStart:lineEnd]
		if defusedPattern.MatchString(line) {
			continue
		}
		lineNum := strings.Count(content[:match[0]], "\n") + 1
		snippet := content[match[0]:match[1]]
		remediation := "Use defusedxml instead of standard XML parsers to prevent XXE attacks."
		findings = append(findings, core.Finding{
			RuleID:      "SG-STRUCT-DS-001",
			RuleName:    "Unsafe XML Parsing",
			Severity:    core.SeverityHigh,
			Category:    "structural",
			Description: fmt.Sprintf("Unsafe XML parser '%s' used without defusedxml. Vulnerable to XML external entity (XXE) attacks.", snippet),
			FilePath:    sf.Path,
			LineStart:   &lineNum,
			Snippet:     &snippet,
			OWASPAST:    []string{"AST05"},
			Confidence:  0.85,
			Remediation: &remediation,
		})
	}

	// SG-STRUCT-DS-002: JSON with code execution hooks
	jsonHookPattern := regexp.MustCompile(`(?i)json\.loads?\s*\(.*object_hook|jsonpickle\.decode`)
	for _, match := range jsonHookPattern.FindAllStringIndex(content, -1) {
		lineNum := strings.Count(content[:match[0]], "\n") + 1
		snippet := content[match[0]:match[1]]
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		remediation := "Avoid using object_hook with untrusted data. Do not use jsonpickle for untrusted input."
		findings = append(findings, core.Finding{
			RuleID:      "SG-STRUCT-DS-002",
			RuleName:    "JSON Code Execution Hook",
			Severity:    core.SeverityHigh,
			Category:    "structural",
			Description: "JSON deserialization with code execution hooks detected. This can lead to arbitrary code execution via crafted payloads.",
			FilePath:    sf.Path,
			LineStart:   &lineNum,
			Snippet:     &snippet,
			OWASPAST:    []string{"AST05"},
			Confidence:  0.80,
			Remediation: &remediation,
		})
	}

	return findings
}
