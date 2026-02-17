package engines

import (
	"encoding/json"
	"fmt"
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
