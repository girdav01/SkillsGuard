// Package core provides the foundational data models and types for SkillGuard.
package core

import "time"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityPoints maps severity to risk score points.
var SeverityPoints = map[Severity]int{
	SeverityCritical: 40,
	SeverityHigh:     20,
	SeverityMedium:   10,
	SeverityLow:      3,
	SeverityInfo:     0,
}

// Verdict is the overall scan verdict.
type Verdict string

const (
	VerdictClean      Verdict = "clean"
	VerdictLowRisk    Verdict = "low_risk"
	VerdictSuspicious Verdict = "suspicious"
	VerdictHighRisk   Verdict = "high_risk"
	VerdictMalicious  Verdict = "malicious"
)

// EngineVerdict is a per-engine verdict.
type EngineVerdict string

const (
	EngineVerdictClean      EngineVerdict = "clean"
	EngineVerdictSuspicious EngineVerdict = "suspicious"
	EngineVerdictMalicious  EngineVerdict = "malicious"
)

// SkillPlatform identifies the AI platform.
type SkillPlatform string

const (
	PlatformClaudeCode    SkillPlatform = "claude_code"
	PlatformClaudeDesktop SkillPlatform = "claude_desktop"
	PlatformCursor        SkillPlatform = "cursor"
	PlatformWindsurf      SkillPlatform = "windsurf"
	PlatformOpenClaw      SkillPlatform = "openclaw"
	PlatformGeneric       SkillPlatform = "generic"
)

// FileType classifies files within a skill package.
type FileType string

const (
	FileTypeSkillMD  FileType = "skill_md"
	FileTypeFrontmatter FileType = "frontmatter"
	FileTypeScriptPython FileType = "script_python"
	FileTypeScriptBash   FileType = "script_bash"
	FileTypeScriptJS     FileType = "script_javascript"
	FileTypeScriptTS     FileType = "script_typescript"
	FileTypeTemplate     FileType = "template"
	FileTypeResource     FileType = "resource"
	FileTypeConfig       FileType = "config"
	FileTypeOther        FileType = "other"
)

// SkillFile represents a single file within a skill package.
type SkillFile struct {
	Path      string   `json:"path"`
	FileType  FileType `json:"file_type"`
	SHA256    string   `json:"sha256"`
	SizeBytes int64    `json:"size_bytes"`
	Content   *string  `json:"content,omitempty"`
}

// Finding represents a single security finding from a scan engine.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	FilePath    string   `json:"file_path"`
	LineStart   *int     `json:"line_start,omitempty"`
	LineEnd     *int     `json:"line_end,omitempty"`
	Snippet     *string  `json:"snippet,omitempty"`
	CWE         *string  `json:"cwe,omitempty"`
	OWASPLLM    []string `json:"owasp_llm,omitempty"`
	MITREAttack []string `json:"mitre_attack,omitempty"`
	Confidence  float64  `json:"confidence"`
	Remediation *string  `json:"remediation,omitempty"`
}

// EngineResult holds the result from a single scanning engine.
type EngineResult struct {
	EngineName    string        `json:"engine_name"`
	EngineVersion string        `json:"engine_version"`
	Verdict       EngineVerdict `json:"verdict"`
	Confidence    float64       `json:"confidence"`
	DetectionName *string       `json:"detection_name,omitempty"`
	Findings      []Finding     `json:"findings"`
	DurationMs    int64         `json:"duration_ms"`
}

// ScanResult is the complete scan result aggregating all engine results.
type ScanResult struct {
	ScanID             string         `json:"scan_id"`
	SkillName          string         `json:"skill_name"`
	SkillSHA256        string         `json:"skill_sha256"`
	Platform           SkillPlatform  `json:"platform"`
	ScanStarted        time.Time      `json:"scan_started"`
	ScanCompleted      time.Time      `json:"scan_completed"`
	CompositeScore     int            `json:"composite_score"`
	Verdict            Verdict        `json:"verdict"`
	EngineResults      []EngineResult `json:"engine_results"`
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FilesScanned       int            `json:"files_scanned"`
	OWASPCoverage      []string       `json:"owasp_coverage,omitempty"`
}

// ScanRequest represents a request to scan a skill.
type ScanRequest struct {
	SkillPath string        `json:"skill_path,omitempty"`
	GitURL    string        `json:"git_url,omitempty"`
	ScanType  string        `json:"scan_type"`
	Platform  SkillPlatform `json:"platform"`
}

// DetectionRule is a detection rule loaded from YAML.
type DetectionRule struct {
	ID                 string   `json:"id" yaml:"id"`
	Name               string   `json:"name" yaml:"name"`
	Description        string   `json:"description" yaml:"description"`
	Severity           Severity `json:"severity" yaml:"severity"`
	Category           string   `json:"category" yaml:"category"`
	OWASPLLM           []string `json:"owasp_llm" yaml:"owasp_llm"`
	MITREAttack        []string `json:"mitre_attack" yaml:"mitre_attack"`
	Target             string   `json:"target" yaml:"target"`
	Engine             string   `json:"engine" yaml:"engine"`
	Pattern            any      `json:"pattern" yaml:"pattern"`
	FalsePositiveNotes string   `json:"false_positive_notes,omitempty" yaml:"false_positive_notes"`
	Remediation        string   `json:"remediation,omitempty" yaml:"remediation"`
	References         []string `json:"references,omitempty" yaml:"references"`
	Enabled            bool     `json:"enabled" yaml:"enabled"`
}

// NewScanRequest creates a ScanRequest with defaults.
func NewScanRequest(skillPath string) ScanRequest {
	return ScanRequest{
		SkillPath: skillPath,
		ScanType:  "full",
		Platform:  PlatformGeneric,
	}
}
