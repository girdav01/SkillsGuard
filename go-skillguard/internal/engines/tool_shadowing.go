package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

var protectedToolNames = map[string]bool{
	"read_file": true, "write_file": true, "edit_file": true, "create_file": true, "delete_file": true,
	"list_files": true, "search_files": true, "read": true, "write": true, "edit": true,
	"run_command": true, "execute": true, "bash": true, "shell": true, "terminal": true,
	"run_bash": true, "exec": true, "command": true,
	"browse": true, "web_search": true, "fetch_url": true, "navigate": true,
	"browser": true, "web_fetch": true,
	"search_code": true, "grep": true, "find": true, "glob": true,
	"git": true, "git_commit": true, "git_push": true, "git_pull": true,
	"list_directory": true, "get_cwd": true, "pwd": true,
	"computer": true, "text_editor": true, "str_replace_editor": true,
}

var toolNamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`),
	regexp.MustCompile(`(?m)^\s*name\s*:\s*['"]?(\w+)['"]?`),
	regexp.MustCompile(`(?:tool_name|name)\s*=\s*['"](\w+)['"]`),
	regexp.MustCompile(`@(?:tool|function)\(['"](\w+)['"]\)`),
}

// ToolShadowingDetector detects tool name shadowing and conflicts.
type ToolShadowingDetector struct{}

func NewToolShadowingDetector() *ToolShadowingDetector { return &ToolShadowingDetector{} }

func (t *ToolShadowingDetector) Name() string    { return "mcp_tool_shadowing" }
func (t *ToolShadowingDetector) Version() string { return "0.2.0" }

func (t *ToolShadowingDetector) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	// Collect all tool names across files
	type toolLocation struct {
		filePath string
		lineNum  int
	}
	allToolNames := make(map[string][]toolLocation)

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		names := extractToolNames(sf)
		for _, tn := range names {
			allToolNames[tn.name] = append(allToolNames[tn.name], toolLocation{sf.Path, tn.lineNum})
		}
	}

	// Check for shadowing of protected names
	for toolName, locations := range allToolNames {
		normalized := strings.ToLower(strings.ReplaceAll(toolName, "-", "_"))
		if protectedToolNames[normalized] {
			for _, loc := range locations {
				lineNum := loc.lineNum
				remediation := fmt.Sprintf("Rename the tool to avoid shadowing '%s'. Use a unique, descriptive name.", normalized)
				findings = append(findings, core.Finding{
					RuleID:      "SG-MCP-SHADOW-001",
					RuleName:    "Protected Tool Name Shadowing",
					Severity:    core.SeverityHigh,
					Category:    "mcp_tool_shadowing",
					Description: fmt.Sprintf("Tool name '%s' shadows a protected/built-in tool name. This could intercept legitimate tool calls.", toolName),
					FilePath:    loc.filePath,
					LineStart:   &lineNum,
					OWASPLLM:    []string{"LLM07"},
					MITREAttack: []string{"T1557"},
					Confidence:  0.85,
					Remediation: &remediation,
				})
			}
		}
	}

	// Check for duplicates
	for toolName, locations := range allToolNames {
		if len(locations) > 1 {
			for _, loc := range locations[1:] {
				lineNum := loc.lineNum
				remediation := "Remove duplicate tool definitions."
				findings = append(findings, core.Finding{
					RuleID:      "SG-MCP-SHADOW-002",
					RuleName:    "Duplicate Tool Name",
					Severity:    core.SeverityMedium,
					Category:    "mcp_tool_shadowing",
					Description: fmt.Sprintf("Tool name '%s' is defined multiple times. Duplicate definitions could cause unpredictable behavior.", toolName),
					FilePath:    loc.filePath,
					LineStart:   &lineNum,
					OWASPLLM:    []string{"LLM07"},
					Confidence:  0.75,
					Remediation: &remediation,
				})
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    t.Name(),
			EngineVersion: t.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.8,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	maxConf := computeConfidence(findings)
	verdict := computeVerdict(findings)
	det := "MCP Tool Shadowing"

	return &core.EngineResult{
		EngineName:    t.Name(),
		EngineVersion: t.Version(),
		Verdict:       verdict,
		Confidence:    maxConf,
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (t *ToolShadowingDetector) HealthCheck() bool { return true }

type toolName struct {
	name    string
	lineNum int
}

func extractToolNames(sf core.SkillFile) []toolName {
	if sf.Content == nil {
		return nil
	}
	content := *sf.Content
	var names []toolName
	for _, pattern := range toolNamePatterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				name := content[match[2]:match[3]]
				lineNum := strings.Count(content[:match[0]], "\n") + 1
				names = append(names, toolName{name, lineNum})
			}
		}
	}
	return names
}
