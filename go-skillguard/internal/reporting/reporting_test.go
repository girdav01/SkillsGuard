package reporting

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

func makeScanResult() *core.ScanResult {
	lineStart := 5
	snippet := "eval('payload')"
	cwe := "CWE-94"
	remediation := "Remove eval usage"

	return &core.ScanResult{
		ScanID:         "test-scan-001",
		SkillName:      "test-skill",
		SkillSHA256:    "abc123def456abc123def456abc123def456abc123def456abc123def456abcde",
		Platform:       core.PlatformGeneric,
		ScanStarted:    time.Now().UTC(),
		ScanCompleted:  time.Now().UTC(),
		CompositeScore: 60,
		Verdict:        core.VerdictSuspicious,
		EngineResults: []core.EngineResult{
			{
				EngineName:    "regex_scanner",
				EngineVersion: "0.1.0",
				Verdict:       core.EngineVerdictSuspicious,
				Confidence:    0.8,
				Findings: []core.Finding{
					{
						RuleID:      "SG-CE-002",
						RuleName:    "Eval Injection",
						Severity:    core.SeverityHigh,
						Category:    "code_execution",
						Description: "Detected eval usage that could execute arbitrary code.",
						FilePath:    "main.py",
						LineStart:   &lineStart,
						Snippet:     &snippet,
						CWE:         &cwe,
						OWASPLLM:    []string{"LLM06"},
						Confidence:  0.8,
						Remediation: &remediation,
					},
				},
				DurationMs: 15,
			},
		},
		TotalFindings:      1,
		FindingsBySeverity: map[string]int{"high": 1},
		FilesScanned:       5,
	}
}

func TestGenerateJSONReport(t *testing.T) {
	result := makeScanResult()
	report, err := GenerateJSONReport(result)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !strings.Contains(report, "test-scan-001") {
		t.Error("Report should contain scan ID")
	}
	if !strings.Contains(report, "test-skill") {
		t.Error("Report should contain skill name")
	}

	// Should be valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(report), &parsed); err != nil {
		t.Fatalf("Report is not valid JSON: %v", err)
	}
}

func TestGenerateJSONSummary(t *testing.T) {
	result := makeScanResult()
	summary, err := GenerateJSONSummary(result)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !strings.Contains(summary, "test-scan-001") {
		t.Error("Summary should contain scan ID")
	}
}

func TestGenerateSARIFReport(t *testing.T) {
	result := makeScanResult()
	report, err := GenerateSARIFReport(result)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !strings.Contains(report, "2.1.0") {
		t.Error("SARIF report should contain version 2.1.0")
	}
	if !strings.Contains(report, "SkillGuard") {
		t.Error("SARIF report should contain SkillGuard")
	}
	if !strings.Contains(report, "SG-CE-002") {
		t.Error("SARIF report should contain rule ID")
	}

	// Validate JSON structure
	var sarif map[string]any
	if err := json.Unmarshal([]byte(report), &sarif); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Error("SARIF version should be 2.1.0")
	}
}

func TestGenerateHTMLReport(t *testing.T) {
	result := makeScanResult()
	report := GenerateHTMLReport(result)
	if !strings.Contains(report, "<!DOCTYPE html>") {
		t.Error("HTML report should contain DOCTYPE")
	}
	if !strings.Contains(report, "test-skill") {
		t.Error("HTML report should contain skill name")
	}
	if !strings.Contains(report, "60/100") {
		t.Error("HTML report should contain score")
	}
	if !strings.Contains(report, "SUSPICIOUS") {
		t.Error("HTML report should contain verdict")
	}
}

func TestGenerateHTMLReportClean(t *testing.T) {
	result := &core.ScanResult{
		ScanID:         "clean-001",
		SkillName:      "clean-skill",
		SkillSHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
		ScanStarted:    time.Now().UTC(),
		ScanCompleted:  time.Now().UTC(),
		CompositeScore: 0,
		Verdict:        core.VerdictClean,
		EngineResults:  []core.EngineResult{},
		TotalFindings:  0,
		FindingsBySeverity: map[string]int{},
		FilesScanned:   3,
	}
	report := GenerateHTMLReport(result)
	if !strings.Contains(report, "clean-skill") {
		t.Error("HTML report should contain skill name")
	}
}

func TestGenerateAIBOM(t *testing.T) {
	result := makeScanResult()
	bom := GenerateAIBOM(result)

	if bom["bomFormat"] != "CycloneDX" {
		t.Error("BOM format should be CycloneDX")
	}
	if bom["specVersion"] != "1.5" {
		t.Error("Spec version should be 1.5")
	}

	components, ok := bom["components"].([]map[string]any)
	if !ok || len(components) == 0 {
		t.Error("Should have components")
	}
	if components[0]["name"] != "test-skill" {
		t.Error("Main component should be skill name")
	}

	// Should have vulnerabilities since there are findings
	vulns, ok := bom["vulnerabilities"].([]map[string]any)
	if !ok || len(vulns) == 0 {
		t.Error("Should have vulnerabilities from findings")
	}
}

func TestGenerateAIBOMJSON(t *testing.T) {
	result := makeScanResult()
	jsonStr, err := GenerateAIBOMJSON(result)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !strings.Contains(jsonStr, "CycloneDX") {
		t.Error("JSON should contain CycloneDX")
	}
}
