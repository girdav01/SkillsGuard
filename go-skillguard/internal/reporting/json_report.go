// Package reporting provides report generation in various formats.
package reporting

import (
	"encoding/json"

	"github.com/girdav01/skillguard/internal/core"
)

// GenerateJSONReport generates a JSON report from scan results.
func GenerateJSONReport(result *core.ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateJSONSummary generates a concise JSON summary without detailed findings.
func GenerateJSONSummary(result *core.ScanResult) (string, error) {
	type summaryEngine struct {
		EngineName    string             `json:"engine_name"`
		EngineVersion string             `json:"engine_version"`
		Verdict       core.EngineVerdict `json:"verdict"`
		Confidence    float64            `json:"confidence"`
		FindingsCount int                `json:"findings_count"`
		DurationMs    int64              `json:"duration_ms"`
	}

	engines := make([]summaryEngine, len(result.EngineResults))
	for i, er := range result.EngineResults {
		engines[i] = summaryEngine{
			EngineName:    er.EngineName,
			EngineVersion: er.EngineVersion,
			Verdict:       er.Verdict,
			Confidence:    er.Confidence,
			FindingsCount: len(er.Findings),
			DurationMs:    er.DurationMs,
		}
	}

	summary := map[string]any{
		"scan_id":              result.ScanID,
		"skill_name":           result.SkillName,
		"composite_score":      result.CompositeScore,
		"verdict":              result.Verdict,
		"total_findings":       result.TotalFindings,
		"findings_by_severity": result.FindingsBySeverity,
		"files_scanned":        result.FilesScanned,
		"engine_results":       engines,
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
