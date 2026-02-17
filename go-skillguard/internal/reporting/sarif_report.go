package reporting

import (
	"encoding/json"

	"github.com/girdav01/skillguard/internal/core"
)

var sarifSeverityMap = map[core.Severity]string{
	core.SeverityCritical: "error",
	core.SeverityHigh:     "error",
	core.SeverityMedium:   "warning",
	core.SeverityLow:      "note",
	core.SeverityInfo:     "note",
}

// GenerateSARIFReport generates a SARIF 2.1.0 report.
func GenerateSARIFReport(result *core.ScanResult) (string, error) {
	rulesMap := make(map[string]map[string]any)
	var resultsList []map[string]any

	for _, er := range result.EngineResults {
		for _, f := range er.Findings {
			if _, exists := rulesMap[f.RuleID]; !exists {
				rule := map[string]any{
					"id":               f.RuleID,
					"name":             f.RuleName,
					"shortDescription": map[string]string{"text": f.RuleName},
					"fullDescription":  map[string]string{"text": f.Description},
					"defaultConfiguration": map[string]string{
						"level": sarifSeverityMap[f.Severity],
					},
					"properties": map[string]any{
						"tags": []string{f.Category},
					},
				}
				if len(f.OWASPLLM) > 0 {
					rule["properties"].(map[string]any)["owasp_llm"] = f.OWASPLLM
				}
				if len(f.MITREAttack) > 0 {
					rule["properties"].(map[string]any)["mitre_attack"] = f.MITREAttack
				}
				if f.CWE != nil {
					rule["properties"].(map[string]any)["cwe"] = *f.CWE
				}
				rulesMap[f.RuleID] = rule
			}

			region := map[string]any{}
			if f.LineStart != nil {
				region["startLine"] = *f.LineStart
			}
			if f.LineEnd != nil {
				region["endLine"] = *f.LineEnd
			}
			if f.Snippet != nil {
				region["snippet"] = map[string]string{"text": *f.Snippet}
			}

			sarifResult := map[string]any{
				"ruleId":  f.RuleID,
				"level":   sarifSeverityMap[f.Severity],
				"message": map[string]string{"text": f.Description},
				"locations": []map[string]any{
					{
						"physicalLocation": map[string]any{
							"artifactLocation": map[string]string{"uri": f.FilePath},
							"region":           region,
						},
					},
				},
			}

			if f.Remediation != nil {
				sarifResult["fixes"] = []map[string]any{
					{"description": map[string]string{"text": *f.Remediation}},
				}
			}

			resultsList = append(resultsList, sarifResult)
		}
	}

	rules := make([]map[string]any, 0, len(rulesMap))
	for _, r := range rulesMap {
		rules = append(rules, r)
	}

	verdictStr := string(result.Verdict)

	sarif := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "SkillGuard",
						"version":        "0.1.0",
						"informationUri": "https://github.com/skillguard/skillguard",
						"rules":          rules,
					},
				},
				"results": resultsList,
				"properties": map[string]any{
					"skillName":      result.SkillName,
					"skillSha256":    result.SkillSHA256,
					"compositeScore": result.CompositeScore,
					"verdict":        verdictStr,
					"filesScanned":   result.FilesScanned,
				},
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
