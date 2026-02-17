package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadRules loads detection rules from YAML files in the rules directory.
func LoadRules(rulesDir string, engineFilter string, categoryFilter string, enabledOnly bool) ([]DetectionRule, error) {
	if rulesDir == "" {
		return []DetectionRule{}, nil
	}

	info, err := os.Stat(rulesDir)
	if err != nil || !info.IsDir() {
		return []DetectionRule{}, nil
	}

	var paths []string
	err = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	var rules []DetectionRule
	for _, p := range paths {
		rule, err := loadRuleFile(p)
		if err != nil || rule == nil {
			continue
		}
		if enabledOnly && !rule.Enabled {
			continue
		}
		if engineFilter != "" && !strings.EqualFold(rule.Engine, engineFilter) {
			continue
		}
		if categoryFilter != "" && rule.Category != categoryFilter {
			continue
		}
		rules = append(rules, *rule)
	}

	return rules, nil
}

func loadRuleFile(path string) (*DetectionRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	if raw == nil || raw["id"] == nil {
		return nil, nil
	}

	rule := &DetectionRule{
		ID:          getString(raw, "id"),
		Name:        getStringDefault(raw, "name", getString(raw, "id")),
		Description: getStringDefault(raw, "description", ""),
		Severity:    Severity(getStringDefault(raw, "severity", "medium")),
		Category:    getStringDefault(raw, "category", "unknown"),
		OWASPLLM:    getStringSlice(raw, "owasp_llm"),
		MITREAttack: getStringSlice(raw, "mitre_attack"),
		Target:      getStringDefault(raw, "target", "ANY"),
		Engine:      getStringDefault(raw, "engine", "REGEX"),
		Pattern:     raw["pattern"],
		FalsePositiveNotes: getStringDefault(raw, "false_positive_notes", ""),
		Remediation: getStringDefault(raw, "remediation", ""),
		References:  getStringSlice(raw, "references"),
		Enabled:     getBoolDefault(raw, "enabled", true),
	}

	return rule, nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringDefault(m map[string]any, key, def string) string {
	s := getString(m, key)
	if s == "" {
		return def
	}
	return s
}

func getStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func getBoolDefault(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
