package engines

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

var suspiciousDomains = regexp.MustCompile(`(?i)(?:ngrok|localtunnel|serveo|pagekite|telebit|localhost\.run|burpcollaborator|interactsh|pipedream|webhook\.site|requestbin|hookbin|beeceptor)`)
var sensitivePaths = regexp.MustCompile(`(?:\.ssh|\.aws|\.gnupg|\.netrc|\.env|credentials|id_rsa|id_ed25519|\.pem|\.key|shadow|passwd|htpasswd)`)

// MCPConfigScanner scans MCP configuration files for security issues.
type MCPConfigScanner struct{}

func NewMCPConfigScanner() *MCPConfigScanner { return &MCPConfigScanner{} }

func (m *MCPConfigScanner) Name() string    { return "mcp_config_scanner" }
func (m *MCPConfigScanner) Version() string { return "0.2.0" }

func (m *MCPConfigScanner) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		if sf.FileType == core.FileTypeConfig || isConfigFile(sf.Path) {
			findings = append(findings, m.scanConfig(sf)...)
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    m.Name(),
			EngineVersion: m.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.8,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	maxConf := computeConfidence(findings)
	verdict := computeVerdict(findings)
	det := "MCP Config Issue"

	return &core.EngineResult{
		EngineName:    m.Name(),
		EngineVersion: m.Version(),
		Verdict:       verdict,
		Confidence:    maxConf,
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (m *MCPConfigScanner) HealthCheck() bool { return true }

func (m *MCPConfigScanner) scanConfig(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	findings = append(findings, checkInsecureTransport(sf)...)
	findings = append(findings, checkSuspiciousURLs(sf)...)
	findings = append(findings, checkSensitivePaths(sf)...)
	findings = append(findings, checkWildcardPermissions(sf)...)
	if strings.HasSuffix(sf.Path, ".json") {
		findings = append(findings, checkJSONConfig(sf)...)
	}
	return findings
}

func checkInsecureTransport(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content

	// Go regexp doesn't support lookahead (?!), so we match all http:// then filter
	httpPattern := regexp.MustCompile(`http://(\S+)`)
	localPrefixes := []string{"localhost", "127.0.0.1", "0.0.0.0", "[::1]"}

	matches := httpPattern.FindAllStringIndex(content, -1)
	for _, match := range matches {
		matched := content[match[0]:match[1]]
		host := strings.TrimPrefix(matched, "http://")
		isLocal := false
		for _, prefix := range localPrefixes {
			if strings.HasPrefix(host, prefix) {
				isLocal = true
				break
			}
		}
		if isLocal {
			continue
		}

		lineNum := strings.Count(content[:match[0]], "\n") + 1
		snippet := matched
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		remediation := "Use HTTPS instead of HTTP for MCP server connections."
		findings = append(findings, core.Finding{
			RuleID:      "SG-MCP-CFG-001",
			RuleName:    "Insecure HTTP Transport",
			Severity:    core.SeverityHigh,
			Category:    "mcp_config",
			Description: "MCP server configured with insecure HTTP transport. Use HTTPS for encrypted communication.",
			FilePath:    sf.Path,
			LineStart:   &lineNum,
			Snippet:     &snippet,
			OWASPLLM:    []string{"LLM07"},
			Confidence:  0.90,
			Remediation: &remediation,
		})
	}
	return findings
}

func checkSuspiciousURLs(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content
	matches := suspiciousDomains.FindAllStringIndex(strings.ToLower(content), -1)
	for _, match := range matches {
		lineNum := strings.Count(content[:match[0]], "\n") + 1
		matched := strings.ToLower(content[match[0]:match[1]])
		remediation := "Use production-grade server URLs instead of tunneling services."
		findings = append(findings, core.Finding{
			RuleID:      "SG-MCP-CFG-002",
			RuleName:    "Suspicious Tunneling Service",
			Severity:    core.SeverityHigh,
			Category:    "mcp_config",
			Description: fmt.Sprintf("MCP config references tunneling/proxy service '%s'. Commonly used to expose local services.", matched),
			FilePath:    sf.Path,
			LineStart:   &lineNum,
			OWASPLLM:    []string{"LLM07"},
			MITREAttack: []string{"T1071.001"},
			Confidence:  0.80,
			Remediation: &remediation,
		})
	}
	return findings
}

func checkSensitivePaths(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content
	matches := sensitivePaths.FindAllStringIndex(content, -1)
	for _, match := range matches {
		lineNum := strings.Count(content[:match[0]], "\n") + 1
		matched := content[match[0]:match[1]]
		remediation := "Remove direct references to sensitive files."
		findings = append(findings, core.Finding{
			RuleID:      "SG-MCP-CFG-003",
			RuleName:    "Sensitive Path Reference",
			Severity:    core.SeverityHigh,
			Category:    "mcp_config",
			Description: fmt.Sprintf("MCP config references sensitive path '%s'.", matched),
			FilePath:    sf.Path,
			LineStart:   &lineNum,
			OWASPLLM:    []string{"LLM06"},
			MITREAttack: []string{"T1552.001"},
			Confidence:  0.85,
			Remediation: &remediation,
		})
	}
	return findings
}

func checkWildcardPermissions(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content
	wildcardPatterns := []struct {
		pattern string
		desc    string
	}{
		{`"permissions"\s*:\s*\[\s*"\*"\s*\]`, "wildcard permissions"},
		{`"allowedTools"\s*:\s*\[\s*"\*"\s*\]`, "unrestricted tool access"},
	}
	for _, wp := range wildcardPatterns {
		re, err := regexp.Compile(wp.pattern)
		if err != nil {
			continue
		}
		matches := re.FindAllStringIndex(content, -1)
		for _, match := range matches {
			lineNum := strings.Count(content[:match[0]], "\n") + 1
			snippet := content[match[0]:match[1]]
			if len(snippet) > 200 {
				snippet = snippet[:200]
			}
			remediation := "Restrict permissions to only required tools."
			findings = append(findings, core.Finding{
				RuleID:      "SG-MCP-CFG-004",
				RuleName:    "Overly Permissive Configuration",
				Severity:    core.SeverityHigh,
				Category:    "mcp_config",
				Description: fmt.Sprintf("MCP config has %s. Restrict access.", wp.desc),
				FilePath:    sf.Path,
				LineStart:   &lineNum,
				Snippet:     &snippet,
				OWASPLLM:    []string{"LLM07"},
				Confidence:  0.85,
				Remediation: &remediation,
			})
		}
	}
	return findings
}

func checkJSONConfig(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	var data map[string]any
	if err := json.Unmarshal([]byte(*sf.Content), &data); err != nil {
		return findings
	}

	servers, ok := data["mcpServers"]
	if !ok {
		servers = data["servers"]
	}
	serversMap, ok := servers.(map[string]any)
	if !ok {
		return findings
	}

	for serverName, config := range serversMap {
		configMap, ok := config.(map[string]any)
		if !ok {
			continue
		}
		command, ok := configMap["command"].(string)
		if !ok {
			continue
		}
		for _, c := range []string{"|", ";", "&&", "`", "$("} {
			if strings.Contains(command, c) {
				snippet := fmt.Sprintf(`"command": "%s"`, truncate(command, 100))
				remediation := "Use simple command strings without shell operators."
				findings = append(findings, core.Finding{
					RuleID:      "SG-MCP-CFG-006",
					RuleName:    "Command Injection in Server Config",
					Severity:    core.SeverityCritical,
					Category:    "mcp_config",
					Description: fmt.Sprintf("MCP server '%s' has command with potential injection characters.", serverName),
					FilePath:    sf.Path,
					Snippet:     &snippet,
					OWASPLLM:    []string{"LLM06"},
					MITREAttack: []string{"T1059"},
					Confidence:  0.90,
					Remediation: &remediation,
				})
				break
			}
		}
	}
	return findings
}

func isConfigFile(path string) bool {
	lower := strings.ToLower(path)
	configExts := []string{".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
	for _, ext := range configExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	configNames := []string{"config", "settings", "mcp", "claude_desktop_config", ".mcp"}
	base := strings.ToLower(strings.TrimSuffix(lower, strings.ToLower(getExt(lower))))
	for _, name := range configNames {
		if strings.HasSuffix(base, name) {
			return true
		}
	}
	return false
}

func getExt(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	return ""
}
