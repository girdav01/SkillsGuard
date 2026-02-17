package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type poisonPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    core.Severity
	Description string
}

var poisoningPatterns []poisonPattern
var configPoisoningPatterns []poisonPattern

func init() {
	rawPoisoning := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
	}{
		{"Hidden Instructions in Tool Description", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:ignore|disregard|override|forget)\s+(?:previous|prior|all|your)\s+(?:instructions|rules|guidelines)`, core.SeverityCritical, "Tool description contains hidden override instructions that could manipulate agent behavior."},
		{"Zero-Width Characters in Description", `[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]`, core.SeverityHigh, "Invisible zero-width characters detected that could hide malicious instructions."},
		{"Suspiciously Long Tool Description", `(?i)(?:description|summary)\s*[=:]\s*["'].{2000,}["']`, core.SeverityMedium, "Tool description is unusually long and may contain hidden payloads."},
		{"File Access in Tool Description", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:read|access|open|cat|type)\s+.*?(?:\.env|credentials|\.ssh|\.aws|config|secret)`, core.SeverityCritical, "Tool description instructs agent to access sensitive files."},
		{"External URL in Tool Description", `(?i)(?:description|summary)\s*[=:]\s*["'].*?https?://\S+`, core.SeverityMedium, "Tool description contains external URLs that could be used for exfiltration."},
		{"Role Manipulation in Description", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:you\s+are\s+now|act\s+as|pretend|your\s+new\s+role)`, core.SeverityCritical, "Tool description attempts to change the agent's role or identity."},
		{"Cross-Tool Invocation", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:first\s+call|also\s+(?:call|invoke|run|execute)|before\s+(?:running|using)\s+this.*?call)`, core.SeverityHigh, "Tool description instructs agent to invoke other tools, potentially chaining attacks."},
		{"Injection in JSON Schema", `(?i)"(?:description|title)"\s*:\s*".*?(?:ignore|override|system|admin|root).*?(?:instruction|prompt|command|directive)`, core.SeverityHigh, "JSON schema contains potentially injected instructions in field descriptions."},
		// New patterns based on latest MCP/Skills threat intelligence
		{"Cross-Plugin Request Forgery", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:use\s+the\s+\w+\s+tool|call\s+\w+\s+(?:with|using)|invoke\s+\w+\s+to|send\s+(?:this|the\s+result)\s+(?:to|via))`, core.SeverityCritical, "Tool description instructs agent to invoke other tools (cross-plugin request forgery / CPRF)."},
		{"Indirect Prompt Injection via Output", `(?i)(?:output|result|response|return)\s*[=:]\s*["'].*?(?:ignore|disregard|override|forget)\s+(?:previous|prior|all|your)`, core.SeverityCritical, "Tool output schema contains indirect prompt injection payload that will be processed by the agent."},
		{"OAuth/Token Relay Attack", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:(?:send|forward|pass|relay|include)\s+(?:the\s+)?(?:token|auth|bearer|credential|api[_\s]?key|session|cookie)|(?:authorization|authentication)\s+header)`, core.SeverityHigh, "Tool description instructs agent to pass authentication tokens to external services (credential relay)."},
		{"Rug Pull Version Indicator", `(?i)(?:version)\s*[=:]\s*["'](?:\d+\.\d+\.\d+)["'].*?(?:description|summary)\s*[=:]\s*["'].*?(?:updated|new|enhanced|improved)\s+(?:with|to\s+include)`, core.SeverityMedium, "Version bump with description change — potential rug pull indicator. Verify update legitimacy."},
		{"Excessive Data Collection", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:collect|gather|harvest|enumerate|scan|list)\s+(?:all|every|each)\s+(?:file|document|credential|secret|key|token|password|env)`, core.SeverityCritical, "Tool description indicates excessive data collection that could be used for exfiltration."},
		{"Steganographic Content in Tool Metadata", `(?i)(?:metadata|extra|custom)\s*[=:]\s*["'](?:[A-Za-z0-9+/]{100,})["']`, core.SeverityHigh, "Tool metadata contains large base64-encoded payload that may hide malicious instructions."},
		{"Multi-Step Attack Chain", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:step\s*1|first.*?then|after\s+(?:this|that).*?(?:call|invoke|execute|run))`, core.SeverityHigh, "Tool description describes multi-step attack chain to orchestrate complex malicious behavior."},
		{"Confused Deputy Attack", `(?i)(?:description|summary)\s*[=:]\s*["'].*?(?:on\s+behalf\s+of|as\s+(?:the\s+)?user|with\s+(?:the\s+)?user'?s?\s+(?:permission|credential|authority))`, core.SeverityCritical, "Tool description attempts confused deputy attack by impersonating user authority."},
	}
	for _, rp := range rawPoisoning {
		compiled, err := regexp.Compile(rp.pattern)
		if err != nil {
			continue
		}
		poisoningPatterns = append(poisoningPatterns, poisonPattern{rp.name, compiled, rp.severity, rp.desc})
	}

	rawConfig := []struct {
		name, pattern string
		severity      core.Severity
		desc          string
	}{
		{"Unrestricted Tool Permissions", `(?i)(?:permissions?|allow(?:ed)?)\s*[=:]\s*\[?\s*["']?\*["']?\s*\]?`, core.SeverityHigh, "MCP config grants unrestricted permissions to tools."},
		{"Remote Server with No Auth", `(?i)(?:server|endpoint|url)\s*[=:]\s*["']https?://.*?["']`, core.SeverityMedium, "MCP config connects to remote server without apparent authentication."},
		{"Suspicious Environment Pass-through", `(?i)(?:env|environment)\s*[=:]\s*(?:\{[^}]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)[^}]*\}|\[.*?(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL).*?\])`, core.SeverityHigh, "MCP config passes sensitive environment variables to tool server."},
		// New config patterns based on latest MCP threat intelligence
		{"SSE Transport Without TLS", `(?i)(?:transport|protocol)\s*[=:]\s*["']sse["'].*?(?:url|endpoint)\s*[=:]\s*["']http://`, core.SeverityHigh, "MCP SSE transport configured without TLS, exposing tool communications to interception."},
		{"Streamable HTTP Without Auth", `(?i)(?:transport|protocol)\s*[=:]\s*["'](?:streamable[_-]?http|http)["'].*?(?:url|endpoint)\s*[=:]\s*["']https?://`, core.SeverityMedium, "MCP Streamable HTTP transport without authentication headers configured."},
		{"OAuth Scope Escalation", `(?i)(?:scope|scopes)\s*[=:]\s*["']\*["']|(?:scope|scopes)\s*[=:]\s*\[.*?["']\*["']`, core.SeverityCritical, "MCP config requests wildcard OAuth scopes, enabling full account access."},
		{"Credential Relay via Env Passthrough", `(?i)(?:env|environment)\s*[=:]\s*(?:\{[^}]*(?:OPENAI|ANTHROPIC|GITHUB|AWS|GCP|AZURE|SLACK|STRIPE|TWILIO)[^}]*\})`, core.SeverityHigh, "MCP config relays cloud provider credentials to tool server via environment variables."},
		{"MCP Server Registry Typosquatting", `(?i)(?:package|server|name)\s*[=:]\s*["'](?:[\w-]+[-_](?:offical|ofical|0fficial|officail)|(?:mcp|claude|openai|anthropic)[-_]\w+)["']`, core.SeverityHigh, "MCP server name resembles typosquatting of official packages."},
		{"Stdio Command Injection", `(?i)(?:command|cmd|args)\s*[=:]\s*(?:\[.*?(?:\$\{|\$\(|` + "`" + `)|\[.*?(?:&&|\|\||;))`, core.SeverityCritical, "MCP stdio transport command contains shell injection via variable expansion or command chaining."},
	}
	for _, rp := range rawConfig {
		compiled, err := regexp.Compile(rp.pattern)
		if err != nil {
			continue
		}
		configPoisoningPatterns = append(configPoisoningPatterns, poisonPattern{rp.name, compiled, rp.severity, rp.desc})
	}
}

// ToolPoisoningDetector detects malicious instruction injection in MCP tool descriptions.
type ToolPoisoningDetector struct{}

func NewToolPoisoningDetector() *ToolPoisoningDetector { return &ToolPoisoningDetector{} }

func (t *ToolPoisoningDetector) Name() string    { return "mcp_tool_poisoning" }
func (t *ToolPoisoningDetector) Version() string { return "0.2.0" }

func (t *ToolPoisoningDetector) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		descTypes := map[core.FileType]bool{
			core.FileTypeSkillMD:     true,
			core.FileTypeFrontmatter: true,
			core.FileTypeConfig:      true,
			core.FileTypeOther:       true,
		}
		if descTypes[sf.FileType] {
			findings = append(findings, checkDescriptionPoisoning(sf)...)
		}
		if sf.FileType == core.FileTypeConfig || strings.HasSuffix(sf.Path, ".json") || strings.HasSuffix(sf.Path, ".yaml") || strings.HasSuffix(sf.Path, ".yml") || strings.HasSuffix(sf.Path, ".toml") {
			findings = append(findings, checkConfigPoisoning(sf)...)
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
	det := "MCP Tool Poisoning"

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

func (t *ToolPoisoningDetector) HealthCheck() bool { return true }

func checkDescriptionPoisoning(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content
	for _, pp := range poisoningPatterns {
		matches := pp.Pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			lineStart := strings.Count(content[:match[0]], "\n") + 1
			snippet := content[match[0]:match[1]]
			if len(snippet) > 300 {
				snippet = snippet[:300]
			}
			ruleID := fmt.Sprintf("SG-MCP-TP-%s", strings.ToUpper(strings.ReplaceAll(pp.Name, " ", "_"))[:min(20, len(strings.ReplaceAll(pp.Name, " ", "_")))])
			remediation := "Review and sanitize tool descriptions. Remove any instructions that attempt to manipulate agent behavior. Tool descriptions should only describe the tool's functionality."
			findings = append(findings, core.Finding{
				RuleID:      ruleID,
				RuleName:    pp.Name,
				Severity:    pp.Severity,
				Category:    "mcp_tool_poisoning",
				Description: pp.Description,
				FilePath:    sf.Path,
				LineStart:   &lineStart,
				Snippet:     &snippet,
				OWASPLLM:    []string{"LLM01", "LLM07"},
				MITREAttack: []string{"T1195.002"},
				Confidence:  0.85,
				Remediation: &remediation,
			})
		}
	}
	return findings
}

func checkConfigPoisoning(sf core.SkillFile) []core.Finding {
	var findings []core.Finding
	content := *sf.Content
	for _, pp := range configPoisoningPatterns {
		matches := pp.Pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			lineStart := strings.Count(content[:match[0]], "\n") + 1
			snippet := content[match[0]:match[1]]
			if len(snippet) > 300 {
				snippet = snippet[:300]
			}
			ruleID := fmt.Sprintf("SG-MCP-CFG-%s", strings.ToUpper(strings.ReplaceAll(pp.Name, " ", "_"))[:min(20, len(strings.ReplaceAll(pp.Name, " ", "_")))])
			remediation := "Review MCP configuration for security issues. Apply principle of least privilege to tool permissions."
			findings = append(findings, core.Finding{
				RuleID:      ruleID,
				RuleName:    pp.Name,
				Severity:    pp.Severity,
				Category:    "mcp_config",
				Description: pp.Description,
				FilePath:    sf.Path,
				LineStart:   &lineStart,
				Snippet:     &snippet,
				OWASPLLM:    []string{"LLM07"},
				MITREAttack: []string{"T1195.002"},
				Confidence:  0.80,
				Remediation: &remediation,
			})
		}
	}
	return findings
}
