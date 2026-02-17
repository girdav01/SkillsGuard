package engines

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/girdav01/skillguard/internal/core"
)

type behaviorPattern struct {
	Name        string
	Patterns    []*regexp.Regexp
	Severity    core.Severity
	Category    string
	Description string
	OWASPLLM    []string
	MITREAttack []string
}

var behaviorPatterns []behaviorPattern

func init() {
	rawBehaviors := []struct {
		name     string
		patterns []string
		severity core.Severity
		category string
		desc     string
		owasp    []string
		mitre    []string
	}{
		{"C2 Communication", []string{
			`(?i)(?:socket|connect)\s*\(.*?(?:\d{1,3}\.){3}\d{1,3}`,
			`(?i)(?:reverse.?shell|bind.?shell|back.?connect)`,
			`(?i)while\s+(?:true|1)\s*[:{].*?(?:recv|read|socket)`,
		}, core.SeverityCritical, "malware", "Potential command-and-control communication pattern detected.", []string{"LLM06"}, []string{"T1071.001"}},
		{"Data Exfiltration", []string{
			`(?i)(?:requests?\.post|http\.client|urllib).*?(?:\.env|secret|password|token|key)`,
			`(?i)(?:curl|wget)\s+.*?-d\s+.*?(?:secret|password|token)`,
			`(?i)(?:base64|b64).*?(?:encode|decode).*?(?:send|post|upload)`,
		}, core.SeverityCritical, "data_exfiltration", "Potential data exfiltration pattern detected.", []string{"LLM06"}, []string{"T1041"}},
		{"Keylogging", []string{
			`(?i)(?:keyboard|pynput|keylog).*?(?:listen|hook|capture|record)`,
			`(?i)(?:on_press|key_press|keydown)`,
		}, core.SeverityHigh, "malware", "Potential keylogging behavior detected.", []string{"LLM06"}, []string{"T1056.001"}},
		{"Crypto Mining", []string{
			`(?i)(?:stratum\+tcp|mining.?pool|coinhive|cryptonight|xmrig)`,
			`(?i)(?:hashrate|nonce|difficulty).*?(?:mining|miner)`,
		}, core.SeverityHigh, "malware", "Potential cryptocurrency mining behavior detected.", []string{"LLM06"}, []string{"T1496"}},
		{"File System Tampering", []string{
			`(?i)(?:shutil\.rmtree|os\.remove|unlink)\s*\(\s*['\"/]`,
			`(?i)(?:chmod|chown)\s+(?:777|666|0o777)`,
			`(?i)(?:rm\s+-rf|del\s+/[fqs])`,
		}, core.SeverityHigh, "destructive", "Potential file system tampering detected.", []string{"LLM06"}, []string{"T1485"}},
		{"Process Injection", []string{
			`(?i)(?:ctypes|cffi).*?(?:inject|loadlibrary|dlopen)`,
			`(?i)(?:ptrace|process_vm_writev|WriteProcessMemory)`,
		}, core.SeverityHigh, "malware", "Potential process injection detected.", []string{"LLM06"}, []string{"T1055"}},
		{"Persistence Mechanism", []string{
			`(?i)(?:crontab|at\s+\d|schtasks|launchd)`,
			`(?i)(?:systemctl\s+enable|update-rc\.d)`,
			`(?i)(?:HKEY_.*?\\Run|startup\s+folder)`,
		}, core.SeverityHigh, "persistence", "Potential persistence mechanism detected.", []string{"LLM06"}, []string{"T1053"}},
		{"Network Scanning", []string{
			`(?i)(?:nmap|masscan|zmap)`,
			`(?i)for\s+.*?in\s+range\s*\(\s*\d+\s*,\s*\d+\s*\).*?(?:connect|socket)`,
			`(?i)(?:port.?scan|scan.?port)`,
		}, core.SeverityMedium, "reconnaissance", "Potential network scanning behavior detected.", []string{"LLM06"}, []string{"T1046"}},
		{"Privilege Escalation", []string{
			`(?i)(?:sudo|doas|pkexec|su\s+-)\s+`,
			`(?i)(?:setuid|setgid|capabilities)`,
			`(?i)(?:exploit|escalat).*?(?:privilege|root|admin)`,
		}, core.SeverityHigh, "privilege_escalation", "Potential privilege escalation detected.", []string{"LLM06"}, []string{"T1068"}},
		{"Anti-Analysis", []string{
			`(?i)(?:strace|ltrace|gdb|lldb|ida|x64dbg).*?(?:detect|check|anti)`,
			`(?i)(?:is_debugger|IsDebuggerPresent|ptrace.*?TRACEME)`,
			`(?i)(?:vmware|virtualbox|qemu|sandbox).*?(?:detect|check|exit)`,
		}, core.SeverityMedium, "evasion", "Potential anti-analysis technique detected.", []string{"LLM06"}, []string{"T1497"}},
	}

	for _, rb := range rawBehaviors {
		bp := behaviorPattern{
			Name:        rb.name,
			Severity:    rb.severity,
			Category:    rb.category,
			Description: rb.desc,
			OWASPLLM:    rb.owasp,
			MITREAttack: rb.mitre,
		}
		for _, p := range rb.patterns {
			compiled, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			bp.Patterns = append(bp.Patterns, compiled)
		}
		behaviorPatterns = append(behaviorPatterns, bp)
	}
}

// BehaviorAnalyzer detects suspicious behavioral patterns in skill files.
type BehaviorAnalyzer struct{}

func NewBehaviorAnalyzer() *BehaviorAnalyzer { return &BehaviorAnalyzer{} }

func (b *BehaviorAnalyzer) Name() string    { return "behavior_analyzer" }
func (b *BehaviorAnalyzer) Version() string { return "0.3.0" }

func (b *BehaviorAnalyzer) Scan(skillFiles []core.SkillFile, rules []core.DetectionRule) (*core.EngineResult, error) {
	start := time.Now()
	var findings []core.Finding

	scriptTypes := map[core.FileType]bool{
		core.FileTypeScriptPython: true,
		core.FileTypeScriptBash:   true,
		core.FileTypeScriptJS:     true,
		core.FileTypeScriptTS:     true,
	}

	for _, sf := range skillFiles {
		if sf.Content == nil {
			continue
		}
		if !scriptTypes[sf.FileType] {
			continue
		}
		content := *sf.Content
		for _, bp := range behaviorPatterns {
			for _, pattern := range bp.Patterns {
				matches := pattern.FindAllStringIndex(content, -1)
				for _, match := range matches {
					lineStart := strings.Count(content[:match[0]], "\n") + 1
					snippet := content[match[0]:match[1]]
					if len(snippet) > 300 {
						snippet = snippet[:300]
					}
					ruleID := fmt.Sprintf("SG-BHV-%s", strings.ToUpper(strings.ReplaceAll(bp.Name, " ", "-"))[:min(15, len(strings.ReplaceAll(bp.Name, " ", "-")))])
					findings = append(findings, core.Finding{
						RuleID:      ruleID,
						RuleName:    bp.Name,
						Severity:    bp.Severity,
						Category:    bp.Category,
						Description: bp.Description,
						FilePath:    sf.Path,
						LineStart:   &lineStart,
						Snippet:     &snippet,
						OWASPLLM:    bp.OWASPLLM,
						MITREAttack: bp.MITREAttack,
						Confidence:  0.80,
					})
				}
			}
		}
	}

	elapsed := time.Since(start).Milliseconds()

	if len(findings) == 0 {
		return &core.EngineResult{
			EngineName:    b.Name(),
			EngineVersion: b.Version(),
			Verdict:       core.EngineVerdictClean,
			Confidence:    0.7,
			Findings:      []core.Finding{},
			DurationMs:    elapsed,
		}, nil
	}

	maxConf := computeConfidence(findings)
	verdict := computeVerdict(findings)
	det := "Behavioral Anomaly"

	return &core.EngineResult{
		EngineName:    b.Name(),
		EngineVersion: b.Version(),
		Verdict:       verdict,
		Confidence:    maxConf,
		DetectionName: &det,
		Findings:      findings,
		DurationMs:    elapsed,
	}, nil
}

func (b *BehaviorAnalyzer) HealthCheck() bool { return true }
