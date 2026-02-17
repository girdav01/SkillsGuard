package intelligence

// MITREMapping maps technique IDs to attack pattern descriptions.
type MITREMapping struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Description string `json:"description"`
}

// DefaultMITREMappings contains the default MITRE ATT&CK mappings used by SkillGuard.
var DefaultMITREMappings = []MITREMapping{
	{"T1059", "Command and Scripting Interpreter", "Execution", "Adversaries may abuse command and script interpreters to execute commands."},
	{"T1059.006", "Python", "Execution", "Adversaries may use Python scripts to execute malicious code."},
	{"T1071.001", "Web Protocols", "Command and Control", "Adversaries may communicate using HTTP/HTTPS protocols."},
	{"T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Adversaries may steal data by exfiltrating it over C2 channel."},
	{"T1046", "Network Service Discovery", "Discovery", "Adversaries may attempt to get a listing of services on remote hosts."},
	{"T1055", "Process Injection", "Defense Evasion", "Adversaries may inject code into processes to evade defenses."},
	{"T1056.001", "Keylogging", "Collection", "Adversaries may log user keystrokes to intercept credentials."},
	{"T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "Adversaries may exploit vulnerabilities to escalate privileges."},
	{"T1195.002", "Compromise Software Supply Chain", "Initial Access", "Adversaries may manipulate tools in the software supply chain."},
	{"T1485", "Data Destruction", "Impact", "Adversaries may destroy data and files on specific systems."},
	{"T1496", "Resource Hijacking", "Impact", "Adversaries may leverage compute resources for cryptocurrency mining."},
	{"T1497", "Virtualization/Sandbox Evasion", "Defense Evasion", "Adversaries may check for virtual environments to avoid analysis."},
	{"T1552.001", "Credentials In Files", "Credential Access", "Adversaries may search local file systems for files containing credentials."},
	{"T1557", "Adversary-in-the-Middle", "Credential Access", "Adversaries may attempt to intercept network communications."},
}

// MITREMapper provides lookup for MITRE ATT&CK techniques.
type MITREMapper struct {
	techniques map[string]MITREMapping
}

// NewMITREMapper creates a new MITREMapper.
func NewMITREMapper() *MITREMapper {
	m := &MITREMapper{
		techniques: make(map[string]MITREMapping),
	}
	for _, mapping := range DefaultMITREMappings {
		m.techniques[mapping.TechniqueID] = mapping
	}
	return m
}

// Lookup returns the MITRE mapping for a technique ID.
func (m *MITREMapper) Lookup(techniqueID string) (*MITREMapping, bool) {
	mapping, ok := m.techniques[techniqueID]
	if !ok {
		return nil, false
	}
	return &mapping, true
}

// LookupMultiple returns mappings for multiple technique IDs.
func (m *MITREMapper) LookupMultiple(ids []string) []MITREMapping {
	var results []MITREMapping
	for _, id := range ids {
		if mapping, ok := m.techniques[id]; ok {
			results = append(results, mapping)
		}
	}
	return results
}
