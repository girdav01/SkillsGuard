// Package governance provides policy engine, RBAC, and audit logging.
package governance

import (
	"fmt"
	"strings"
	"sync"

	"github.com/girdav01/skillguard/internal/core"
)

// PolicyAction is the action taken when a policy matches.
type PolicyAction string

const (
	PolicyActionBlock PolicyAction = "block"
	PolicyActionWarn  PolicyAction = "warn"
	PolicyActionAudit PolicyAction = "audit"
)

// Policy defines a governance policy.
type Policy struct {
	ID          string       `json:"id" yaml:"id"`
	Name        string       `json:"name" yaml:"name"`
	Description string       `json:"description" yaml:"description"`
	Conditions  []Condition  `json:"conditions" yaml:"conditions"`
	Action      PolicyAction `json:"action" yaml:"action"`
	Enabled     bool         `json:"enabled" yaml:"enabled"`
}

// Condition is a single policy condition.
type Condition struct {
	Field    string `json:"field" yaml:"field"`
	Operator string `json:"operator" yaml:"operator"`
	Value    any    `json:"value" yaml:"value"`
}

// PolicyResult is the result of policy evaluation.
type PolicyResult struct {
	PolicyID string       `json:"policy_id"`
	Name     string       `json:"name"`
	Action   PolicyAction `json:"action"`
	Matched  bool         `json:"matched"`
	Message  string       `json:"message"`
}

// PolicyEngine manages and evaluates governance policies.
type PolicyEngine struct {
	mu       sync.RWMutex
	policies []Policy
}

// NewPolicyEngine creates a new PolicyEngine with default policies.
func NewPolicyEngine() *PolicyEngine {
	pe := &PolicyEngine{}
	pe.loadDefaults()
	return pe
}

func (pe *PolicyEngine) loadDefaults() {
	pe.policies = []Policy{
		{ID: "default-001", Name: "Block Malicious", Description: "Block skills with malicious verdict", Conditions: []Condition{{Field: "verdict", Operator: "eq", Value: "malicious"}}, Action: PolicyActionBlock, Enabled: true},
		{ID: "default-002", Name: "Block High Risk", Description: "Block skills with high risk verdict", Conditions: []Condition{{Field: "verdict", Operator: "eq", Value: "high_risk"}}, Action: PolicyActionBlock, Enabled: true},
		{ID: "default-003", Name: "Warn Suspicious", Description: "Warn on suspicious skills", Conditions: []Condition{{Field: "verdict", Operator: "eq", Value: "suspicious"}}, Action: PolicyActionWarn, Enabled: true},
		{ID: "default-004", Name: "Block Critical Findings", Description: "Block skills with critical findings", Conditions: []Condition{{Field: "critical_count", Operator: "gt", Value: 0}}, Action: PolicyActionBlock, Enabled: true},
		{ID: "default-005", Name: "Warn High Score", Description: "Warn on score above 50", Conditions: []Condition{{Field: "score", Operator: "gt", Value: 50}}, Action: PolicyActionWarn, Enabled: true},
		{ID: "default-006", Name: "Audit All Scans", Description: "Audit log all scan results", Conditions: []Condition{{Field: "score", Operator: "gte", Value: 0}}, Action: PolicyActionAudit, Enabled: true},
	}
}

// ListPolicies returns all policies.
func (pe *PolicyEngine) ListPolicies() []Policy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	result := make([]Policy, len(pe.policies))
	copy(result, pe.policies)
	return result
}

// AddPolicy adds a new policy.
func (pe *PolicyEngine) AddPolicy(p Policy) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.policies = append(pe.policies, p)
}

// RemovePolicy removes a policy by ID.
func (pe *PolicyEngine) RemovePolicy(id string) bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for i, p := range pe.policies {
		if p.ID == id {
			pe.policies = append(pe.policies[:i], pe.policies[i+1:]...)
			return true
		}
	}
	return false
}

// Evaluate evaluates all policies against a scan result.
func (pe *PolicyEngine) Evaluate(result *core.ScanResult) []PolicyResult {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	var results []PolicyResult
	for _, policy := range pe.policies {
		if !policy.Enabled {
			continue
		}
		matched := pe.evaluateConditions(policy.Conditions, result)
		msg := ""
		if matched {
			msg = fmt.Sprintf("Policy '%s' triggered: %s", policy.Name, policy.Description)
		}
		results = append(results, PolicyResult{
			PolicyID: policy.ID,
			Name:     policy.Name,
			Action:   policy.Action,
			Matched:  matched,
			Message:  msg,
		})
	}
	return results
}

func (pe *PolicyEngine) evaluateConditions(conditions []Condition, result *core.ScanResult) bool {
	for _, cond := range conditions {
		if !pe.evaluateCondition(cond, result) {
			return false
		}
	}
	return true
}

func (pe *PolicyEngine) evaluateCondition(cond Condition, result *core.ScanResult) bool {
	switch cond.Field {
	case "verdict":
		actual := string(result.Verdict)
		expected, _ := cond.Value.(string)
		return compareString(actual, cond.Operator, expected)
	case "score":
		return compareInt(result.CompositeScore, cond.Operator, toInt(cond.Value))
	case "critical_count":
		count := result.FindingsBySeverity["critical"]
		return compareInt(count, cond.Operator, toInt(cond.Value))
	case "high_count":
		count := result.FindingsBySeverity["high"]
		return compareInt(count, cond.Operator, toInt(cond.Value))
	case "total_findings":
		return compareInt(result.TotalFindings, cond.Operator, toInt(cond.Value))
	}
	return false
}

func compareString(actual, op, expected string) bool {
	switch op {
	case "eq":
		return strings.EqualFold(actual, expected)
	case "neq":
		return !strings.EqualFold(actual, expected)
	case "contains":
		return strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
	}
	return false
}

func compareInt(actual int, op string, expected int) bool {
	switch op {
	case "eq":
		return actual == expected
	case "neq":
		return actual != expected
	case "gt":
		return actual > expected
	case "gte":
		return actual >= expected
	case "lt":
		return actual < expected
	case "lte":
		return actual <= expected
	}
	return false
}

func toInt(v any) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	case string:
		n := 0
		fmt.Sscanf(val, "%d", &n)
		return n
	}
	return 0
}
