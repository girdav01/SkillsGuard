package governance

import (
	"testing"

	"github.com/girdav01/skillguard/internal/core"
)

func TestPolicyEngineDefaults(t *testing.T) {
	pe := NewPolicyEngine()
	policies := pe.ListPolicies()
	if len(policies) != 6 {
		t.Errorf("Default policies = %d, want 6", len(policies))
	}
}

func TestPolicyEngineAddRemove(t *testing.T) {
	pe := NewPolicyEngine()
	initial := len(pe.ListPolicies())

	pe.AddPolicy(Policy{
		ID:      "custom-001",
		Name:    "Custom Policy",
		Action:  PolicyActionWarn,
		Enabled: true,
	})

	if len(pe.ListPolicies()) != initial+1 {
		t.Error("Policy should have been added")
	}

	if !pe.RemovePolicy("custom-001") {
		t.Error("Should have removed policy")
	}

	if len(pe.ListPolicies()) != initial {
		t.Error("Policy count should return to initial")
	}

	if pe.RemovePolicy("nonexistent") {
		t.Error("Should not remove nonexistent policy")
	}
}

func TestPolicyEngineEvaluate(t *testing.T) {
	pe := NewPolicyEngine()
	result := &core.ScanResult{
		Verdict:            core.VerdictMalicious,
		CompositeScore:     95,
		TotalFindings:      5,
		FindingsBySeverity: map[string]int{"critical": 2, "high": 3},
	}

	results := pe.Evaluate(result)
	if len(results) == 0 {
		t.Error("Expected policy results")
	}

	// Check that "Block Malicious" policy matched
	matched := false
	for _, r := range results {
		if r.Name == "Block Malicious" && r.Matched {
			matched = true
			if r.Action != PolicyActionBlock {
				t.Error("Action should be block")
			}
		}
	}
	if !matched {
		t.Error("Block Malicious policy should have matched")
	}
}

func TestPolicyEngineCleanResult(t *testing.T) {
	pe := NewPolicyEngine()
	result := &core.ScanResult{
		Verdict:            core.VerdictClean,
		CompositeScore:     0,
		FindingsBySeverity: map[string]int{},
	}

	results := pe.Evaluate(result)
	for _, r := range results {
		if r.Action == PolicyActionBlock && r.Matched {
			t.Errorf("No block policies should match for clean result: %s", r.Name)
		}
	}
}

func TestRBACManager(t *testing.T) {
	rbac := NewRBACManager()

	// Generate key
	key := rbac.GenerateKey(RoleAdmin, "test-admin")
	if key.Key == "" {
		t.Error("Key should not be empty")
	}
	if key.Role != RoleAdmin {
		t.Error("Role should be admin")
	}

	// Validate key
	role, valid := rbac.ValidateKey(key.Key)
	if !valid {
		t.Error("Key should be valid")
	}
	if role != RoleAdmin {
		t.Error("Role should be admin")
	}

	// Invalid key
	_, valid = rbac.ValidateKey("invalid-key")
	if valid {
		t.Error("Invalid key should not validate")
	}
}

func TestRBACPermissions(t *testing.T) {
	// Admin has all permissions
	if !HasPermission(RoleAdmin, "scan") {
		t.Error("Admin should have scan permission")
	}
	if !HasPermission(RoleAdmin, "rules:write") {
		t.Error("Admin should have rules:write")
	}

	// Viewer has limited permissions
	if !HasPermission(RoleViewer, "scan") {
		t.Error("Viewer should have scan")
	}
	if HasPermission(RoleViewer, "rules:write") {
		t.Error("Viewer should not have rules:write")
	}
	if HasPermission(RoleViewer, "monitor") {
		t.Error("Viewer should not have monitor")
	}

	// Developer
	if !HasPermission(RoleDeveloper, "bom") {
		t.Error("Developer should have bom")
	}
	if HasPermission(RoleDeveloper, "policy:write") {
		t.Error("Developer should not have policy:write")
	}
}

func TestRBACAuthorize(t *testing.T) {
	rbac := NewRBACManager()
	key := rbac.GenerateKey(RoleViewer, "viewer")

	if !rbac.Authorize(key.Key, "scan") {
		t.Error("Viewer should be authorized for scan")
	}
	if rbac.Authorize(key.Key, "rules:write") {
		t.Error("Viewer should not be authorized for rules:write")
	}
	if rbac.Authorize("bad-key", "scan") {
		t.Error("Bad key should not authorize")
	}
}

func TestAuditLog(t *testing.T) {
	al := NewAuditLog()

	al.Log("scan", "user1", map[string]string{"skill": "test"})
	al.Log("scan", "user2", map[string]string{"skill": "test2"})
	al.Log("policy_add", "admin", map[string]string{"policy": "p1"})

	entries := al.Entries()
	if len(entries) != 3 {
		t.Errorf("Entries = %d, want 3", len(entries))
	}

	// Check integrity chain
	if entries[0].PreviousHash != "" {
		t.Error("First entry should have empty previous hash")
	}
	if entries[1].PreviousHash != entries[0].EntryHash {
		t.Error("Second entry should link to first")
	}
	if entries[2].PreviousHash != entries[1].EntryHash {
		t.Error("Third entry should link to second")
	}
}

func TestAuditLogVerifyIntegrity(t *testing.T) {
	al := NewAuditLog()
	al.Log("test1", "user", nil)
	al.Log("test2", "user", nil)

	valid, _ := al.VerifyIntegrity()
	if !valid {
		t.Error("Audit log should be valid")
	}
}

func TestAuditLogQuery(t *testing.T) {
	al := NewAuditLog()
	al.Log("scan", "user1", nil)
	al.Log("scan", "user2", nil)
	al.Log("policy", "admin", nil)

	// Query by action
	results := al.Query("scan", "", 0)
	if len(results) != 2 {
		t.Errorf("Query(scan) = %d, want 2", len(results))
	}

	// Query by actor
	results = al.Query("", "admin", 0)
	if len(results) != 1 {
		t.Errorf("Query(admin) = %d, want 1", len(results))
	}

	// Query with limit
	results = al.Query("", "", 1)
	if len(results) != 1 {
		t.Errorf("Query(limit=1) = %d, want 1", len(results))
	}
}

func TestAuditLogExport(t *testing.T) {
	al := NewAuditLog()
	al.Log("test", "user", nil)

	data, err := al.Export()
	if err != nil {
		t.Fatalf("Export error: %v", err)
	}
	if len(data) == 0 {
		t.Error("Export should produce data")
	}
}
