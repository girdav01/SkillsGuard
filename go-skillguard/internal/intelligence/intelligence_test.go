package intelligence

import "testing"

func TestThreatIntelDB(t *testing.T) {
	db := NewThreatIntelDB()

	if db.IsMaliciousHash("abc123") {
		t.Error("Should not find unknown hash")
	}

	db.AddHash(ThreatEntry{
		SHA256:   "abc123",
		Name:     "test malware",
		Category: "malware",
		Source:   "test",
	})

	if !db.IsMaliciousHash("abc123") {
		t.Error("Should find added hash")
	}

	entry, ok := db.Lookup("abc123")
	if !ok {
		t.Error("Lookup should succeed")
	}
	if entry.Name != "test malware" {
		t.Errorf("Name = %q, want 'test malware'", entry.Name)
	}

	if db.Count() != 1 {
		t.Errorf("Count = %d, want 1", db.Count())
	}
}

func TestCommunityVerdicts(t *testing.T) {
	cv := NewCommunityVerdicts()

	// Empty reputation
	rep := cv.GetReputation("sha256test")
	if rep.TotalVotes != 0 {
		t.Error("Should have 0 votes initially")
	}
	if rep.ConsensusVerdict != "unknown" {
		t.Errorf("Consensus = %q, want 'unknown'", rep.ConsensusVerdict)
	}

	// Add verdicts
	cv.AddVerdict("sha256test", "malicious", "analyst1")
	cv.AddVerdict("sha256test", "malicious", "analyst2")
	cv.AddVerdict("sha256test", "clean", "analyst3")

	rep = cv.GetReputation("sha256test")
	if rep.TotalVotes != 3 {
		t.Errorf("TotalVotes = %d, want 3", rep.TotalVotes)
	}
	if rep.ConsensusVerdict != "malicious" {
		t.Errorf("Consensus = %q, want 'malicious'", rep.ConsensusVerdict)
	}

	// Add comment
	cv.AddComment("sha256test", "analyst1", "Very suspicious patterns")
	rep = cv.GetReputation("sha256test")
	if len(rep.Comments) != 1 {
		t.Errorf("Comments = %d, want 1", len(rep.Comments))
	}
}

func TestMITREMapper(t *testing.T) {
	mapper := NewMITREMapper()

	mapping, ok := mapper.Lookup("T1059")
	if !ok {
		t.Error("Should find T1059")
	}
	if mapping.Name != "Command and Scripting Interpreter" {
		t.Errorf("Name = %q", mapping.Name)
	}

	_, ok = mapper.Lookup("T9999")
	if ok {
		t.Error("Should not find T9999")
	}

	results := mapper.LookupMultiple([]string{"T1059", "T1041", "T9999"})
	if len(results) != 2 {
		t.Errorf("LookupMultiple = %d, want 2", len(results))
	}
}
