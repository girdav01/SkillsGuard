package governance

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Action       string    `json:"action"`
	Actor        string    `json:"actor"`
	Details      any       `json:"details"`
	PreviousHash string    `json:"previous_hash"`
	EntryHash    string    `json:"entry_hash"`
}

// AuditLog maintains an integrity-chained audit log.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
}

// NewAuditLog creates a new AuditLog.
func NewAuditLog() *AuditLog {
	return &AuditLog{}
}

// Log adds a new entry to the audit log.
func (a *AuditLog) Log(action, actor string, details any) {
	a.mu.Lock()
	defer a.mu.Unlock()

	prevHash := ""
	if len(a.entries) > 0 {
		prevHash = a.entries[len(a.entries)-1].EntryHash
	}

	entry := AuditEntry{
		Timestamp:    time.Now().UTC(),
		Action:       action,
		Actor:        actor,
		Details:      details,
		PreviousHash: prevHash,
	}

	// Compute entry hash for integrity chain
	data, _ := json.Marshal(map[string]any{
		"timestamp":     entry.Timestamp.Format(time.RFC3339Nano),
		"action":        entry.Action,
		"actor":         entry.Actor,
		"details":       entry.Details,
		"previous_hash": entry.PreviousHash,
	})
	h := sha256.Sum256(data)
	entry.EntryHash = fmt.Sprintf("%x", h)

	a.entries = append(a.entries, entry)
}

// Entries returns all audit entries.
func (a *AuditLog) Entries() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]AuditEntry, len(a.entries))
	copy(result, a.entries)
	return result
}

// VerifyIntegrity checks the integrity chain of the audit log.
func (a *AuditLog) VerifyIntegrity() (bool, int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, entry := range a.entries {
		// Check previous hash link
		if i == 0 {
			if entry.PreviousHash != "" {
				return false, i
			}
		} else {
			if entry.PreviousHash != a.entries[i-1].EntryHash {
				return false, i
			}
		}

		// Recompute hash
		data, _ := json.Marshal(map[string]any{
			"timestamp":     entry.Timestamp.Format(time.RFC3339Nano),
			"action":        entry.Action,
			"actor":         entry.Actor,
			"details":       entry.Details,
			"previous_hash": entry.PreviousHash,
		})
		h := sha256.Sum256(data)
		expected := fmt.Sprintf("%x", h)
		if entry.EntryHash != expected {
			return false, i
		}
	}
	return true, -1
}

// Query returns entries matching action and/or actor filters.
func (a *AuditLog) Query(action, actor string, limit int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	var results []AuditEntry
	for _, entry := range a.entries {
		if action != "" && entry.Action != action {
			continue
		}
		if actor != "" && entry.Actor != actor {
			continue
		}
		results = append(results, entry)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	return results
}

// Export exports the audit log as JSON.
func (a *AuditLog) Export() ([]byte, error) {
	entries := a.Entries()
	return json.MarshalIndent(map[string]any{
		"entries": entries,
		"total":   len(entries),
	}, "", "  ")
}
