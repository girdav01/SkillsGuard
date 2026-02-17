// Package intelligence provides threat intelligence, community verdicts, and MITRE mapping.
package intelligence

import "sync"

// ThreatIntelDB is an in-memory threat intelligence database.
type ThreatIntelDB struct {
	mu     sync.RWMutex
	hashes map[string]ThreatEntry
}

// ThreatEntry represents a known malicious hash entry.
type ThreatEntry struct {
	SHA256   string `json:"sha256"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Source   string `json:"source"`
}

// NewThreatIntelDB creates a new ThreatIntelDB.
func NewThreatIntelDB() *ThreatIntelDB {
	return &ThreatIntelDB{
		hashes: make(map[string]ThreatEntry),
	}
}

// IsMaliciousHash checks if a hash is in the threat database.
func (t *ThreatIntelDB) IsMaliciousHash(sha256 string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.hashes[sha256]
	return ok
}

// AddHash adds a malicious hash to the database.
func (t *ThreatIntelDB) AddHash(entry ThreatEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hashes[entry.SHA256] = entry
}

// Lookup retrieves a threat entry by hash.
func (t *ThreatIntelDB) Lookup(sha256 string) (*ThreatEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	entry, ok := t.hashes[sha256]
	if !ok {
		return nil, false
	}
	return &entry, true
}

// Count returns the number of entries in the database.
func (t *ThreatIntelDB) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.hashes)
}
