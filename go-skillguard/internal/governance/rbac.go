package governance

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// Role defines RBAC roles.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleAnalyst   Role = "analyst"
	RoleDeveloper Role = "developer"
	RoleViewer    Role = "viewer"
)

// RolePermissions maps roles to their allowed actions.
var RolePermissions = map[Role]map[string]bool{
	RoleAdmin: {
		"scan": true, "rules:read": true, "rules:write": true,
		"policy:read": true, "policy:write": true,
		"audit:read": true, "audit:export": true,
		"community:read": true, "community:write": true,
		"monitor": true, "server": true, "bom": true,
	},
	RoleAnalyst: {
		"scan": true, "rules:read": true,
		"policy:read": true,
		"audit:read": true, "audit:export": true,
		"community:read": true, "community:write": true,
		"monitor": true, "bom": true,
	},
	RoleDeveloper: {
		"scan": true, "rules:read": true,
		"policy:read": true,
		"community:read": true,
		"bom": true,
	},
	RoleViewer: {
		"scan": true, "rules:read": true,
		"policy:read": true,
		"community:read": true,
	},
}

// APIKey represents an API key with an associated role.
type APIKey struct {
	Key  string `json:"key"`
	Role Role   `json:"role"`
	Name string `json:"name"`
}

// RBACManager manages role-based access control.
type RBACManager struct {
	mu   sync.RWMutex
	keys map[string]APIKey // key -> APIKey
}

// NewRBACManager creates a new RBACManager.
func NewRBACManager() *RBACManager {
	return &RBACManager{
		keys: make(map[string]APIKey),
	}
}

// GenerateKey creates a new API key with the given role and name.
func (r *RBACManager) GenerateKey(role Role, name string) APIKey {
	r.mu.Lock()
	defer r.mu.Unlock()

	b := make([]byte, 24)
	rand.Read(b)
	key := "sg_" + hex.EncodeToString(b)

	apiKey := APIKey{Key: key, Role: role, Name: name}
	r.keys[key] = apiKey
	return apiKey
}

// ValidateKey checks if an API key is valid and returns the associated role.
func (r *RBACManager) ValidateKey(key string) (Role, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ak, ok := r.keys[key]
	if !ok {
		return "", false
	}
	return ak.Role, true
}

// HasPermission checks if a role has the given permission.
func HasPermission(role Role, permission string) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	return perms[permission]
}

// Authorize checks if an API key has the given permission.
func (r *RBACManager) Authorize(key, permission string) bool {
	role, valid := r.ValidateKey(key)
	if !valid {
		return false
	}
	return HasPermission(role, permission)
}
