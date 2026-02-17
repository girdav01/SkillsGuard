package core

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// HashContent computes the SHA256 hash of a string.
func HashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

// HashFile computes the SHA256 hash of a file by reading in chunks.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// HashSkill computes a composite hash for an entire skill package.
// Takes a slice of (relativePath, fileSHA256) pairs.
func HashSkill(files []FileHash) string {
	parts := make([]string, len(files))
	for i, f := range files {
		parts[i] = f.Path + ":" + f.SHA256
	}
	sort.Strings(parts)
	combined := strings.Join(parts, "\n")
	h := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", h)
}

// FileHash is a path:hash pair for composite hashing.
type FileHash struct {
	Path   string
	SHA256 string
}
