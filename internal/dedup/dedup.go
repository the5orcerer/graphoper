// Package dedup provides SHA256-based deduplication for GraphQL operations.
package dedup

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Deduplicator tracks seen operation hashes in memory for fast lookups
// before hitting the database.
type Deduplicator struct {
	seen map[string]struct{}
	mu   sync.RWMutex
}

// New creates a new Deduplicator.
func New() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]struct{}),
	}
}

// whitespace normalizer
var wsRe = regexp.MustCompile(`\s+`)

// NormalizeQuery strips insignificant whitespace and lowercases the query
// to produce a canonical form for hashing.
func NormalizeQuery(query string) string {
	q := strings.TrimSpace(query)
	q = wsRe.ReplaceAllString(q, " ")
	return q
}

// Hash returns the SHA256 hex digest of a normalized GraphQL query.
func Hash(query string) string {
	normalized := NormalizeQuery(query)
	h := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", h)
}

// IsSeen returns true if this hash has already been recorded.
func (d *Deduplicator) IsSeen(hash string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.seen[hash]
	return ok
}

// Mark records a hash as seen. Returns false if it was already seen.
func (d *Deduplicator) Mark(hash string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[hash]; ok {
		return false
	}
	d.seen[hash] = struct{}{}
	return true
}

// Count returns the number of unique hashes tracked.
func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}
