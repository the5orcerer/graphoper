// Package storage provides in-memory persistence for graphoper data.
package storage

import (
	"sync"
	"time"

	"github.com/the5orcerer/graphoper/internal/models"
)

// DB provides thread-safe in-memory storage for captured artifacts.
type DB struct {
	mu sync.Mutex

	operations      []models.Operation
	responses       []models.Response
	bundles         []models.Bundle
	schemaFragments []SchemaFragmentExport

	operationByHash map[string]struct{}
	bundleByURL     map[string]struct{}
}

// ExportData is a full snapshot of persisted capture artifacts.
type ExportData struct {
	Operations      []models.Operation     `json:"operations"`
	Responses       []models.Response      `json:"responses"`
	SchemaFragments []SchemaFragmentExport `json:"schema_fragments"`
}

type SchemaFragmentExport struct {
	TypeName  string `json:"typename"`
	Fields    string `json:"fields"`
	Parent    string `json:"parent"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

// New initializes in-memory storage.
func New() (*DB, error) {
	return &DB{
		operationByHash: make(map[string]struct{}),
		bundleByURL:     make(map[string]struct{}),
	}, nil
}

// Close is a no-op for in-memory storage.
func (db *DB) Close() error {
	return nil
}

// InsertOperation stores a new operation if its hash does not already exist.
// Returns true if inserted, false if it was a duplicate.
func (db *DB) InsertOperation(op *models.Operation) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.operationByHash[op.Hash]; ok {
		return false, nil
	}
	db.operationByHash[op.Hash] = struct{}{}

	opCopy := *op
	opCopy.ID = int64(len(db.operations) + 1)
	if opCopy.CreatedAt.IsZero() {
		opCopy.CreatedAt = time.Now()
	}
	db.operations = append(db.operations, opCopy)
	return true, nil
}

// InsertResponse stores a GraphQL response linked to an operation hash.
func (db *DB) InsertResponse(resp *models.Response) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	respCopy := *resp
	respCopy.ID = int64(len(db.responses) + 1)
	if respCopy.CreatedAt.IsZero() {
		respCopy.CreatedAt = time.Now()
	}
	db.responses = append(db.responses, respCopy)
	return nil
}

// InsertBundle stores a JS bundle record. Returns true if newly inserted.
func (db *DB) InsertBundle(b *models.Bundle) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.bundleByURL[b.URL]; ok {
		return false, nil
	}
	db.bundleByURL[b.URL] = struct{}{}

	bCopy := *b
	bCopy.ID = int64(len(db.bundles) + 1)
	if bCopy.CreatedAt.IsZero() {
		bCopy.CreatedAt = time.Now()
	}
	db.bundles = append(db.bundles, bCopy)
	return true, nil
}

// InsertSchemaFragment stores an observed type from a response.
func (db *DB) InsertSchemaFragment(typename, fields, parent, source string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.schemaFragments = append(db.schemaFragments, SchemaFragmentExport{
		TypeName:  typename,
		Fields:    fields,
		Parent:    parent,
		Source:    source,
		CreatedAt: time.Now().Format(time.RFC3339Nano),
	})
	return nil
}

// OperationExists checks whether an operation with the given hash is stored.
func (db *DB) OperationExists(hash string) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, ok := db.operationByHash[hash]
	return ok, nil
}

// BundleExists checks whether a bundle URL has already been recorded.
func (db *DB) BundleExists(url string) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, ok := db.bundleByURL[url]
	return ok, nil
}

// Stats returns counts of operations, responses, bundles, and schema fragments.
func (db *DB) Stats() (ops, resps, bundles, fragments int, err error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	ops = len(db.operations)
	resps = len(db.responses)
	bundles = len(db.bundles)
	fragments = len(db.schemaFragments)
	return
}

// ExportSnapshot returns all persisted operations, responses, and schema fragments.
func (db *DB) ExportSnapshot() (*ExportData, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	out := &ExportData{}

	out.Operations = append(out.Operations, db.operations...)
	out.Responses = append(out.Responses, db.responses...)
	out.SchemaFragments = append(out.SchemaFragments, db.schemaFragments...)

	return out, nil
}
