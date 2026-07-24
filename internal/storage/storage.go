// Package storage provides SQLite-backed persistence for graphoper data.
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/the5orcerer/graphoper/internal/models"
)

// DB wraps the SQLite connection and provides thread-safe operations.
type DB struct {
	conn *sql.DB
	mu   sync.Mutex
	path string
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

// New opens (or creates) the SQLite database at the given path and
// runs the schema migration.
func New(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("storage: create dir: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}

	conn.SetMaxOpenConns(1) // SQLite is single-writer

	db := &DB{conn: conn, path: dbPath}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}

	return db, nil
}

// Close shuts down the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS operations (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		hash            TEXT NOT NULL UNIQUE,
		operation_name  TEXT NOT NULL DEFAULT '',
		query           TEXT NOT NULL,
		variables       TEXT DEFAULT '',
		source          TEXT NOT NULL DEFAULT 'network',
		endpoint        TEXT NOT NULL DEFAULT '',
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS responses (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		operation_hash  TEXT NOT NULL,
		response_json   TEXT NOT NULL,
		http_status     INTEGER DEFAULT 0,
		headers         TEXT DEFAULT '',
		created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (operation_hash) REFERENCES operations(hash)
	);

	CREATE TABLE IF NOT EXISTS bundles (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		url        TEXT NOT NULL UNIQUE,
		local_path TEXT NOT NULL,
		size       INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS schema_fragments (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		typename   TEXT NOT NULL,
		fields     TEXT DEFAULT '',
		parent     TEXT DEFAULT '',
		source     TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_operations_hash ON operations(hash);
	CREATE INDEX IF NOT EXISTS idx_responses_ophash ON responses(operation_hash);
	CREATE INDEX IF NOT EXISTS idx_bundles_url ON bundles(url);
	CREATE INDEX IF NOT EXISTS idx_schema_typename ON schema_fragments(typename);
	`

	_, err := db.conn.Exec(schema)
	if err != nil {
		return fmt.Errorf("storage: migrate: %w", err)
	}
	return nil
}

// InsertOperation stores a new operation if its hash does not already exist.
// Returns true if inserted, false if it was a duplicate.
func (db *DB) InsertOperation(op *models.Operation) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	res, err := db.conn.Exec(
		`INSERT OR IGNORE INTO operations (hash, operation_name, query, variables, source, endpoint, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		op.Hash, op.OperationName, op.Query, op.Variables, op.Source, op.Endpoint, time.Now(),
	)
	if err != nil {
		return false, fmt.Errorf("storage: insert operation: %w", err)
	}

	rows, _ := res.RowsAffected()
	return rows > 0, nil
}

// InsertResponse stores a GraphQL response linked to an operation hash.
func (db *DB) InsertResponse(resp *models.Response) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec(
		`INSERT INTO responses (operation_hash, response_json, http_status, headers, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		resp.OperationHash, resp.ResponseJSON, resp.HTTPStatus, resp.Headers, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("storage: insert response: %w", err)
	}
	return nil
}

// InsertBundle stores a JS bundle record. Returns true if newly inserted.
func (db *DB) InsertBundle(b *models.Bundle) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	res, err := db.conn.Exec(
		`INSERT OR IGNORE INTO bundles (url, local_path, size, created_at) VALUES (?, ?, ?, ?)`,
		b.URL, b.LocalPath, b.Size, time.Now(),
	)
	if err != nil {
		return false, fmt.Errorf("storage: insert bundle: %w", err)
	}

	rows, _ := res.RowsAffected()
	return rows > 0, nil
}

// InsertSchemaFragment stores an observed type from a response.
func (db *DB) InsertSchemaFragment(typename, fields, parent, source string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	_, err := db.conn.Exec(
		`INSERT INTO schema_fragments (typename, fields, parent, source, created_at) VALUES (?, ?, ?, ?, ?)`,
		typename, fields, parent, source, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("storage: insert schema fragment: %w", err)
	}
	return nil
}

// OperationExists checks whether an operation with the given hash is stored.
func (db *DB) OperationExists(hash string) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM operations WHERE hash = ?`, hash).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// BundleExists checks whether a bundle URL has already been recorded.
func (db *DB) BundleExists(url string) (bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM bundles WHERE url = ?`, url).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Stats returns counts of operations, responses, bundles, and schema fragments.
func (db *DB) Stats() (ops, resps, bundles, fragments int, err error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.conn.QueryRow(`SELECT COUNT(*) FROM operations`).Scan(&ops)
	db.conn.QueryRow(`SELECT COUNT(*) FROM responses`).Scan(&resps)
	db.conn.QueryRow(`SELECT COUNT(*) FROM bundles`).Scan(&bundles)
	db.conn.QueryRow(`SELECT COUNT(*) FROM schema_fragments`).Scan(&fragments)
	return
}

// ExportSnapshot returns all persisted operations, responses, and schema fragments.
func (db *DB) ExportSnapshot() (*ExportData, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	out := &ExportData{}

	opRows, err := db.conn.Query(`
		SELECT id, hash, operation_name, query, variables, source, endpoint, created_at
		FROM operations
		ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list operations: %w", err)
	}
	defer opRows.Close()
	for opRows.Next() {
		var op models.Operation
		if err := opRows.Scan(&op.ID, &op.Hash, &op.OperationName, &op.Query, &op.Variables, &op.Source, &op.Endpoint, &op.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan operation: %w", err)
		}
		out.Operations = append(out.Operations, op)
	}

	respRows, err := db.conn.Query(`
		SELECT id, operation_hash, response_json, http_status, headers, created_at
		FROM responses
		ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list responses: %w", err)
	}
	defer respRows.Close()
	for respRows.Next() {
		var resp models.Response
		if err := respRows.Scan(&resp.ID, &resp.OperationHash, &resp.ResponseJSON, &resp.HTTPStatus, &resp.Headers, &resp.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan response: %w", err)
		}
		out.Responses = append(out.Responses, resp)
	}

	sRows, err := db.conn.Query(`
		SELECT typename, fields, parent, source, created_at
		FROM schema_fragments
		ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("storage: list schema fragments: %w", err)
	}
	defer sRows.Close()
	for sRows.Next() {
		var sf SchemaFragmentExport
		if err := sRows.Scan(&sf.TypeName, &sf.Fields, &sf.Parent, &sf.Source, &sf.CreatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan schema fragment: %w", err)
		}
		out.SchemaFragments = append(out.SchemaFragments, sf)
	}

	return out, nil
}
