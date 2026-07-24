// Package models defines the core data structures used throughout graphoper.
package models

import "time"

// Operation represents a captured or extracted GraphQL operation.
type Operation struct {
	ID            int64     `json:"id"`
	Hash          string    `json:"hash"`
	OperationName string    `json:"operation_name"`
	Query         string    `json:"query"`
	Variables     string    `json:"variables,omitempty"`
	Source        string    `json:"source"` // "network" or "js"
	Endpoint      string    `json:"endpoint"`
	CreatedAt     time.Time `json:"created_at"`
}

// Response represents a captured GraphQL response paired to an operation.
type Response struct {
	ID            int64  `json:"id"`
	OperationHash string `json:"operation_hash"`
	ResponseJSON  string `json:"response_json"`
	HTTPStatus    int    `json:"http_status"`
	Headers       string `json:"headers,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Bundle represents a downloaded JavaScript bundle.
type Bundle struct {
	ID        int64     `json:"id"`
	URL       string    `json:"url"`
	LocalPath string    `json:"local_path"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// CapturedRequest holds the raw data from an intercepted network request
// before it is parsed into an Operation.
type CapturedRequest struct {
	RequestID     string
	URL           string
	Method        string
	PostData      string
	Headers       map[string]string
	Timestamp     time.Time
}

// CapturedResponse holds the raw response data paired with a request.
type CapturedResponse struct {
	RequestID  string
	Body       string
	Status     int
	Headers    map[string]string
	Timestamp  time.Time
}

// SchemaFragment stores observed type information extracted from responses.
type SchemaFragment struct {
	TypeName   string   `json:"__typename,omitempty"`
	FieldNames []string `json:"field_names,omitempty"`
	Children   map[string]*SchemaFragment `json:"children,omitempty"`
}
