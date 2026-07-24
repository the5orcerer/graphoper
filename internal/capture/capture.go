// Package capture provides Chrome DevTools Protocol event handling for
// intercepting network traffic and downloading JS bundles.
package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/the5orcerer/graphoper/internal/dedup"
	"github.com/the5orcerer/graphoper/internal/extractor"
	"github.com/the5orcerer/graphoper/internal/models"
	"github.com/the5orcerer/graphoper/internal/storage"
)

// Capturer listens to Chrome DevTools Protocol events and processes
// GraphQL traffic and JS bundles.
type Capturer struct {
	db         *storage.DB
	dedup      *dedup.Deduplicator
	bundleDir  string
	logger     *log.Logger

	// pending holds request data keyed by request ID until the response arrives.
	pending   map[network.RequestID]*models.CapturedRequest
	pendingMu sync.Mutex

	// stats
	reqCount    int64
	gqlCount    int64
	bundleCount int64
	mu          sync.Mutex
}

// New creates a new Capturer.
func New(db *storage.DB, dd *dedup.Deduplicator, bundleDir string, logger *log.Logger) *Capturer {
	return &Capturer{
		db:        db,
		dedup:     dd,
		bundleDir: bundleDir,
		logger:    logger,
		pending:   make(map[network.RequestID]*models.CapturedRequest),
	}
}

// Stats returns current capture statistics.
func (c *Capturer) Stats() (requests, graphql, bundles int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqCount, c.gqlCount, c.bundleCount
}

// SetupListeners registers CDP event listeners on the given chromedp context.
func (c *Capturer) SetupListeners(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			c.onRequest(ctx, e)
		case *network.EventResponseReceived:
			c.onResponse(ctx, e)
		case *network.EventLoadingFinished:
			c.onLoadingFinished(ctx, e)
		case *fetch.EventRequestPaused:
			c.onFetchPaused(ctx, e)
		}
	})
}

// onRequest handles an outgoing network request.
func (c *Capturer) onRequest(ctx context.Context, ev *network.EventRequestWillBeSent) {
	c.mu.Lock()
	c.reqCount++
	c.mu.Unlock()

	req := ev.Request

	headers := make(map[string]string)
	for k, v := range req.Headers {
		if s, ok := v.(string); ok {
			headers[k] = s
		}
	}

	postData := strings.TrimSpace(req.PostData)
	if postData == "" {
		postData = extractPostData(req.PostDataEntries)
	}

	captured := &models.CapturedRequest{
		RequestID: string(ev.RequestID),
		URL:       req.URL,
		Method:    req.Method,
		PostData:  postData,
		Headers:   headers,
		Timestamp: time.Now(),
	}

	c.pendingMu.Lock()
	c.pending[ev.RequestID] = captured
	c.pendingMu.Unlock()

	// Check if this is a GraphQL request
	if extractor.IsGraphQLRequest(req.URL, headers, postData) {
		c.processGraphQLRequest(captured)
	}
}

// onResponse handles received response headers.
func (c *Capturer) onResponse(ctx context.Context, ev *network.EventResponseReceived) {
	// We process the body in onLoadingFinished when the full body is available.
	// Here we just record the status.
	c.pendingMu.Lock()
	req, ok := c.pending[ev.RequestID]
	c.pendingMu.Unlock()

	if ok {
		req.ResponseStatus = int(ev.Response.Status)
		req.ResponseHeaders = normalizeHeaders(ev.Response.Headers)
	}

	// Check if this is a JS bundle URL for later download
	url := ev.Response.URL
	if extractor.IsJSBundleURL(url) {
		go c.downloadBundle(url)
	}
}

// onLoadingFinished fires when a resource has fully loaded. We fetch the
// response body here for GraphQL responses.
func (c *Capturer) onLoadingFinished(ctx context.Context, ev *network.EventLoadingFinished) {
	c.pendingMu.Lock()
	req, ok := c.pending[ev.RequestID]
	delete(c.pending, ev.RequestID)
	c.pendingMu.Unlock()

	if !ok {
		return
	}

	// Only fetch body for potential GraphQL endpoints
	if !extractor.IsGraphQLRequest(req.URL, req.Headers, req.PostData) {
		return
	}

	// Fetch the response body via CDP
	go func() {
		var body []byte
		err := chromedp.Run(ctx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				body, err = network.GetResponseBody(ev.RequestID).Do(ctx)
				return err
			}),
		)
		if err != nil {
			c.logger.Printf("[capture] failed to get response body for %s: %v", req.URL, err)
			return
		}

		bodyStr := string(body)

		// Verify it's actually a GraphQL response
		if !extractor.IsGraphQLResponse(bodyStr) {
			return
		}

		c.processGraphQLResponse(req, bodyStr)
	}()
}

// onFetchPaused handles paused fetch requests (used when fetch domain is enabled).
func (c *Capturer) onFetchPaused(ctx context.Context, ev *fetch.EventRequestPaused) {
	// Continue the request without modification — we're passive
	go func() {
		err := chromedp.Run(ctx,
			fetch.ContinueRequest(ev.RequestID),
		)
		if err != nil {
			c.logger.Printf("[capture] fetch continue error: %v", err)
		}
	}()
}

// processGraphQLRequest extracts and stores GraphQL operations from a request.
func (c *Capturer) processGraphQLRequest(req *models.CapturedRequest) {
	ops := extractor.ParseBatchRequest(req.PostData, req.URL)
	for _, op := range ops {
		hash := dedup.Hash(op.Query)
		op.Hash = hash

		if !c.dedup.Mark(hash) {
			c.logger.Printf("[dedup] skipping duplicate: %s (%s)", op.OperationName, hash[:12])
			continue
		}

		inserted, err := c.db.InsertOperation(op)
		if err != nil {
			c.logger.Printf("[storage] insert operation error: %v", err)
			continue
		}

		if inserted {
			c.mu.Lock()
			c.gqlCount++
			c.mu.Unlock()
			c.logger.Printf("[graphql] captured: %s → %s (hash: %s)",
				op.Source, op.OperationName, hash[:12])
		}
	}
}

// processGraphQLResponse stores the response and extracts schema info.
func (c *Capturer) processGraphQLResponse(req *models.CapturedRequest, body string) {
	// Determine the operation hash from the request
	ops := extractor.ParseBatchRequest(req.PostData, req.URL)
	for _, op := range ops {
		hash := dedup.Hash(op.Query)

		resp := &models.Response{
			OperationHash: hash,
			ResponseJSON:  body,
			HTTPStatus:    req.ResponseStatus,
			Headers:       formatHeaders(req.ResponseHeaders),
		}

		if err := c.db.InsertResponse(resp); err != nil {
			c.logger.Printf("[storage] insert response error: %v", err)
		}

		// Extract schema information from the response
		fragments := extractor.ExtractTypenames(body)
		for _, frag := range fragments {
			if frag.TypeName != "" {
				fields, _ := json.Marshal(frag.FieldNames)
				if err := c.db.InsertSchemaFragment(frag.TypeName, string(fields), "", hash); err != nil {
					c.logger.Printf("[storage] insert schema fragment error: %v", err)
				}
				c.logger.Printf("[schema] observed type: %s (fields: %d)", frag.TypeName, len(frag.FieldNames))
			}
		}
	}
}

// downloadBundle fetches a JS bundle, saves it, and extracts GraphQL operations.
func (c *Capturer) downloadBundle(url string) {
	// Check if already downloaded
	exists, err := c.db.BundleExists(url)
	if err != nil {
		c.logger.Printf("[bundle] db check error: %v", err)
		return
	}
	if exists {
		return
	}

	c.logger.Printf("[bundle] downloading: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		c.logger.Printf("[bundle] download error for %s: %v", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.logger.Printf("[bundle] non-200 status for %s: %d", url, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Printf("[bundle] read error for %s: %v", url, err)
		return
	}

	source := string(body)

	// Check if bundle has any GraphQL markers before saving
	if !extractor.HasGraphQLMarkers(source) {
		return
	}

	// Save the bundle file
	filename := sanitizeFilename(url)
	localPath := filepath.Join(c.bundleDir, filename)

	if err := os.WriteFile(localPath, body, 0o644); err != nil {
		c.logger.Printf("[bundle] write error for %s: %v", url, err)
		return
	}

	bundle := &models.Bundle{
		URL:       url,
		LocalPath: localPath,
		Size:      int64(len(body)),
	}

	inserted, err := c.db.InsertBundle(bundle)
	if err != nil {
		c.logger.Printf("[storage] insert bundle error: %v", err)
		return
	}

	if inserted {
		c.mu.Lock()
		c.bundleCount++
		c.mu.Unlock()
		c.logger.Printf("[bundle] saved: %s (%d bytes)", filename, len(body))
	}

	// Extract GraphQL operations from the bundle
	queries := extractor.ExtractFromBundle(source)
	for _, query := range queries {
		hash := dedup.Hash(query)

		if !c.dedup.Mark(hash) {
			continue
		}

		op := &models.Operation{
			Hash:          hash,
			OperationName: extractOpName(query),
			Query:         query,
			Source:        "js",
			Endpoint:      url,
		}

		inserted, err := c.db.InsertOperation(op)
		if err != nil {
			c.logger.Printf("[storage] insert js operation error: %v", err)
			continue
		}

		if inserted {
			c.mu.Lock()
			c.gqlCount++
			c.mu.Unlock()
			c.logger.Printf("[graphql] extracted from JS: %s (hash: %s)", op.OperationName, hash[:12])
		}
	}
}

// extractOpName attempts to pull the operation name from a raw query string.
func extractOpName(query string) string {
	query = strings.TrimSpace(query)
	// Match "query OperationName" or "mutation OperationName"
	for _, prefix := range []string{"query ", "mutation ", "subscription "} {
		lower := strings.ToLower(query)
		if strings.HasPrefix(lower, prefix) {
			rest := query[len(prefix):]
			// Take until ( or { or whitespace
			name := strings.FieldsFunc(rest, func(r rune) bool {
				return r == '(' || r == '{' || r == ' ' || r == '\n' || r == '\r'
			})
			if len(name) > 0 && name[0] != "" {
				return name[0]
			}
		}
	}
	lower := strings.ToLower(query)
	if strings.HasPrefix(lower, "fragment ") {
		rest := query[len("fragment "):]
		name := strings.FieldsFunc(rest, func(r rune) bool {
			return r == ' ' || r == '\n' || r == '\r'
		})
		if len(name) > 0 && name[0] != "" {
			return name[0]
		}
	}
	return ""
}

func sanitizeFilename(url string) string {
	// Take the last path segment
	parts := strings.Split(url, "/")
	name := parts[len(parts)-1]

	// Remove query params
	if idx := strings.Index(name, "?"); idx != -1 {
		name = name[:idx]
	}

	// Replace dangerous chars
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)

	if name == "" {
		name = fmt.Sprintf("bundle_%d.js", time.Now().UnixNano())
	}

	return name
}

func formatHeaders(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}

	func normalizeHeaders(h network.Headers) map[string]string {
		if len(h) == 0 {
			return nil
		}
		out := make(map[string]string, len(h))
		for k, v := range h {
			switch t := v.(type) {
			case string:
				out[k] = t
			default:
				out[k] = fmt.Sprint(t)
			}
		}
		return out
	}
	b, _ := json.Marshal(h)
	return string(b)
}

// extractPostData concatenates all PostDataEntry.Bytes into a single string.
func extractPostData(entries []*network.PostDataEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.Bytes)
	}
	return sb.String()
}
