// Package extractor handles parsing GraphQL operations from network traffic,
// responses, and JavaScript bundles.
package extractor

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/the5orcerer/graphoper/internal/models"
)

// graphqlBodyPayload is the standard shape of a GraphQL HTTP request body.
type graphqlBodyPayload struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName"`
	Variables     map[string]interface{} `json:"variables"`
}

// ParseNetworkRequest attempts to extract a GraphQL operation from an
// intercepted HTTP request body. Returns nil if the body is not GraphQL.
func ParseNetworkRequest(body, url string) *models.Operation {
	body = strings.TrimSpace(body)
	if body == "" {
		return parseFromURL(url)
	}

	// Try single operation
	var payload graphqlBodyPayload
	if err := json.Unmarshal([]byte(body), &payload); err == nil {
		if payload.Query != "" {
			return buildOp(payload, url)
		}
	}

	// Try batched operations (array of operations)
	var batch []graphqlBodyPayload
	if err := json.Unmarshal([]byte(body), &batch); err == nil && len(batch) > 0 {
		// For batched requests, return the first one.
		// The caller should call ParseBatchRequest for full coverage.
		if batch[0].Query != "" {
			return buildOp(batch[0], url)
		}
	}

	return parseFromURL(url)
}

// ParseBatchRequest extracts all operations from a batched GraphQL request.
func ParseBatchRequest(body, url string) []*models.Operation {
	body = strings.TrimSpace(body)
	if body == "" {
		op := parseFromURL(url)
		if op != nil {
			return []*models.Operation{op}
		}
		return nil
	}

	var batch []graphqlBodyPayload
	if err := json.Unmarshal([]byte(body), &batch); err != nil {
		// Not a batch — try single
		op := ParseNetworkRequest(body, url)
		if op != nil {
			return []*models.Operation{op}
		}
		return nil
	}

	var ops []*models.Operation
	for _, p := range batch {
		if p.Query != "" {
			ops = append(ops, buildOp(p, url))
		}
	}

	if len(ops) == 0 {
		op := parseFromURL(url)
		if op != nil {
			return []*models.Operation{op}
		}
	}
	return ops
}

func buildOp(p graphqlBodyPayload, url string) *models.Operation {
	vars := ""
	if p.Variables != nil {
		b, _ := json.Marshal(p.Variables)
		vars = string(b)
	}

	return &models.Operation{
		OperationName: p.OperationName,
		Query:         p.Query,
		Variables:     vars,
		Source:        "network",
		Endpoint:      url,
	}
}

func parseFromURL(raw string) *models.Operation {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	query := parsed.Query().Get("query")
	if strings.TrimSpace(query) == "" {
		return nil
	}
	opName := parsed.Query().Get("operationName")
	vars := parsed.Query().Get("variables")
	query = strings.TrimSpace(query)
	if looksLikeGraphQL(query) {
		return &models.Operation{
			OperationName: opName,
			Query:         query,
			Variables:     vars,
			Source:        "network",
			Endpoint:      raw,
		}
	}
	return nil
}

// IsGraphQLRequest returns true if the URL or content-type suggests this
// is a GraphQL request.
func IsGraphQLRequest(url string, headers map[string]string, postData string) bool {
	urlLower := strings.ToLower(url)

	// Common GraphQL endpoint patterns
	if strings.Contains(urlLower, "/graphql") ||
		strings.Contains(urlLower, "/gql") ||
		strings.Contains(urlLower, "/api/graphql") ||
		strings.Contains(urlLower, "/query") {
		return true
	}

	// Check content type
	ct := headers["content-type"]
	if ct == "" {
		ct = headers["Content-Type"]
	}
	if strings.Contains(ct, "application/json") && postData != "" {
		// Peek at the body for GraphQL markers
		if strings.Contains(postData, `"query"`) ||
			strings.Contains(postData, `"mutation"`) ||
			strings.Contains(postData, `"operationName"`) {
			return true
		}
	}

	// GET-style GraphQL query string
	if strings.Contains(urlLower, "query=") ||
		strings.Contains(urlLower, "operationname=") {
		return true
	}

	return false
}

// IsGraphQLResponse checks if a response body looks like GraphQL JSON.
func IsGraphQLResponse(body string) bool {
	body = strings.TrimSpace(body)
	if body == "" {
		return false
	}

	// Standard GraphQL response has "data" and/or "errors" at root
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return false
	}

	_, hasData := obj["data"]
	_, hasErrors := obj["errors"]
	return hasData || hasErrors
}

// ---- Schema extraction from responses ----

// ExtractTypenames recursively walks a JSON response and extracts all
// observed __typename values and field names.
func ExtractTypenames(body string) []*models.SchemaFragment {
	var obj interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return nil
	}

	var fragments []*models.SchemaFragment
	walkJSON(obj, "", &fragments)
	return fragments
}

func walkJSON(v interface{}, parent string, out *[]*models.SchemaFragment) {
	switch val := v.(type) {
	case map[string]interface{}:
		frag := &models.SchemaFragment{
			Children: make(map[string]*models.SchemaFragment),
		}

		if tn, ok := val["__typename"]; ok {
			if s, ok := tn.(string); ok {
				frag.TypeName = s
			}
		}

		for k, child := range val {
			if k == "__typename" {
				continue
			}
			frag.FieldNames = append(frag.FieldNames, k)

			// Recurse into objects and arrays
			switch child.(type) {
			case map[string]interface{}, []interface{}:
				walkJSON(child, k, out)
			}
		}

		if frag.TypeName != "" || len(frag.FieldNames) > 0 {
			*out = append(*out, frag)
		}

	case []interface{}:
		for _, item := range val {
			walkJSON(item, parent, out)
		}
	}
}

// ---- JS bundle extraction ----

// graphQL operation patterns in JS bundles
var bundlePatterns = []*regexp.Regexp{
	// Template literal tagged queries: gql`...` or graphql`...`
	regexp.MustCompile("(?s)(?:gql|graphql)`([^`]+)`"),

	// String literal queries with common GraphQL keywords
	regexp.MustCompile(`(?s)"((?:query|mutation|subscription|fragment)\s+\w+[\s\S]*?(?:\{[\s\S]*?\}))"`),
	regexp.MustCompile(`(?s)'((?:query|mutation|subscription|fragment)\s+\w+[\s\S]*?(?:\{[\s\S]*?\}))'`),

	// Relay-style persisted queries
	regexp.MustCompile(`(?s)"text"\s*:\s*"((?:query|mutation|subscription|fragment)\s[\s\S]*?)"`),

	// Apollo-style document nodes
	regexp.MustCompile(`(?s)"query"\s*:\s*"((?:query|mutation|subscription|fragment)\s[\s\S]*?)"`),

	// Escaped string patterns common in webpack bundles
	regexp.MustCompile(`(?s)\\?"((?:query|mutation|subscription|fragment)\s+\w+[^"]*?\{[^"]*?\})\\?"`),
}

// Additional marker patterns to detect GraphQL presence in a bundle
var markerPatterns = []string{
	"__typename",
	"operationName",
	"graphql",
	"gql`",
	"useQuery",
	"useMutation",
	"useLazyQuery",
	"ApolloClient",
	"RelayEnvironment",
	"fetchQuery",
	"commitMutation",
	"__generated__",
}

// ExtractFromBundle scans JavaScript source code for GraphQL operations.
// Returns the raw query strings found.
func ExtractFromBundle(source string) []string {
	var results []string
	seen := make(map[string]struct{})

	for _, pat := range bundlePatterns {
		matches := pat.FindAllStringSubmatch(source, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			query := unescapeJS(m[1])
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}

			// Validate it looks like GraphQL
			if !looksLikeGraphQL(query) {
				continue
			}

			if _, ok := seen[query]; !ok {
				seen[query] = struct{}{}
				results = append(results, query)
			}
		}
	}

	return results
}

// HasGraphQLMarkers returns true if the JS source contains any known
// GraphQL-related patterns, which signals the bundle is worth deep-scanning.
func HasGraphQLMarkers(source string) bool {
	lower := strings.ToLower(source)
	for _, marker := range markerPatterns {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

// IsJSBundleURL returns true if the URL points to a JavaScript bundle.
func IsJSBundleURL(url string) bool {
	lower := strings.ToLower(url)
	return strings.HasSuffix(lower, ".js") ||
		strings.HasSuffix(lower, ".mjs") ||
		strings.Contains(lower, ".js?") ||
		strings.Contains(lower, ".mjs?") ||
		strings.Contains(lower, "chunk") ||
		strings.Contains(lower, "bundle")
}

func looksLikeGraphQL(s string) bool {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "query ") ||
		strings.HasPrefix(lower, "mutation ") ||
		strings.HasPrefix(lower, "subscription ") ||
		strings.HasPrefix(lower, "fragment ") ||
		strings.HasPrefix(lower, "{") ||
		strings.Contains(lower, "... on ")
}

func unescapeJS(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}
