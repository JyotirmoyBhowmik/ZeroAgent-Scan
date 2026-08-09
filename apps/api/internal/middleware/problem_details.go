package middleware

import (
	"encoding/json"
	"net/http"
	"time"
)

// ProblemDetails represents an RFC 9457 / RFC 7807 compliant error response.
type ProblemDetails struct {
	Type          string                 `json:"type"`                     // URI reference identifying the problem type
	Title         string                 `json:"title"`                    // Short, human-readable summary
	Status        int                    `json:"status"`                   // HTTP status code
	Detail        string                 `json:"detail"`                   // Human-readable explanation specific to this occurrence
	Instance      string                 `json:"instance,omitempty"`       // URI reference identifying specific occurrence
	ErrorCode     string                 `json:"error_code,omitempty"`     // Domain specific error code
	CorrelationID string                 `json:"correlation_id,omitempty"` // Trace identifier
	Timestamp     string                 `json:"timestamp"`                // ISO 8601 UTC timestamp
	InvalidParams []InvalidParameter     `json:"invalid_params,omitempty"` // For validation failures
	Extensions    map[string]interface{} `json:"extensions,omitempty"`     // Additional safe metadata
}

// InvalidParameter describes a single field validation error.
type InvalidParameter struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// WriteProblemDetails writes an RFC 9457 compliant error response to the client.
func WriteProblemDetails(w http.ResponseWriter, r *http.Request, status int, errorCode, detail string, invalidParams []InvalidParameter) {
	corrID := GetCorrelationID(r.Context())
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	title := http.StatusText(status)
	if title == "" {
		title = "API Error"
	}

	problemType := "https://endpointguard.io/errors/" + toSnakeCase(errorCode)
	if errorCode == "" {
		problemType = "about:blank"
	}

	resp := ProblemDetails{
		Type:          problemType,
		Title:         title,
		Status:        status,
		Detail:        detail,
		Instance:      r.URL.Path,
		ErrorCode:     errorCode,
		CorrelationID: corrID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		InvalidParams: invalidParams,
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func toSnakeCase(s string) string {
	var result []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '-')
		}
		if r >= 'A' && r <= 'Z' {
			result = append(result, r+('a'-'A'))
		} else if r == '_' {
			result = append(result, '-')
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}
