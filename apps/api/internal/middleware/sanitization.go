package middleware

import (
	"html"
	"regexp"
	"strings"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// SanitizeHTML escapes HTML special characters to prevent Cross-Site Scripting (XSS) in UI rendering.
func SanitizeHTML(input string) string {
	return html.EscapeString(strings.TrimSpace(input))
}

// SanitizeText removes null bytes, unprintable control characters, and leading/trailing whitespace.
func SanitizeText(input string) string {
	var sb strings.Builder
	for _, r := range input {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
			continue // Strip control chars and null bytes
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

// ValidateUUID strictly checks if a string is a valid RFC 4122 UUID.
func ValidateUUID(id string) bool {
	return uuidRegex.MatchString(id)
}

// ValidateStringLength checks if a string's length is within the specified bounds.
func ValidateStringLength(s string, minLen, maxLen int) bool {
	length := len(strings.TrimSpace(s))
	return length >= minLen && length <= maxLen
}
