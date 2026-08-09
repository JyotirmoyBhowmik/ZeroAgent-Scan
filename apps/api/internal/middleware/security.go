package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

type APIErrorResponse struct {
	Timestamp     string `json:"timestamp"`
	StatusCode    int    `json:"status_code"`
	ErrorCode     string `json:"error_code"`
	CorrelationID string `json:"correlation_id"`
	Message       string `json:"message"`
}

func WriteSanitizedError(w http.ResponseWriter, r *http.Request, statusCode int, errorCode, message string) {
	corrID := GetCorrelationID(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := APIErrorResponse{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		StatusCode:    statusCode,
		ErrorCode:     errorCode,
		CorrelationID: corrID,
		Message:       message,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OWASP ASVS Level 2 Required Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data: https:;")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		next.ServeHTTP(w, r)
	})
}

// ValidateScanTargetSubnet prevents SSRF against dangerous metadata endpoints (e.g. AWS 169.254.169.254)
func ValidateScanTargetSubnet(cidrStr string) (bool, string) {
	cidrStr = strings.TrimSpace(cidrStr)
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		// Try parsing single IP
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			return false, "Invalid CIDR or IP address format"
		}
		if ip.IsLoopback() || ip.String() == "169.254.169.254" {
			return false, "Target IP is a restricted metadata/loopback address (SSRF Protection)"
		}
		return true, ""
	}

	// Disallow link-local cloud metadata range (169.254.0.0/16)
	_, metaNet, _ := net.ParseCIDR("169.254.0.0/16")
	if metaNet.Contains(ipNet.IP) {
		return false, "Target subnet overlaps with cloud instance metadata range (SSRF Protection)"
	}

	return true, ""
}
