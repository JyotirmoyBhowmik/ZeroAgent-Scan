package openapi

import (
	"encoding/json"
	"net/http"
)

// GenerateOpenAPISpec builds the complete OpenAPI 3.1 JSON Schema specification for the EndpointGuard REST API.
func GenerateOpenAPISpec() map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "EndpointGuard ZeroAgent Scan REST API",
			"version":     "1.0.0",
			"description": "Enterprise agentless remote security auditing, hardware telemetry, vulnerability scanning (NVD/CISA KEV), CIS compliance verification, and configuration drift detection API.",
			"contact": map[string]interface{}{
				"name":  "EndpointGuard SecOps Team",
				"email": "security@endpointguard.local",
			},
			"license": map[string]interface{}{
				"name": "Proprietary",
			},
		},
		"servers": []map[string]interface{}{
			{
				"url":         "/api/v1",
				"description": "Primary API v1 gateway",
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"BearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
					"description":  "JWT containing tenant_id, user_id, and role claims",
				},
				"mTLS": map[string]interface{}{
					"type":        "mutualTLS",
					"description": "Mutual TLS for Collector Gateways",
				},
			},
			"schemas": map[string]interface{}{
				"ProblemDetails": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"type":           map[string]interface{}{"type": "string"},
						"title":          map[string]interface{}{"type": "string"},
						"status":         map[string]interface{}{"type": "integer"},
						"detail":         map[string]interface{}{"type": "string"},
						"instance":       map[string]interface{}{"type": "string"},
						"error_code":     map[string]interface{}{"type": "string"},
						"correlation_id": map[string]interface{}{"type": "string"},
						"timestamp":      map[string]interface{}{"type": "string", "format": "date-time"},
					},
					"required": []string{"type", "title", "status", "detail", "timestamp"},
				},
				"Endpoint": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":               map[string]interface{}{"type": "string", "format": "uuid"},
						"hostname":         map[string]interface{}{"type": "string"},
						"ip_address":       map[string]interface{}{"type": "string"},
						"mac_address":      map[string]interface{}{"type": "string"},
						"os_name":          map[string]interface{}{"type": "string"},
						"chassis_type":     map[string]interface{}{"type": "string"},
						"status":           map[string]interface{}{"type": "string"},
						"compliance_score": map[string]interface{}{"type": "number"},
					},
				},
				"ScanJob": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":          map[string]interface{}{"type": "string", "format": "uuid"},
						"name":        map[string]interface{}{"type": "string"},
						"target_cidr": map[string]interface{}{"type": "string"},
						"protocol":    map[string]interface{}{"type": "string"},
						"status":      map[string]interface{}{"type": "string"},
					},
				},
				"VulnerabilityFinding": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":         map[string]interface{}{"type": "string"},
						"cve_id":     map[string]interface{}{"type": "string"},
						"title":      map[string]interface{}{"type": "string"},
						"cvss_score": map[string]interface{}{"type": "number"},
						"severity":   map[string]interface{}{"type": "string"},
						"is_kev":     map[string]interface{}{"type": "boolean"},
					},
				},
				"DriftEvent": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":             map[string]interface{}{"type": "string"},
						"drift_category": map[string]interface{}{"type": "string"},
						"property_name":  map[string]interface{}{"type": "string"},
						"baseline_value": map[string]interface{}{"type": "string"},
						"current_value":  map[string]interface{}{"type": "string"},
						"severity":       map[string]interface{}{"type": "string"},
					},
				},
			},
		},
		"security": []map[string]interface{}{
			{"BearerAuth": []string{}},
		},
		"paths": map[string]interface{}{
			"/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "System Health Check",
					"description": "Returns operational liveness and system health status",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Healthy"},
					},
				},
			},
			"/metrics": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Fleet Telemetry Metrics",
					"description": "Returns high-level aggregate fleet coverage and health statistics",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Fleet metrics"},
					},
				},
			},
			"/endpoints": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Endpoints",
					"description": "Returns inventory of scanned network hosts",
					"parameters": []map[string]interface{}{
						{"name": "search", "in": "query", "schema": map[string]interface{}{"type": "string"}},
						{"name": "status", "in": "query", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of endpoints"},
					},
				},
			},
			"/endpoints/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Get Endpoint Detail",
					"description": "Returns full host details including hardware and security baseline",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Endpoint details"},
						"404": map[string]interface{}{"description": "Endpoint not found"},
					},
				},
			},
			"/snapshots": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Snapshots (Keyset Paginated)",
					"description": "Returns high-volume telemetry snapshots with cursor-based pagination",
					"parameters": []map[string]interface{}{
						{"name": "cursor", "in": "query", "schema": map[string]interface{}{"type": "string"}},
						{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 20}},
						{"name": "host_id", "in": "query", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Paginated snapshots"},
					},
				},
			},
			"/scans": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Scan Jobs",
					"description": "Returns scheduled and completed agentless network scan jobs",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of scan jobs"},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Create Scan Job",
					"description": "Triggers a new agentless subnet or IP scan",
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "Scan job created"},
						"400": map[string]interface{}{"description": "Validation error or SSRF blocked target"},
					},
				},
			},
			"/scans/{id}/cancel": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Cancel Scan Job",
					"description": "Cancels an in-progress scan job",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Scan job cancelled"},
					},
				},
			},
			"/findings": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Vulnerabilities (KEV First, CVSS Desc)",
					"description": "Returns open CVE findings with CISA KEV prioritization",
					"parameters": []map[string]interface{}{
						{"name": "severity", "in": "query", "schema": map[string]interface{}{"type": "string"}},
						{"name": "kev_only", "in": "query", "schema": map[string]interface{}{"type": "boolean"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of findings"},
					},
				},
			},
			"/compliance/frameworks": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Compliance Frameworks",
					"description": "Returns supported benchmarks (CIS Windows 11 v2.0, DISA STIG)",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of frameworks"},
					},
				},
			},
			"/compliance/tenant/summary": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Tenant Compliance Summary",
					"description": "Returns fleet aggregate compliance percentage and status",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Compliance summary"},
					},
				},
			},
			"/drift/events": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Drift Events",
					"description": "Returns configuration drift events classified by severity",
					"parameters": []map[string]interface{}{
						{"name": "severity", "in": "query", "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of drift events"},
					},
				},
			},
			"/drift/events/{id}/acknowledge": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Acknowledge Drift Event",
					"description": "Marks a configuration drift as acknowledged by an operator",
					"parameters": []map[string]interface{}{
						{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Event acknowledged"},
					},
				},
			},
			"/vault/credentials": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Vault Credential References (Metadata Only)",
					"description": "Returns opaque credential references without plaintext secret material",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of credential metadata"},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Create Vault Credential",
					"description": "Encrypts and stores a credential secret, returning an opaque reference ID",
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "Credential created"},
					},
				},
			},
			"/reports": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Generate Executive & Compliance Reports",
					"description": "Builds on-demand CISO Executive, Compliance Audit, or Vulnerability Posture reports",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Report generated"},
					},
				},
			},
			"/audit-logs": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List Security Audit Logs (Keyset Paginated)",
					"description": "Returns immutable security audit entries with cursor-based pagination",
					"parameters": []map[string]interface{}{
						{"name": "cursor", "in": "query", "schema": map[string]interface{}{"type": "string"}},
						{"name": "limit", "in": "query", "schema": map[string]interface{}{"type": "integer", "default": 50}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Paginated audit logs"},
					},
				},
			},
		},
	}
}

// ServeOpenAPIJSON responds with the OpenAPI 3.1 JSON document.
func ServeOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	spec := GenerateOpenAPISpec()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(spec)
}

// ServeSwaggerUI serves interactive Swagger UI documentation.
func ServeSwaggerUI(w http.ResponseWriter, r *http.Request) {
	htmlContent := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>EndpointGuard API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; background: #0f172a; }
    .swagger-ui { filter: invert(88%) hue-rotate(180deg); }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api/v1/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
      });
    };
  </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlContent))
}
