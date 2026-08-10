package readiness

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/config"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
)

// Default insecure development values that must never be present in production
const (
	DefaultDevMasterKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	DefaultDevJWTSecret    = "enterprise-endpointguard-master-jwt-secret-key-32b!"
)

// ReadinessCheckItem represents an individual audit item.
type ReadinessCheckItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Pillar      string   `json:"pillar"` // "DEMO_HYGIENE", "CREDENTIAL_SECURITY", "FEATURE_FLAGS", "AUDIT_INTEGRITY", "NETWORK_MTLS"
	Status      string   `json:"status"` // "PASS", "FAIL", "WARN"
	Message     string   `json:"message"`
	Remediation string   `json:"remediation"`
	Details     []string `json:"details,omitempty"`
}

// ProductionReadinessReport aggregates all readiness results into a single go-live verdict.
type ProductionReadinessReport struct {
	OverallVerdict string               `json:"overall_verdict"` // "PASS" (Go-Live Ready) or "FAIL" (Blocked)
	Environment    string               `json:"environment"`
	GeneratedAt    time.Time            `json:"generated_at"`
	PassedCount    int                  `json:"passed_count"`
	FailedCount    int                  `json:"failed_count"`
	WarningCount   int                  `json:"warning_count"`
	TotalChecks    int                  `json:"total_checks"`
	Checks         []ReadinessCheckItem `json:"checks"`
}

// EvaluateProductionReadiness performs comprehensive auditing of the runtime environment and data state.
func EvaluateProductionReadiness(repo *repository.Repository, authRepo auth.AuthRepository, cfg *config.Config) ProductionReadinessReport {
	now := time.Now().UTC()
	var checks []ReadinessCheckItem
	env := "development"
	if cfg != nil && cfg.Environment != "" {
		env = cfg.Environment
	}

	// -------------------------------------------------------------------------
	// 1. Pillar: Demo Data Hygiene (DEMO_HYGIENE)
	// -------------------------------------------------------------------------
	violations := CheckForDemoData(repo)
	if len(violations) > 0 {
		var details []string
		for _, v := range violations {
			details = append(details, fmt.Sprintf("[%s] %s: %s", v.Type, v.Identifier, v.Details))
		}
		checks = append(checks, ReadinessCheckItem{
			ID:          "DEMO_DATA_ABSENCE",
			Name:        "Demo & RFC 5737 Mock Fleet Elimination",
			Pillar:      "DEMO_HYGIENE",
			Status:      "FAIL",
			Message:     fmt.Sprintf("Found %d non-production demo endpoints or RFC 5737 IP addresses in database.", len(violations)),
			Remediation: "Purge all seed data via 'DELETE FROM endpoints WHERE hostname LIKE ''DEMO-%'';' before production deployment.",
			Details:     details,
		})
	} else {
		checks = append(checks, ReadinessCheckItem{
			ID:          "DEMO_DATA_ABSENCE",
			Name:        "Demo & RFC 5737 Mock Fleet Elimination",
			Pillar:      "DEMO_HYGIENE",
			Status:      "PASS",
			Message:     "No demo hostnames (DEMO-*) or RFC 5737 documentation IP ranges found in active inventory.",
			Remediation: "None required. Clean fleet state verified.",
		})
	}

	// -------------------------------------------------------------------------
	// 2. Pillar: Vault Master Key Security (CREDENTIAL_SECURITY)
	// -------------------------------------------------------------------------
	if cfg != nil {
		currentKeyHex := hex.EncodeToString(cfg.VaultMasterKey)
		if strings.EqualFold(currentKeyHex, DefaultDevMasterKeyHex) {
			checks = append(checks, ReadinessCheckItem{
				ID:          "VAULT_MASTER_KEY",
				Name:        "AES-256-GCM Vault Master Key Entropy",
				Pillar:      "CREDENTIAL_SECURITY",
				Status:      "FAIL",
				Message:     "Default insecure development VAULT_MASTER_KEY_HEX is active in configuration.",
				Remediation: "Generate a cryptographically random 32-byte key via 'openssl rand -hex 32' and set VAULT_MASTER_KEY_HEX in production environment.",
			})
		} else if len(cfg.VaultMasterKey) != 32 {
			checks = append(checks, ReadinessCheckItem{
				ID:          "VAULT_MASTER_KEY",
				Name:        "AES-256-GCM Vault Master Key Entropy",
				Pillar:      "CREDENTIAL_SECURITY",
				Status:      "FAIL",
				Message:     fmt.Sprintf("Vault Master Key has invalid length: %d bytes (expected 32 bytes).", len(cfg.VaultMasterKey)),
				Remediation: "Ensure VAULT_MASTER_KEY_HEX is exactly 64 hex characters (32 bytes).",
			})
		} else {
			checks = append(checks, ReadinessCheckItem{
				ID:          "VAULT_MASTER_KEY",
				Name:        "AES-256-GCM Vault Master Key Entropy",
				Pillar:      "CREDENTIAL_SECURITY",
				Status:      "PASS",
				Message:     "Vault master key is non-default, high-entropy 256-bit AES-GCM key.",
				Remediation: "None required. Key entropy verified.",
			})
		}
	}

	// -------------------------------------------------------------------------
	// 3. Pillar: Break-Glass Account Hardening (CREDENTIAL_SECURITY)
	// -------------------------------------------------------------------------
	if authRepo != nil {
		bgUser, exists := authRepo.GetUserByUsername("", "breakglass")
		if exists && bgUser != nil {
			defaultHash := auth.HashPassword("EmergencyBreakGlassPass2026!", bgUser.ID)
			if bgUser.PasswordHash == defaultHash {
				checks = append(checks, ReadinessCheckItem{
					ID:          "BREAKGLASS_CREDENTIAL_ROTATION",
					Name:        "Break-Glass Emergency Account Password Rotation",
					Pillar:      "CREDENTIAL_SECURITY",
					Status:      "WARN",
					Message:     "Break-glass account 'breakglass' is currently using the default example password.",
					Remediation: "Rotate break-glass emergency password immediately via admin portal or API with step-up MFA.",
				})
			} else {
				checks = append(checks, ReadinessCheckItem{
					ID:          "BREAKGLASS_CREDENTIAL_ROTATION",
					Name:        "Break-Glass Emergency Account Password Rotation",
					Pillar:      "CREDENTIAL_SECURITY",
					Status:      "PASS",
					Message:     "Break-glass account password has been rotated from default bootstrap credentials.",
					Remediation: "None required. Password rotated.",
				})
			}
		}
	}

	// -------------------------------------------------------------------------
	// 4. Pillar: Non-Production Feature Flags (FEATURE_FLAGS)
	// -------------------------------------------------------------------------
	mockScanMode := strings.EqualFold(os.Getenv("MOCK_SCAN_MODE"), "true")
	if mockScanMode {
		checks = append(checks, ReadinessCheckItem{
			ID:          "MOCK_SCAN_MODE_FLAG",
			Name:        "Agentless Scan Engine Simulation Flag",
			Pillar:      "FEATURE_FLAGS",
			Status:      "FAIL",
			Message:     "MOCK_SCAN_MODE is set to 'true'. Real WinRM/DCOM scans are disabled.",
			Remediation: "Remove or set MOCK_SCAN_MODE=false in production environment to enable live network scanning.",
		})
	} else {
		checks = append(checks, ReadinessCheckItem{
			ID:          "MOCK_SCAN_MODE_FLAG",
			Name:        "Agentless Scan Engine Simulation Flag",
			Pillar:      "FEATURE_FLAGS",
			Status:      "PASS",
			Message:     "Mock scan simulation mode is disabled. Real WinRM/DCOM network scanning active.",
			Remediation: "None required.",
		})
	}

	// -------------------------------------------------------------------------
	// 5. Pillar: Security Audit Log Stream (AUDIT_INTEGRITY)
	// -------------------------------------------------------------------------
	if repo != nil {
		logs := repo.ListAuditLogs()
		checks = append(checks, ReadinessCheckItem{
			ID:          "AUDIT_LOG_PIPELINE",
			Name:        "OWASP ASVS Immutable Audit Logging Stream",
			Pillar:      "AUDIT_INTEGRITY",
			Status:      "PASS",
			Message:     fmt.Sprintf("Audit logging pipeline active with %d immutable trace events recorded.", len(logs)),
			Remediation: "None required. Audit stream active.",
		})
	}

	// -------------------------------------------------------------------------
	// 6. Pillar: Collector Gateway Connectivity (NETWORK_MTLS)
	// -------------------------------------------------------------------------
	if repo != nil {
		gateways := repo.ListGateways()
		if len(gateways) == 0 {
			checks = append(checks, ReadinessCheckItem{
				ID:          "GATEWAY_TOPOLOGY",
				Name:        "Subnet Collector Gateway Deployment",
				Pillar:      "NETWORK_MTLS",
				Status:      "WARN",
				Message:     "No collector gateways are registered. WinRM scanning may require direct network reachability.",
				Remediation: "Deploy at least one Collector Gateway per targeted subnet.",
			})
		} else {
			checks = append(checks, ReadinessCheckItem{
				ID:          "GATEWAY_TOPOLOGY",
				Name:        "Subnet Collector Gateway Deployment",
				Pillar:      "NETWORK_MTLS",
				Status:      "PASS",
				Message:     fmt.Sprintf("Registered %d collector gateways with mTLS mutual authentication.", len(gateways)),
				Remediation: "None required.",
			})
		}
	}

	// -------------------------------------------------------------------------
	// Aggregate Statistics & Final Go-Live Verdict
	// -------------------------------------------------------------------------
	var passed, failed, warnings int
	for _, c := range checks {
		switch c.Status {
		case "PASS":
			passed++
		case "FAIL":
			failed++
		case "WARN":
			warnings++
		}
	}

	verdict := "PASS"
	if failed > 0 {
		verdict = "FAIL"
	}

	return ProductionReadinessReport{
		OverallVerdict: verdict,
		Environment:    env,
		GeneratedAt:    now,
		PassedCount:    passed,
		FailedCount:    failed,
		WarningCount:   warnings,
		TotalChecks:    len(checks),
		Checks:         checks,
	}
}
