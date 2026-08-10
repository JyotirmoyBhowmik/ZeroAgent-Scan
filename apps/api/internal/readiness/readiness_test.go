package readiness

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/config"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
)

func TestCheckForDemoData_DetectsDemoPrefixAndRFC5737(t *testing.T) {
	repo := repository.NewRepository()
	repo.ClearEndpoints()

	// 1. Add clean enterprise hosts
	cleanHost := models.Endpoint{
		ID:        "host-prod-01",
		Hostname:  "CORP-PRD-WKS01",
		IPAddress: "10.200.5.50",
		Status:    "online",
		CreatedAt: time.Now().UTC(),
	}
	repo.SaveEndpoint(cleanHost)

	// 2. Add demo prefix host
	demoPrefixHost := models.Endpoint{
		ID:        "host-demo-01",
		Hostname:  "DEMO-WKS-001",
		IPAddress: "10.200.5.51",
		Status:    "online",
		CreatedAt: time.Now().UTC(),
	}
	repo.SaveEndpoint(demoPrefixHost)

	// 3. Add RFC 5737 host
	rfcHost := models.Endpoint{
		ID:        "host-rfc-01",
		Hostname:  "CORP-WKS-002",
		IPAddress: "192.0.2.15", // RFC 5737 TEST-NET-1
		Status:    "online",
		CreatedAt: time.Now().UTC(),
	}
	repo.SaveEndpoint(rfcHost)

	violations := CheckForDemoData(repo)
	if len(violations) < 2 {
		t.Fatalf("expected at least 2 demo violations, got %d", len(violations))
	}

	foundPrefix := false
	foundRFC := false
	for _, v := range violations {
		if v.Type == "HOSTNAME_PREFIX" && v.Identifier == "DEMO-WKS-001" {
			foundPrefix = true
		}
		if v.Type == "RFC5737_IP" && v.Identifier == "192.0.2.15" {
			foundRFC = true
		}
	}

	if !foundPrefix {
		t.Errorf("failed to detect HOSTNAME_PREFIX violation for DEMO-WKS-001")
	}
	if !foundRFC {
		t.Errorf("failed to detect RFC5737_IP violation for 192.0.2.15")
	}
}

func TestVerifyNoDemoDataInProduction_FailsOnDemoData(t *testing.T) {
	repo := repository.NewRepository()
	repo.ClearEndpoints()
	repo.SaveEndpoint(models.Endpoint{
		ID:        "host-demo-test",
		Hostname:  "DEMO-SRV-001",
		IPAddress: "10.0.0.1",
	})

	err := VerifyNoDemoDataInProduction(repo)
	if err == nil {
		t.Fatalf("expected fatal error on demo data in production, got nil")
	}
}

func TestEvaluateProductionReadiness_CatchesInsecureDefaults(t *testing.T) {
	os.Setenv("MOCK_SCAN_MODE", "true")
	defer os.Unsetenv("MOCK_SCAN_MODE")

	repo := repository.NewRepository()
	repo.ClearEndpoints()
	repo.SaveEndpoint(models.Endpoint{
		ID:        "host-demo-01",
		Hostname:  "DEMO-WKS-001",
		IPAddress: "192.0.2.11",
	})

	authRepo := auth.NewMemoryAuthRepository()

	defaultKey, _ := hex.DecodeString(DefaultDevMasterKeyHex)
	cfg := &config.Config{
		Environment:    "production",
		VaultMasterKey: defaultKey,
	}

	report := EvaluateProductionReadiness(repo, authRepo, cfg)

	if report.OverallVerdict != "FAIL" {
		t.Errorf("expected overall verdict 'FAIL', got '%s'", report.OverallVerdict)
	}

	if report.FailedCount < 2 {
		t.Errorf("expected at least 2 failed checks (demo data, default vault key, mock scan mode), got %d", report.FailedCount)
	}
}

func TestEvaluateProductionReadiness_PassesOnHardenedConfig(t *testing.T) {
	os.Setenv("MOCK_SCAN_MODE", "false")
	defer os.Unsetenv("MOCK_SCAN_MODE")

	cleanRepo := repository.NewRepository()
	cleanRepo.ClearEndpoints()

	// Add clean production host
	cleanRepo.SaveEndpoint(models.Endpoint{
		ID:        "host-prod-01",
		Hostname:  "NYC-DC-01",
		IPAddress: "10.10.1.10",
		Status:    "online",
	})

	// Rotate break-glass account
	authRepo := auth.NewMemoryAuthRepository()
	bgUser, _ := authRepo.GetUserByUsername("", "breakglass")
	if bgUser != nil {
		bgUser.PasswordHash = auth.HashPassword("CustomStrongP@ssw0rd2026!", bgUser.ID)
		_ = authRepo.SaveUser(*bgUser)
	}

	// High entropy production key
	prodKeyHex := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	prodKey, _ := hex.DecodeString(prodKeyHex)
	cfg := &config.Config{
		Environment:    "production",
		VaultMasterKey: prodKey,
	}

	report := EvaluateProductionReadiness(cleanRepo, authRepo, cfg)

	// Check Demo Data check passes
	var demoCheck *ReadinessCheckItem
	for i := range report.Checks {
		if report.Checks[i].ID == "DEMO_DATA_ABSENCE" {
			demoCheck = &report.Checks[i]
		}
	}

	if demoCheck == nil || demoCheck.Status != "PASS" {
		t.Errorf("expected DEMO_DATA_ABSENCE check to PASS, got %+v", demoCheck)
	}
}
