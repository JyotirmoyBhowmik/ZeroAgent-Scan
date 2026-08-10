package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/auth"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/compliance"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/config"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/handlers"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/openapi"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/readiness"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/telemetry"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vulnscan"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Config validation error: %v\n", err)
		os.Exit(1)
	}

	// Initialize Vault Provider
	envelopeProvider, err := vault.NewEnvelopeProvider(cfg.VaultMasterKey)
	if err != nil {
		fmt.Printf("Failed to initialize vault provider: %v\n", err)
		os.Exit(1)
	}

	// Initialize Repositories: Fleet, Vulnerability Findings, Compliance Controls, Drift Events, and Auth
	repo := repository.NewRepository()
	findingRepo := vulnscan.NewMemoryFindingRepository()
	compRepo := compliance.NewMemoryComplianceRepository()
	driftRepo := drift.NewMemoryDriftRepository()
	authRepo := auth.NewMemoryAuthRepository()

	// -------------------------------------------------------------------------
	// CLI Flag: One-time Production Readiness Audit
	// -------------------------------------------------------------------------
	for _, arg := range os.Args[1:] {
		if arg == "--readiness-check" || arg == "-readiness-check" {
			report := readiness.EvaluateProductionReadiness(repo, authRepo, cfg)
			fmt.Println("==========================================================================")
			fmt.Println(" ZeroAgent-Scan / EndpointGuard EMS — Production Readiness Audit Report")
			fmt.Println("==========================================================================")
			fmt.Printf(" • Environment:     %s\n", report.Environment)
			fmt.Printf(" • Overall Verdict: %s\n", report.OverallVerdict)
			fmt.Printf(" • Checks Passed:   %d/%d\n", report.PassedCount, report.TotalChecks)
			fmt.Printf(" • Checks Failed:   %d\n", report.FailedCount)
			fmt.Printf(" • Warnings:        %d\n", report.WarningCount)
			fmt.Println("--------------------------------------------------------------------------")
			for _, c := range report.Checks {
				badge := "[PASS]"
				if c.Status == "FAIL" {
					badge = "[FAIL]"
				} else if c.Status == "WARN" {
					badge = "[WARN]"
				}
				fmt.Printf(" %s %s: %s\n", badge, c.Name, c.Message)
				if c.Status != "PASS" && c.Remediation != "" {
					fmt.Printf("        Remediation: %s\n", c.Remediation)
				}
			}
			fmt.Println("==========================================================================")
			if report.OverallVerdict == "PASS" {
				os.Exit(0)
			}
			os.Exit(1)
		}
	}

	// -------------------------------------------------------------------------
	// Production Boot Guard: Strictly reject startup if demo data is detected
	// -------------------------------------------------------------------------
	if strings.EqualFold(cfg.Environment, "production") || strings.EqualFold(os.Getenv("NODE_ENV"), "production") {
		if err := readiness.VerifyNoDemoDataInProduction(repo); err != nil {
			fmt.Fprintf(os.Stderr, "\n==========================================================================\n")
			fmt.Fprintf(os.Stderr, " ❌ [FATAL SECURITY ERROR] PRODUCTION STARTUP ABORTED!\n")
			fmt.Fprintf(os.Stderr, "==========================================================================\n")
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			fmt.Fprintf(os.Stderr, "==========================================================================\n\n")
			os.Exit(1)
		}
	}

	// Initialize Token Service, OIDC, & Rate Limiter
	tokenService := auth.NewTokenService("enterprise-endpointguard-master-jwt-secret-key-32b!", "endpointguard-api")
	oidcService := auth.NewOIDCService(auth.OIDCConfig{
		IssuerURL:   "https://login.microsoftonline.com/common/v2.0",
		ClientID:    "endpointguard-client-id",
		RedirectURI: "https://endpointguard.local/api/v1/auth/oidc/callback",
	})
	rateLimiter := middleware.NewRateLimiter(60, 20) // 60 req/min, burst 20

	// Initialize & Start VulnScan Background Worker
	vulnWorker := vulnscan.NewVulnScanWorker(vulnscan.WorkerConfig{
		NVDAPIKey:      "",
		NVDBaseURL:     vulnscan.DefaultNVDBaseURL,
		CISAKEVURL:     vulnscan.DefaultCISAKEVURL,
		SyncInterval:   24 * time.Hour,
		EnableAutoSync: false,
	}, findingRepo, nil, nil)

	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	_ = vulnWorker.Start(workerCtx)
	defer vulnWorker.Stop()

	// Wire audit callback: every secret resolution writes to the security audit log
	auditFn := func(entry vault.SecretResolutionAuditEntry) error {
		repo.AddAuditLog(repository.AuditLogFromVaultEntry(entry))
		return nil
	}

	vaultManager := vault.NewVaultManager(envelopeProvider, auditFn)
	apiHandler := handlers.NewAPIHandler(repo, vaultManager, findingRepo, compRepo, driftRepo)
	apiHandler.SetAuthConfig(authRepo, cfg)
	authHandler := handlers.NewAuthHandler(authRepo, tokenService, oidcService)

	// Build Chi Router (Net/HTTP Idiomatic, OWASP ASVS compliant)
	r := chi.NewRouter()

	// Base Chi Middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.StructuredLoggingMiddleware(cfg.ServiceName))
	r.Use(middleware.SecurityHeadersMiddleware)
	r.Use(telemetry.LatencyMiddleware)

	// Strict CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID", "X-Request-ID", "X-Tenant-ID", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link", "X-Correlation-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Standard Prometheus Scrape Endpoint
	r.Get("/metrics", telemetry.GetRegistry().MetricsHandler())

	// API Routes V1
	r.Route("/api/v1", func(api chi.Router) {
		// Public Docs & Schema
		api.Get("/openapi.json", openapi.ServeOpenAPIJSON)
		api.Get("/docs", openapi.ServeSwaggerUI)

		// Health & Metrics
		api.Get("/health", apiHandler.HealthCheck)
		api.Get("/metrics", apiHandler.GetFleetMetrics)

		// Authentication Endpoints (OIDC, Break-Glass Password, TOTP MFA, Refresh)
		api.Route("/auth", func(a chi.Router) {
			a.Post("/login", authHandler.Login)
			a.Post("/mfa/verify", authHandler.VerifyMFA)
			a.Post("/refresh", authHandler.RefreshSession)
			a.Get("/oidc/login", authHandler.OIDCLogin)
			a.Post("/oidc/callback", authHandler.OIDCCallback)

			a.Group(func(authGroup chi.Router) {
				authGroup.Use(auth.OptionalAuth(tokenService, "tenant-default-01"))
				authGroup.Post("/step-up", authHandler.StepUpAuth)
			})
		})

		// SCIM 2.0 Identity Provider Provisioning API
		api.Route("/scim/v2", func(scim chi.Router) {
			scim.Use(auth.OptionalAuth(tokenService, "tenant-default-01"))
			scim.Get("/ServiceProviderConfig", authHandler.SCIMServiceProviderConfig)
			scim.Get("/Users", authHandler.SCIMListUsers)
			scim.Post("/Users", authHandler.SCIMCreateUser)
			scim.Get("/Users/{id}", authHandler.SCIMGetUser)
			scim.Delete("/Users/{id}", authHandler.SCIMDeprovisionUser)
			scim.Patch("/Users/{id}", authHandler.SCIMDeprovisionUser)
		})

		// Protected Subsystem APIs (with RBAC, Tenant Isolation, CSRF, and Step-Up Guards)
		api.Group(func(protected chi.Router) {
			protected.Use(auth.OptionalAuth(tokenService, "tenant-default-01"))
			protected.Use(middleware.RateLimitMutatingMiddleware(rateLimiter))
			protected.Use(auth.CSRFProtectionMiddleware())

			// Endpoints & Hardware Inventory
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/endpoints", apiHandler.ListEndpoints)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/endpoints/pilot/summary", apiHandler.GetPilotHealthSummary)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/endpoints/{id}", apiHandler.GetEndpointByID)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Post("/endpoints/rollout-tier/promote", apiHandler.PromoteEndpointsTier)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Post("/endpoints/rollout-tier/bulk-assign", apiHandler.BulkAssignEndpointsTier)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Post("/endpoints/{id}/rollout-tier", apiHandler.UpdateEndpointRolloutTier)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants), auth.RequireStepUp()).Delete("/endpoints/{id}", apiHandler.DeleteEndpoint)

			// Rollout Tier Settings for Scheduled Scans
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/admin/settings/rollout-tiers", apiHandler.GetRolloutSettings)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Put("/admin/settings/rollout-tiers", apiHandler.UpdateRolloutSettings)

			// Keyset Paginated Snapshots & Retention Management
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/snapshots", apiHandler.ListSnapshots)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/snapshots/{id}", apiHandler.GetSnapshotByID)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/admin/snapshots/retention/policy", apiHandler.GetSnapshotRetentionPolicy)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Put("/admin/snapshots/retention/policy", apiHandler.UpdateSnapshotRetentionPolicy)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Post("/admin/snapshots/retention/dry-run", apiHandler.DryRunSnapshotRetention)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants), auth.RequireStepUp()).Post("/admin/snapshots/retention/execute", apiHandler.ExecuteSnapshotRetention)

			// Agentless Scans
			protected.With(auth.RequirePermission(auth.PermissionTriggerScans)).Post("/scans", apiHandler.CreateScanJob)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/scans", apiHandler.ListScanJobs)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/scans/{id}", apiHandler.GetScanJobByID)
			protected.With(auth.RequirePermission(auth.PermissionCancelScans)).Post("/scans/{id}/cancel", apiHandler.CancelScanJob)

			// Subnet Collector Gateways
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/gateways", apiHandler.ListGateways)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Post("/gateways/register", apiHandler.RegisterGateway)
			protected.With(auth.RequirePermission(auth.PermissionManageTenants)).Post("/gateways/{id}/approve", apiHandler.ApproveGateway)
			protected.Post("/gateways/heartbeat", apiHandler.GatewayHeartbeat)

			// Dedicated Credential Vault (Zero Plaintext Persistence + Step-Up Auth Guard)
			protected.With(auth.RequirePermission(auth.PermissionManageCredentials)).Get("/vault/credentials", apiHandler.ListVaultCredentials)
			protected.With(auth.RequirePermission(auth.PermissionManageCredentials), auth.RequireStepUp()).Post("/vault/credentials", apiHandler.CreateVaultCredential)
			protected.With(auth.RequirePermission(auth.PermissionManageCredentials), auth.RequireStepUp()).Post("/vault/credentials/{id}/rotate", apiHandler.RotateVaultCredential)
			protected.With(auth.RequirePermission(auth.PermissionManageCredentials)).Post("/vault/credentials/{id}/test", apiHandler.TestVaultCredential)

			// Vulnerability Findings (NVD CVE + CISA KEV Prioritized)
			protected.With(auth.RequirePermission(auth.PermissionReadFindings)).Get("/findings", apiHandler.ListVulnerabilityFindings)
			protected.With(auth.RequirePermission(auth.PermissionReadFindings)).Get("/findings/{id}", apiHandler.GetVulnerabilityFindingByID)

			// Compliance Frameworks, Rules, and Evaluations (CIS Benchmarks)
			protected.With(auth.RequirePermission(auth.PermissionReadCompliance)).Get("/compliance/frameworks", apiHandler.ListComplianceFrameworks)
			protected.With(auth.RequirePermission(auth.PermissionReadCompliance)).Get("/compliance/frameworks/{code}/rules", apiHandler.ListComplianceRules)
			protected.With(auth.RequirePermission(auth.PermissionReadCompliance)).Get("/compliance/hosts/{host_id}/results", apiHandler.GetHostComplianceResults)
			protected.With(auth.RequirePermission(auth.PermissionReadCompliance)).Get("/compliance/tenant/summary", apiHandler.GetTenantComplianceSummary)
			protected.With(auth.RequirePermission(auth.PermissionManageCredentials), auth.RequireStepUp()).Post("/compliance/policies/{id}/disable", apiHandler.DisablePolicyEnforcement)

			// Configuration Drift & Rule-Based Webhook Alerts
			protected.With(auth.RequirePermission(auth.PermissionReadDrift)).Get("/drift/events", apiHandler.ListDriftEvents)
			protected.With(auth.RequirePermission(auth.PermissionAcknowledgeDrift)).Post("/drift/events/{id}/acknowledge", apiHandler.AcknowledgeDriftEvent)
			protected.With(auth.RequirePermission(auth.PermissionManageAlerts)).Get("/alerts/rules", apiHandler.ListAlertRules)
			protected.With(auth.RequirePermission(auth.PermissionManageAlerts)).Post("/alerts/rules", apiHandler.CreateAlertRule)
			protected.With(auth.RequirePermission(auth.PermissionManageAlerts)).Get("/alerts/deliveries", apiHandler.ListWebhookDeliveryLogs)
			protected.With(auth.RequirePermission(auth.PermissionManageAlerts)).Post("/admin/health/test-alert", apiHandler.SendTestAlert)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/admin/health/status", apiHandler.GetAlertHealthStatus)
			protected.With(auth.RequirePermission(auth.PermissionReadTelemetry)).Get("/admin/readiness", apiHandler.GetProductionReadiness)

			// Executive & Compliance Reports
			protected.With(auth.RequirePermission(auth.PermissionGenerateReports)).Post("/reports", apiHandler.GenerateReport)

			// OWASP ASVS Audit Logs (Auditor/Admin/SuperAdmin only)
			protected.With(auth.RequirePermission(auth.PermissionReadAuditLogs)).Get("/audit-logs", apiHandler.ListAuditLogs)
		})
	})

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful Shutdown Channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		middleware.LogJSON("info", "bootstrap", cfg.ServiceName, fmt.Sprintf("Server listening at http://%s:%s", cfg.Host, cfg.Port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			middleware.LogJSON("error", "bootstrap", cfg.ServiceName, fmt.Sprintf("Server error: %v", err))
			os.Exit(1)
		}
	}()

	<-stop
	middleware.LogJSON("info", "shutdown", cfg.ServiceName, "Shutting down server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		middleware.LogJSON("error", "shutdown", cfg.ServiceName, fmt.Sprintf("Forced shutdown error: %v", err))
	} else {
		middleware.LogJSON("info", "shutdown", cfg.ServiceName, "Server stopped gracefully.")
	}
}
