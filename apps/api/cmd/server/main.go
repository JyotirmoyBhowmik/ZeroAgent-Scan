package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/compliance"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/config"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/drift"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/handlers"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vault"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/vulnscan"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal configuration error: %v\n", err)
		os.Exit(1)
	}

	middleware.LogJSON("info", "bootstrap", cfg.ServiceName, fmt.Sprintf("Starting EndpointGuard API on port %s (env: %s)", cfg.Port, cfg.Environment))

	// Initialize Vault Backend (Envelope Encryption fallback for local dev)
	envelopeProvider, err := vault.NewEnvelopeProvider(cfg.VaultMasterKey)
	if err != nil {
		middleware.LogJSON("error", "bootstrap", cfg.ServiceName, fmt.Sprintf("Failed to initialize Credential Vault envelope provider: %v", err))
		os.Exit(1)
	}

	// Initialize Repositories: Fleet, Vulnerability Findings, Compliance Controls, and Drift Events
	repo := repository.NewRepository()
	findingRepo := vulnscan.NewMemoryFindingRepository()
	compRepo := compliance.NewMemoryComplianceRepository()
	driftRepo := drift.NewMemoryDriftRepository()

	// Initialize & Start VulnScan Background Worker
	vulnWorker := vulnscan.NewVulnScanWorker(vulnscan.WorkerConfig{
		NVDAPIKey:      "",
		NVDBaseURL:     vulnscan.DefaultNVDBaseURL,
		CISAKEVURL:     vulnscan.DefaultCISAKEVURL,
		SyncInterval:   24 * time.Hour,
		EnableAutoSync: false, // On-demand and scheduled in background
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

	// Build Chi Router (Net/HTTP Idiomatic, OWASP ASVS compliant)
	r := chi.NewRouter()

	// Base Chi Middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.StructuredLoggingMiddleware(cfg.ServiceName))
	r.Use(middleware.SecurityHeadersMiddleware)

	// Strict CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID", "X-Request-ID", "X-Tenant-ID"},
		ExposedHeaders:   []string{"Link", "X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// API Routes V1
	r.Route("/api/v1", func(api chi.Router) {
		api.Get("/health", apiHandler.HealthCheck)
		api.Get("/metrics", apiHandler.GetFleetMetrics)

		// Endpoints & Hardware Inventory
		api.Get("/endpoints", apiHandler.ListEndpoints)
		api.Get("/endpoints/{id}", apiHandler.GetEndpointByID)

		// Agentless Scans
		api.Post("/scans", apiHandler.CreateScanJob)
		api.Get("/scans", apiHandler.ListScanJobs)
		api.Get("/scans/{id}", apiHandler.GetScanJobByID)

		// Subnet Collector Gateways
		api.Get("/gateways", apiHandler.ListGateways)
		api.Post("/gateways/heartbeat", apiHandler.GatewayHeartbeat)

		// Dedicated Credential Vault (Zero Plaintext)
		api.Get("/vault/credentials", apiHandler.ListVaultCredentials)
		api.Post("/vault/credentials", apiHandler.CreateVaultCredential)

		// Vulnerability Findings (NVD CVE + CISA KEV Prioritized)
		api.Get("/findings", apiHandler.ListVulnerabilityFindings)
		api.Get("/findings/{id}", apiHandler.GetVulnerabilityFindingByID)

		// Compliance Frameworks, Rules, and Evaluations (CIS Benchmarks)
		api.Get("/compliance/frameworks", apiHandler.ListComplianceFrameworks)
		api.Get("/compliance/frameworks/{code}/rules", apiHandler.ListComplianceRules)
		api.Get("/compliance/hosts/{host_id}/results", apiHandler.GetHostComplianceResults)
		api.Get("/compliance/tenant/summary", apiHandler.GetTenantComplianceSummary)

		// Configuration Drift & Rule-Based Webhook Alerts
		api.Get("/drift/events", apiHandler.ListDriftEvents)
		api.Post("/drift/events/{id}/acknowledge", apiHandler.AcknowledgeDriftEvent)
		api.Get("/alerts/rules", apiHandler.ListAlertRules)
		api.Post("/alerts/rules", apiHandler.CreateAlertRule)
		api.Get("/alerts/deliveries", apiHandler.ListWebhookDeliveryLogs)

		// OWASP ASVS Audit Logs
		api.Get("/audit-logs", apiHandler.ListAuditLogs)
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
		middleware.LogJSON("info", "shutdown", cfg.ServiceName, "Server gracefully stopped.")
	}
}
