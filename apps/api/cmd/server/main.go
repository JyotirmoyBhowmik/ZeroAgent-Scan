package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/endpointguard/endpointguard/apps/api/internal/config"
	"github.com/endpointguard/endpointguard/apps/api/internal/handlers"
	"github.com/endpointguard/endpointguard/apps/api/internal/middleware"
	"github.com/endpointguard/endpointguard/apps/api/internal/repository"
	"github.com/endpointguard/endpointguard/apps/api/internal/vault"
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

	// Initialize Vault Service
	vaultService, err := vault.NewVaultService(cfg.VaultMasterKey)
	if err != nil {
		middleware.LogJSON("error", "bootstrap", cfg.ServiceName, fmt.Sprintf("Failed to initialize Credential Vault: %v", err))
		os.Exit(1)
	}

	// Initialize Repository
	repo := repository.NewRepository()
	apiHandler := handlers.NewAPIHandler(repo, vaultService)

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
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Correlation-ID", "X-Request-ID"},
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
