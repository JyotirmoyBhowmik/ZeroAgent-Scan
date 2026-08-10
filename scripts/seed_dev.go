package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	// -------------------------------------------------------------------------
	// Production Environment Gate: Strictly refuse execution in production
	// -------------------------------------------------------------------------
	nodeEnv := os.Getenv("NODE_ENV")
	appEnv := os.Getenv("ENVIRONMENT")
	zeroEnv := os.Getenv("ZEROAGENT_ENV")

	if strings.EqualFold(nodeEnv, "production") || strings.EqualFold(appEnv, "production") || strings.EqualFold(zeroEnv, "production") {
		fmt.Println("\n==========================================================================")
		fmt.Println(" ❌ [FATAL SECURITY ERROR] DATABASE SEEDING REJECTED!")
		fmt.Println("==========================================================================")
		fmt.Printf(" • Detected production environment flag:\n")
		if strings.EqualFold(nodeEnv, "production") {
			fmt.Printf("   - NODE_ENV=%s\n", nodeEnv)
		}
		if strings.EqualFold(appEnv, "production") {
			fmt.Printf("   - ENVIRONMENT=%s\n", appEnv)
		}
		if strings.EqualFold(zeroEnv, "production") {
			fmt.Printf("   - ZEROAGENT_ENV=%s\n", zeroEnv)
		}
		fmt.Println(" • Safety Policy Violation: Demo and seed mock data can NEVER be inserted")
		fmt.Println("   into a production database deployment.")
		fmt.Println(" • Aborting execution immediately with exit code 1.")
		fmt.Println("==========================================================================\n")
		os.Exit(1)
	}

	fmt.Println("==========================================================================")
	fmt.Println(" ZeroAgent-Scan / EndpointGuard EMS — Local Dev Database Seeder")
	fmt.Println("==========================================================================")

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://endpointguard_app:endpointguard_secure_dev_password_change_in_prod@localhost:5432/endpointguard?sslmode=disable"
	}

	initPath := findFile("packages/db/init-all.sql")
	seedPath := findFile("packages/db/seed-dev.sql")

	// 1. Try applying via psql if available locally
	psqlPath, err := exec.LookPath("psql")
	if err == nil && initPath != "" && seedPath != "" {
		fmt.Printf("[INFO] Using local psql client: %s\n", psqlPath)
		fmt.Printf("[INFO] Executing schema migrations from '%s'...\n", initPath)
		cmdInit := exec.Command(psqlPath, "-d", dbURL, "-f", initPath)
		cmdInit.Stdout = os.Stdout
		cmdInit.Stderr = os.Stderr
		_ = cmdInit.Run()

		fmt.Printf("[INFO] Executing RFC 5737 mock fleet seed data from '%s'...\n", seedPath)
		cmdSeed := exec.Command(psqlPath, "-d", dbURL, "-f", seedPath)
		cmdSeed.Stdout = os.Stdout
		cmdSeed.Stderr = os.Stderr
		if err := cmdSeed.Run(); err == nil {
			fmt.Println("[OK] Seed data successfully applied via psql.")
		}
	} else {
		// 2. Try applying via Docker container if running
		dockerPath, err := exec.LookPath("docker")
		if err == nil {
			fmt.Println("[INFO] Checking for running Docker PostgreSQL container (zeroagent-dev-postgres)...")
			cmdDocker := exec.Command(dockerPath, "exec", "-i", "zeroagent-dev-postgres", "psql", "-U", "endpointguard_app", "-d", "endpointguard", "-f", "/docker-entrypoint-initdb.d/02_seed_dev_data.sql")
			if out, err := cmdDocker.CombinedOutput(); err == nil {
				fmt.Printf("[OK] Seed data applied inside Docker container: %s\n", string(out))
			}
		}
	}

	printSeedSummary()
}

func findFile(relPath string) string {
	candidates := []string{
		relPath,
		filepath.Join("..", relPath),
		filepath.Join("..", "..", relPath),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func printSeedSummary() {
	fmt.Println("\n==========================================================================")
	fmt.Println(" 🚀 Seed Data Summary — Ready for Local Exploration")
	fmt.Println("==========================================================================")
	fmt.Println(" • Target Subnets (RFC 5737 Documentation Ranges):")
	fmt.Println("   - 192.0.2.0/24   (TEST-NET-1: Pilot Workstations DEMO-WKS-001..008)")
	fmt.Println("   - 198.51.100.0/24 (TEST-NET-2: Staged Workstations DEMO-WKS-009..015)")
	fmt.Println("   - 203.0.113.0/24  (TEST-NET-3: Full Fleet Servers DEMO-SRV-001..010)")
	fmt.Println(" • Total Mock Endpoints: 30 Hosts (20 Workstations, 10 Servers)")
	fmt.Println(" • Compliance Distribution: 18 Compliant, 8 Partial, 4 Failed")
	fmt.Println(" • CISA KEV Vulnerabilities Seeded:")
	fmt.Println("   - CVE-2023-34362 (Progress MOVEit Transfer SQLi / RCE) [CRITICAL, KEV]")
	fmt.Println("   - CVE-2024-21413 (Microsoft Outlook Moniker Link RCE) [CRITICAL, KEV]")
	fmt.Println("   - CVE-2023-23397 (Microsoft Outlook NTLM Relay) [HIGH, KEV]")
	fmt.Println("   - CVE-2024-30051 (Windows DWM Core Library EoP) [HIGH, KEV]")
	fmt.Println(" • Compliance Frameworks: CIS Win11 v3.0, CIS WS2022 v2.0, NIST 800-53 r5, HIPAA, PCI-DSS v4.0")
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Println(" 🔑 Default Login Credentials for Seeded Roles:")
	fmt.Println("   ┌──────────────┬───────────────────────────────┬───────────────────────────────┐")
	fmt.Println("   │ Role         │ Username                      │ Password                      │")
	fmt.Println("   ├──────────────┼───────────────────────────────┼───────────────────────────────┤")
	fmt.Println("   │ Admin        │ admin@demo.local (or 'admin') │ AdminDevPass2026!             │")
	fmt.Println("   │ Operator     │ operator@demo.local           │ OperatorDevPass2026!          │")
	fmt.Println("   │ Auditor      │ auditor@demo.local            │ AuditorDevPass2026!           │")
	fmt.Println("   │ Viewer       │ viewer@demo.local             │ ViewerDevPass2026!            │")
	fmt.Println("   │ SuperAdmin   │ breakglass@endpointguard.local│ EmergencyBreakGlassPass2026!  │")
	fmt.Println("   └──────────────┴───────────────────────────────┴───────────────────────────────┘")
	fmt.Println("==========================================================================\n")
}
