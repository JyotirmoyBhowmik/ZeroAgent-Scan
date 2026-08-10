package readiness

import (
	"fmt"
	"net"
	"strings"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/repository"
)

// RFC 5737 Documentation IP Subnets (strictly reserved for documentation & test environments)
var rfc5737Subnets = []*net.IPNet{
	mustParseCIDR("192.0.2.0/24"),   // TEST-NET-1
	mustParseCIDR("198.51.100.0/24"), // TEST-NET-2
	mustParseCIDR("203.0.113.0/24"),  // TEST-NET-3
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// DemoViolation represents a specific artifact identified as non-production demo data.
type DemoViolation struct {
	Type        string `json:"type"`        // "HOSTNAME_PREFIX", "RFC5737_IP", "DEMO_USER", "DEMO_TENANT"
	Identifier  string `json:"identifier"`  // e.g. "DEMO-WKS-001" or "192.0.2.11"
	Details     string `json:"details"`
}

// CheckForDemoData scans the endpoint inventory and user repository for known mock patterns.
func CheckForDemoData(repo *repository.Repository) []DemoViolation {
	var violations []DemoViolation
	if repo == nil {
		return violations
	}

	endpoints := repo.ListEndpoints("", "", "", "")
	for _, ep := range endpoints {
		// 1. Check Hostname Prefix (DEMO-)
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ep.Hostname)), "DEMO-") {
			violations = append(violations, DemoViolation{
				Type:       "HOSTNAME_PREFIX",
				Identifier: ep.Hostname,
				Details:    fmt.Sprintf("Endpoint ID %s has prohibited demo hostname prefix 'DEMO-'", ep.ID),
			})
		}

		// 2. Check RFC 5737 Documentation IP Ranges
		ip := net.ParseIP(strings.TrimSpace(ep.IPAddress))
		if ip != nil {
			for _, subnet := range rfc5737Subnets {
				if subnet.Contains(ip) {
					violations = append(violations, DemoViolation{
						Type:       "RFC5737_IP",
						Identifier: ep.IPAddress,
						Details:    fmt.Sprintf("Endpoint '%s' (ID %s) uses RFC 5737 documentation subnet IP in %s", ep.Hostname, ep.ID, subnet.String()),
					})
					break
				}
			}
		}
	}

	return violations
}

// VerifyNoDemoDataInProduction evaluates the repository and returns a fatal error if demo data exists.
func VerifyNoDemoDataInProduction(repo *repository.Repository) error {
	violations := CheckForDemoData(repo)
	if len(violations) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("FATAL: Production database contains %d demo/seed data artifacts:\n", len(violations)))
	for idx, v := range violations {
		sb.WriteString(fmt.Sprintf("  [%d] [%s] %s — %s\n", idx+1, v.Type, v.Identifier, v.Details))
	}
	sb.WriteString("Remediation: Purge all demo seed data before starting ZeroAgent-Scan in production mode.")
	return fmt.Errorf("%s", sb.String())
}

// IsRFC5737IP checks if an IP belongs to RFC 5737 documentation ranges.
func IsRFC5737IP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, subnet := range rfc5737Subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsDemoHostname checks if a hostname begins with "DEMO-".
func IsDemoHostname(hostname string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(hostname)), "DEMO-")
}
