package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// GatewayConfig encapsulates all operational settings for the Subnet Collector Gateway.
type GatewayConfig struct {
	// GatewayID is the unique identifier for this gateway instance.
	GatewayID string `json:"gateway_id"`

	// SubnetCIDR is the primary managed subnet (e.g. "10.100.1.0/24").
	SubnetCIDR string `json:"subnet_cidr"`

	// ManagedSubnets is a list of all CIDR subnets managed by this gateway.
	ManagedSubnets []string `json:"managed_subnets"`

	// ControlPlaneURL is the base URL for the Central API (e.g. "https://api.endpointguard.internal:8080").
	ControlPlaneURL string `json:"control_plane_url"`

	// HeartbeatInterval is the cadence for emitting status heartbeats (default: 60s).
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`

	// ProbeTimeout is the maximum duration for a single host CIM/WMI scan probe (default: 30s).
	ProbeTimeout time.Duration `json:"probe_timeout"`

	// MaxConcurrentSessions defines the maximum simultaneous WinRM/SSH sessions per subnet (default: 20).
	MaxConcurrentSessions int `json:"max_concurrent_sessions"`

	// AllowInsecureHTTP permits fallback to unencrypted WinRM (port 5985) when true.
	// Default is false — WinRM over HTTPS (port 5986) is strictly enforced.
	// When true, all unencrypted connections generate high-severity compliance exception audits.
	AllowInsecureHTTP bool `json:"allow_insecure_http"`

	// CertDir is the directory path where mTLS certificates and keys are stored.
	CertDir string `json:"cert_dir"`

	// UpdatePublicKeyHex is the Ed25519 public key (in hex) used to verify self-update binaries.
	UpdatePublicKeyHex string `json:"update_public_key_hex"`

	// PollMinInterval is the base polling interval for job queue (default: 2s).
	PollMinInterval time.Duration `json:"poll_min_interval"`

	// PollMaxInterval is the maximum polling interval with exponential backoff (default: 30s).
	PollMaxInterval time.Duration `json:"poll_max_interval"`
}

// LoadConfig loads and validates gateway configuration from environment variables.
func LoadConfig() (*GatewayConfig, error) {
	gatewayID := getEnv("GATEWAY_ID", "gw-subnet-10-100-1-0")
	if strings.TrimSpace(gatewayID) == "" {
		return nil, fmt.Errorf("config: GATEWAY_ID must not be empty")
	}

	subnetCIDR := getEnv("SUBNET_CIDR", "10.100.1.0/24")
	if _, _, err := net.ParseCIDR(subnetCIDR); err != nil {
		return nil, fmt.Errorf("config: invalid SUBNET_CIDR %q: %w", subnetCIDR, err)
	}

	rawSubnets := getEnv("MANAGED_SUBNETS", subnetCIDR)
	var managedSubnets []string
	for _, s := range strings.Split(rawSubnets, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return nil, fmt.Errorf("config: invalid managed subnet %q: %w", s, err)
			}
			managedSubnets = append(managedSubnets, s)
		}
	}
	if len(managedSubnets) == 0 {
		managedSubnets = []string{subnetCIDR}
	}

	controlPlaneURL := strings.TrimRight(getEnv("CONTROL_PLANE_URL", "http://localhost:8080"), "/")
	if controlPlaneURL == "" {
		return nil, fmt.Errorf("config: CONTROL_PLANE_URL must not be empty")
	}

	heartbeatSec, _ := strconv.Atoi(getEnv("HEARTBEAT_INTERVAL_SEC", "60"))
	if heartbeatSec <= 0 {
		heartbeatSec = 60
	}

	probeTimeoutSec, _ := strconv.Atoi(getEnv("SCAN_PROBE_TIMEOUT_SEC", "30"))
	if probeTimeoutSec <= 0 {
		probeTimeoutSec = 30
	}

	maxConcurrent, _ := strconv.Atoi(getEnv("MAX_CONCURRENT_SESSIONS", "20"))
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}

	allowInsecureHTTP := strings.EqualFold(getEnv("ALLOW_INSECURE_HTTP", "false"), "true")
	certDir := getEnv("GATEWAY_CERT_DIR", "./certs")
	updatePubKey := getEnv("UPDATE_PUBLIC_KEY_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	pollMinSec, _ := strconv.Atoi(getEnv("POLL_MIN_INTERVAL_SEC", "2"))
	if pollMinSec <= 0 {
		pollMinSec = 2
	}

	pollMaxSec, _ := strconv.Atoi(getEnv("POLL_MAX_INTERVAL_SEC", "30"))
	if pollMaxSec <= pollMinSec {
		pollMaxSec = 30
	}

	return &GatewayConfig{
		GatewayID:             gatewayID,
		SubnetCIDR:            subnetCIDR,
		ManagedSubnets:        managedSubnets,
		ControlPlaneURL:       controlPlaneURL,
		HeartbeatInterval:     time.Duration(heartbeatSec) * time.Second,
		ProbeTimeout:          time.Duration(probeTimeoutSec) * time.Second,
		MaxConcurrentSessions: maxConcurrent,
		AllowInsecureHTTP:     allowInsecureHTTP,
		CertDir:               certDir,
		UpdatePublicKeyHex:    updatePubKey,
		PollMinInterval:       time.Duration(pollMinSec) * time.Second,
		PollMaxInterval:       time.Duration(pollMaxSec) * time.Second,
	}, nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}
