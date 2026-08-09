package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/endpointguard/endpointguard/apps/gateway/internal/collector"
)

func main() {
	gatewayID := getEnv("GATEWAY_ID", "gw-subnet-10-100-1-0")
	subnetCIDR := getEnv("SUBNET_CIDR", "10.100.1.0/24")
	controlPlaneURL := getEnv("CONTROL_PLANE_URL", "http://localhost:8080")
	heartbeatInterval, _ := strconv.Atoi(getEnv("HEARTBEAT_INTERVAL_SEC", "10"))
	probeTimeout, _ := strconv.Atoi(getEnv("SCAN_PROBE_TIMEOUT_SEC", "30"))

	fmt.Printf("[INFO] Starting EndpointGuard Subnet Collector Gateway (ID: %s, Subnet: %s)\n", gatewayID, subnetCIDR)
	fmt.Printf("[INFO] Connecting to Central Control Plane at: %s\n", controlPlaneURL)

	cfg := collector.GatewayConfig{
		GatewayID:            gatewayID,
		SubnetCIDR:           subnetCIDR,
		ControlPlaneURL:      controlPlaneURL,
		HeartbeatIntervalSec: heartbeatInterval,
		ProbeTimeoutSec:      probeTimeout,
	}

	daemon := collector.NewGatewayDaemon(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch heartbeat loop
	go daemon.Start(ctx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	fmt.Println("[INFO] Subnet Collector Gateway shutting down...")
	daemon.Stop()
	time.Sleep(500 * time.Millisecond)
	fmt.Println("[INFO] Gateway stopped cleanly.")
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}
