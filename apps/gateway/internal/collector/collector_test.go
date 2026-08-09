package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGatewayDaemon_SendHeartbeat(t *testing.T) {
	heartbeatReceived := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/gateways/heartbeat" && r.Method == http.MethodPost {
			heartbeatReceived = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"acknowledged"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := GatewayConfig{
		GatewayID:            "gw-test-subnet",
		SubnetCIDR:           "10.100.1.0/24",
		ControlPlaneURL:      server.URL,
		HeartbeatIntervalSec: 1,
		ProbeTimeoutSec:      5,
	}

	daemon := NewGatewayDaemon(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := daemon.SendHeartbeat(ctx)
	if err != nil {
		t.Fatalf("expected successful heartbeat, got error: %v", err)
	}

	if !heartbeatReceived {
		t.Fatalf("expected server to receive heartbeat")
	}
}
