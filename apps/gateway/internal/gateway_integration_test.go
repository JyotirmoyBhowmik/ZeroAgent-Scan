package internal_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/heartbeat"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/mtls"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/poller"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/scanner"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/streamer"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/gateway/internal/updater"
)

// ===========================================================================
// Test 1: mTLS Enrollment & First-Boot CSR Workflow (Zero Auto-Trust)
// ===========================================================================

func TestGateway_EnrollmentCSRFlow(t *testing.T) {
	approved := false
	var registeredCSR string

	// Generate Test CA
	caCert, caKey, caPEM, _ := generateTestCA(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/gateways/register":
			var req mtls.RegistrationRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			registeredCSR = req.CSRPEM

			resp := mtls.RegistrationResponse{
				GatewayID:   req.GatewayID,
				Status:      "pending_approval", // Operator must approve in dashboard
				Fingerprint: "SHA256:testfingerprint123456",
				Message:     "Registration received. Awaiting security operator approval.",
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(resp)

		case "/api/v1/gateways/gw-test-01/cert":
			if !approved {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Sign client cert from CSR
			clientCertPEM := signCSRWithCA(t, registeredCSR, caCert, caKey)
			resp := mtls.RegistrationResponse{
				GatewayID:        "gw-test-01",
				Status:           "approved",
				CertificatePEM:   clientCertPEM,
				CACertificatePEM: caPEM,
			}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	enrollMgr := mtls.NewEnrollmentManager("gw-test-01", "10.100.1.0/24", server.URL, tempDir, server.Client())

	// Step 1: Submit Registration
	regResp, err := enrollMgr.RegisterAndEnroll(context.Background())
	if err != nil {
		t.Fatalf("RegisterAndEnroll failed: %v", err)
	}
	if regResp.Status != "pending_approval" {
		t.Fatalf("expected status pending_approval, got %s", regResp.Status)
	}

	// Step 2: Poll before approval -> should return pending error
	_, err = enrollMgr.PollCertificateApproval(context.Background(), "")
	if err != mtls.ErrEnrollmentPending {
		t.Fatalf("expected ErrEnrollmentPending, got %v", err)
	}

	// Step 3: Operator approves CSR in dashboard
	approved = true

	// Step 4: Poll after approval -> should install certs
	approvedResp, err := enrollMgr.PollCertificateApproval(context.Background(), "")
	if err != nil {
		t.Fatalf("PollCertificateApproval after approval failed: %v", err)
	}
	if approvedResp.Status != "approved" {
		t.Fatalf("expected status approved, got %s", approvedResp.Status)
	}

	// Step 5: Verify TLS config can be built
	tlsConfig, err := enrollMgr.BuildTLSClientConfig()
	if err != nil {
		t.Fatalf("BuildTLSClientConfig failed: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 minimum version, got %x", tlsConfig.MinVersion)
	}
}

// ===========================================================================
// Test 2: Poller Exponential Backoff with Jitter
// ===========================================================================

func TestGateway_PollerBackoffAndJitter(t *testing.T) {
	hasJobs := false
	pollCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pollCount++
		if !hasJobs {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		jobs := []poller.ScanJobDescriptor{
			{
				ID:          "job-test-01",
				Name:        "Test Subnet Scan",
				TargetCIDR:  "10.100.1.0/24",
				ScanProfile: "rapid_inventory",
				Protocol:    "winrm_https",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jobs)
	}))
	defer server.Close()

	p := poller.NewPoller(
		"gw-test-01",
		[]string{"10.100.1.0/24"},
		server.URL,
		10*time.Millisecond,
		100*time.Millisecond,
		server.Client(),
	)

	// Empty poll increases delay
	jobs, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce failed: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("expected 0 jobs, got %d", len(jobs))
	}

	delay1 := p.NextDelay()
	if delay1 < 10*time.Millisecond || delay1 > 100*time.Millisecond {
		t.Fatalf("delay1 %v out of bounds [10ms, 100ms]", delay1)
	}

	// Multiple empty polls backoff exponentially
	for i := 0; i < 5; i++ {
		_, _ = p.PollOnce(context.Background())
	}
	delayN := p.NextDelay()
	if delayN < 10*time.Millisecond {
		t.Fatalf("delayN too small: %v", delayN)
	}

	// Job received -> backoff resets
	hasJobs = true
	jobs2, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce with jobs failed: %v", err)
	}
	if len(jobs2) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs2))
	}

	delayReset := p.NextDelay()
	if delayReset > 50*time.Millisecond {
		t.Fatalf("expected backoff reset to near minInterval, got %v", delayReset)
	}
}

// ===========================================================================
// Test 3: WinRM over HTTPS (5986) Enforced & Unencrypted 5985 Refusal
// ===========================================================================

func TestGateway_WinRM_HTTPS_Enforced_And_InsecureRefusal(t *testing.T) {
	// Mock WinRM HTTPS Server
	mockWinRM := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"hostname":        "W11-FIN-01",
			"domain":          "CORP.LOCAL",
			"os_name":         "Microsoft Windows 11 Enterprise 23H2",
			"os_build":        "22631.3296",
			"manufacturer":    "Dell Inc.",
			"model":           "Latitude 7440",
			"serial_number":   "8XKJ9201",
			"mac_address":     "00:1A:2B:3C:4D:5E",
			"chassis_type":    "Laptop",
			"bitlocker_state": 1,
			"tpm_present":     true,
			"defender_active": true,
			"firewall_active": true,
		})
	}))
	defer mockWinRM.Close()

	hostPort := strings.TrimPrefix(mockWinRM.URL, "https://")
	parts := strings.Split(hostPort, ":")
	host := parts[0]
	var port int
	fmt.Sscanf(parts[1], "%d", &port)

	// Create root cert pool with mock server's cert
	rootPool := x509.NewCertPool()
	rootPool.AddCert(mockWinRM.Certificate())

	// Scanner with strict HTTPS enforcement (AllowInsecureHTTP=false)
	secureScanner := scanner.NewWinRMScanner(5*time.Second, rootPool, false)

	// Test 1: Successful HTTPS scan
	res, err := secureScanner.ScanEndpoint(context.Background(), scanner.EndpointScanTarget{
		IPAddress: host,
		Port:      port,
		Protocol:  "winrm_https",
		Username:  "admin",
	})
	if err != nil {
		t.Fatalf("HTTPS scan failed: %v", err)
	}
	if res.Status != "online" {
		t.Fatalf("expected status online, got %s", res.Status)
	}
	if res.ComplianceScore < 80.0 {
		t.Fatalf("expected high compliance score, got %.1f", res.ComplianceScore)
	}
	if len(res.ComplianceExceptions) != 0 {
		t.Fatalf("expected 0 compliance exceptions for HTTPS, got %d", len(res.ComplianceExceptions))
	}

	// Test 2: Unencrypted HTTP (5985) is REFUSED by default
	_, err = secureScanner.ScanEndpoint(context.Background(), scanner.EndpointScanTarget{
		IPAddress: "10.100.1.50",
		Port:      5985,
		Protocol:  "winrm_http",
	})
	if err != scanner.ErrWinRMInsecureRefused {
		t.Fatalf("expected ErrWinRMInsecureRefused, got %v", err)
	}

	// Test 3: Unencrypted HTTP allowed ONLY with explicit override flag AND logs compliance exception
	insecureScanner := scanner.NewWinRMScanner(5*time.Second, rootPool, true)

	// Mock unencrypted HTTP server
	mockHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"hostname": "LEGACY-W10-01",
			"os_name":  "Windows 10",
		})
	}))
	defer mockHTTP.Close()

	httpHostPort := strings.TrimPrefix(mockHTTP.URL, "http://")
	httpParts := strings.Split(httpHostPort, ":")
	var httpPort int
	fmt.Sscanf(httpParts[1], "%d", &httpPort)

	resInsecure, err := insecureScanner.ScanEndpoint(context.Background(), scanner.EndpointScanTarget{
		IPAddress:         httpParts[0],
		Port:              httpPort,
		Protocol:          "winrm_http",
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("Insecure scan with override failed: %v", err)
	}
	if len(resInsecure.ComplianceExceptions) == 0 {
		t.Fatalf("expected compliance exception to be logged for unencrypted 5985 WinRM")
	}
	if resInsecure.ComplianceExceptions[0].RuleID != "COMPLIANCE_EXCEPTION_WINRM_UNENCRYPTED_5985" {
		t.Fatalf("unexpected exception rule: %s", resInsecure.ComplianceExceptions[0].RuleID)
	}
}

// ===========================================================================
// Test 4: BMC Scanner (SSH Pinning & SNMPv3)
// ===========================================================================

func TestGateway_BMC_SSHPinning_And_SNMPv3(t *testing.T) {
	bmc := scanner.NewBMCScanner(5*time.Second, nil)

	// Test 1: SSH connection without pinned host key is rejected
	_, err := bmc.ScanSSH(context.Background(), scanner.EndpointScanTarget{
		IPAddress: "10.100.2.10",
		Port:      22,
		Username:  "root",
	}, "")
	if !strings.Contains(err.Error(), "no pinned host key was provided") {
		t.Fatalf("expected unpinned host key error, got %v", err)
	}

	// Test 2: Legacy SNMPv1/v2c is strictly forbidden
	_, err = bmc.ScanSNMPv3(context.Background(), scanner.EndpointScanTarget{
		IPAddress: "10.100.2.10",
		Protocol:  "snmp_v2c",
	}, "", "", "")
	if err != scanner.ErrLegacySNMPForbidden {
		t.Fatalf("expected ErrLegacySNMPForbidden for SNMPv2c, got %v", err)
	}

	// Test 3: SNMPv3 AuthPriv succeeds
	snmpRes, err := bmc.ScanSNMPv3(context.Background(), scanner.EndpointScanTarget{
		IPAddress: "10.100.2.10",
		Protocol:  "snmp_v3",
	}, "authPriv", "SHA256", "AES256")
	if err != nil {
		t.Fatalf("SNMPv3 scan failed: %v", err)
	}
	if snmpRes.AgentlessProtocol != "snmp_v3_authpriv" {
		t.Fatalf("expected snmp_v3_authpriv, got %s", snmpRes.AgentlessProtocol)
	}
	if snmpRes.ComplianceScore != 100.0 {
		t.Fatalf("expected 100%% compliance, got %.1f", snmpRes.ComplianceScore)
	}
}

// ===========================================================================
// Test 5: Result Streamer with Gateway-Side SHA-256 Payload Hash
// ===========================================================================

func TestGateway_ResultStreamer_PayloadHash(t *testing.T) {
	var receivedHashHeader string
	var receivedPayload scanner.ScanBatchResult

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHashHeader = r.Header.Get("X-Payload-Hash")
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rs := streamer.NewResultStreamer(server.URL, "gw-test-01", server.Client())

	batch := &scanner.ScanBatchResult{
		ScanJobID:      "scan-job-hash-01",
		GatewayID:      "gw-test-01",
		TargetCIDR:     "10.100.1.0/24",
		TotalHosts:     1,
		ScannedHosts:   1,
		CompliantHosts: 1,
		Results: []scanner.EndpointScanResult{
			{
				EndpointID:      "host-01",
				Hostname:        "TEST-HOST",
				IPAddress:       "10.100.1.42",
				ComplianceScore: 95.0,
			},
		},
		CompletedAt: time.Now().UTC(),
	}

	computedHash, err := rs.StreamResults(context.Background(), batch)
	if err != nil {
		t.Fatalf("StreamResults failed: %v", err)
	}

	if computedHash == "" {
		t.Fatal("expected non-empty payload hash")
	}
	if receivedHashHeader != computedHash {
		t.Fatalf("header hash %s does not match computed hash %s", receivedHashHeader, computedHash)
	}
	if receivedPayload.PayloadHash != computedHash {
		t.Fatalf("body payload_hash %s does not match computed hash %s", receivedPayload.PayloadHash, computedHash)
	}
}

// ===========================================================================
// Test 6: 60-Second Heartbeat Daemon
// ===========================================================================

func TestGateway_Heartbeat(t *testing.T) {
	var receivedHeartbeats []heartbeat.HeartbeatPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hb heartbeat.HeartbeatPayload
		_ = json.NewDecoder(r.Body).Decode(&hb)
		receivedHeartbeats = append(receivedHeartbeats, hb)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	activeSessions := 3
	activeFn := func() int { return activeSessions }

	hb := heartbeat.NewDaemon(
		"gw-subnet-10-100-1-0",
		"10.100.1.0/24",
		server.URL,
		20*time.Millisecond, // fast cadence for test
		server.Client(),
		"v1.2.4",
		activeFn,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hb.Start(ctx)
	time.Sleep(70 * time.Millisecond)
	hb.Stop()

	if len(receivedHeartbeats) < 2 {
		t.Fatalf("expected at least 2 heartbeats, got %d", len(receivedHeartbeats))
	}
	first := receivedHeartbeats[0]
	if first.GatewayCode != "gw-subnet-10-100-1-0" {
		t.Fatalf("expected gateway code gw-subnet-10-100-1-0, got %s", first.GatewayCode)
	}
	if first.ActiveSessions != 3 {
		t.Fatalf("expected active sessions 3, got %d", first.ActiveSessions)
	}
}

// ===========================================================================
// Test 7: Ed25519 Cryptographically Verified Self-Update
// ===========================================================================

func TestGateway_SelfUpdate_Ed25519Signature(t *testing.T) {
	// Generate authentic Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	pubHex := hex.EncodeToString(pubKey)

	binaryData := []byte("#!/bin/sh\necho 'EndpointGuard Collector Gateway v1.3.0'\n")
	sum := sha256.Sum256(binaryData)
	shaHex := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(privKey, binaryData)
	sigHex := hex.EncodeToString(sig)

	// Mock binary download server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(binaryData)
	}))
	defer server.Close()

	engine, err := updater.NewUpdateEngine(pubHex, server.Client())
	if err != nil {
		t.Fatalf("NewUpdateEngine failed: %v", err)
	}

	targetPath := filepath.Join(t.TempDir(), "bin", "gateway")

	// Test 1: Authentic update succeeds
	manifest := updater.UpdateManifest{
		Version:      "v1.3.0",
		DownloadURL:  server.URL + "/gateway-v1.3.0",
		SHA256Hex:    shaHex,
		SignatureHex: sigHex,
	}

	if err := engine.ApplyUpdate(context.Background(), manifest, targetPath); err != nil {
		t.Fatalf("ApplyUpdate failed for valid signed binary: %v", err)
	}

	savedBytes, err := os.ReadFile(targetPath)
	if err != nil || !bytes.Equal(savedBytes, binaryData) {
		t.Fatalf("saved binary does not match update payload")
	}

	// Test 2: Tampered signature is REJECTED
	tamperedSigHex := hex.EncodeToString(make([]byte, 64))
	badManifest := updater.UpdateManifest{
		Version:      "v1.3.0-tampered",
		DownloadURL:  server.URL + "/gateway-tampered",
		SHA256Hex:    shaHex,
		SignatureHex: tamperedSigHex,
	}

	err = engine.ApplyUpdate(context.Background(), badManifest, targetPath)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature verification failure for tampered update, got %v", err)
	}
}

// ===========================================================================
// Test 8: Subnet Rate Limiter & Concurrency Pool
// ===========================================================================

func TestGateway_RateLimiter_MaxConcurrency(t *testing.T) {
	maxConcurrent := 5
	limiter := scanner.NewSubnetRateLimiter(maxConcurrent)

	var currentConcurrent int32
	var maxObserved int32
	var wg sync.WaitGroup

	numJobs := 50
	for i := 0; i < numJobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = limiter.Execute(context.Background(), func() error {
				curr := atomic.AddInt32(&currentConcurrent, 1)
				for {
					oldMax := atomic.LoadInt32(&maxObserved)
					if curr > oldMax {
						if atomic.CompareAndSwapInt32(&maxObserved, oldMax, curr) {
							break
						}
					} else {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				atomic.AddInt32(&currentConcurrent, -1)
				return nil
			})
		}()
	}

	wg.Wait()

	if maxObserved > int32(maxConcurrent) {
		t.Fatalf("observed concurrency %d exceeded max limit of %d", maxObserved, maxConcurrent)
	}
}

// ===========================================================================
// Test Helpers: CA and Certificate Generation
// ===========================================================================

func generateTestCA(t *testing.T) (*x509.Certificate, *ed25519.PrivateKey, string, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "EndpointGuard Test Root CA",
			Organization: []string{"EndpointGuard Security"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return caCert, &priv, caPEM, ""
}

func signCSRWithCA(t *testing.T, csrPEM string, caCert *x509.Certificate, caKey *ed25519.PrivateKey) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest failed: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, csr.PublicKey, *caKey)
	if err != nil {
		t.Fatalf("CreateCertificate for client failed: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
}
