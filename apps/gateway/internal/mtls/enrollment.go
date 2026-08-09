package mtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrEnrollmentPending  = errors.New("mtls: enrollment is pending operator approval in control plane dashboard")
	ErrEnrollmentRejected = errors.New("mtls: enrollment was rejected by security operator")
)

// RegistrationRequest payload sent on first boot.
type RegistrationRequest struct {
	GatewayID   string `json:"gateway_id"`
	SubnetCIDR  string `json:"subnet_cidr"`
	Hostname    string `json:"hostname"`
	CSRPEM      string `json:"csr_pem"`
	ClientVer   string `json:"client_version"`
}

// RegistrationResponse received from control plane.
type RegistrationResponse struct {
	GatewayID           string `json:"gateway_id"`
	Status              string `json:"status"` // "pending_approval", "approved", "rejected"
	Fingerprint         string `json:"fingerprint"`
	CertificatePEM      string `json:"certificate_pem,omitempty"`
	CACertificatePEM    string `json:"ca_certificate_pem,omitempty"`
	Message             string `json:"message,omitempty"`
}

// EnrollmentManager coordinates key generation, CSR issuance, approval polling, and mTLS configuration.
type EnrollmentManager struct {
	gatewayID       string
	subnetCIDR      string
	controlPlaneURL string
	certDir         string
	httpClient      *http.Client
	mu              sync.RWMutex
	privKey         *ecdsa.PrivateKey
	keyPEM          string
	csrPEM          string
	clientCert      *tls.Certificate
	caCertPool      *x509.CertPool
}

// NewEnrollmentManager initializes a new mTLS enrollment manager.
func NewEnrollmentManager(gatewayID, subnetCIDR, controlPlaneURL, certDir string, baseClient *http.Client) *EnrollmentManager {
	if baseClient == nil {
		baseClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &EnrollmentManager{
		gatewayID:       gatewayID,
		subnetCIDR:      subnetCIDR,
		controlPlaneURL: strings.TrimRight(controlPlaneURL, "/"),
		certDir:         certDir,
		httpClient:      baseClient,
	}
}

// GenerateKeyAndCSR generates an ECDSA P-256 private key and a PKCS#10 CSR.
func (em *EnrollmentManager) GenerateKeyAndCSR() (csrPEM string, keyPEM string, err error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("mtls: failed to generate private key: %w", err)
	}
	em.privKey = privKey

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", "", fmt.Errorf("mtls: failed to marshal private key: %w", err)
	}
	keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	keyPEM = string(pem.EncodeToMemory(keyBlock))
	em.keyPEM = keyPEM

	hostname, _ := os.Hostname()
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   em.gatewayID,
			Organization: []string{"EndpointGuard Security"},
			Country:      []string{"US"},
		},
		DNSNames: []string{hostname, em.gatewayID},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return "", "", fmt.Errorf("mtls: failed to create CSR: %w", err)
	}
	csrBlock := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}
	csrPEM = string(pem.EncodeToMemory(csrBlock))

	return csrPEM, keyPEM, nil
}

// RegisterAndEnroll submits the CSR to the control plane and checks approval status.
func (em *EnrollmentManager) RegisterAndEnroll(ctx context.Context) (*RegistrationResponse, error) {
	csrPEM, keyPEM, err := em.GenerateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	hostname, _ := os.Hostname()
	reqBody := RegistrationRequest{
		GatewayID:  em.gatewayID,
		SubnetCIDR: em.subnetCIDR,
		Hostname:   hostname,
		CSRPEM:     csrPEM,
		ClientVer:  "v1.0.0",
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("mtls: failed to marshal registration: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/gateways/register", em.controlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("mtls: failed to build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := em.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mtls: registration HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("mtls: failed to read registration response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("mtls: registration rejected with status %d: %s", resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("mtls: failed to unmarshal registration response: %w", err)
	}

	// Persist key to disk if certDir is configured
	if em.certDir != "" {
		_ = os.MkdirAll(em.certDir, 0700)
		_ = os.WriteFile(filepath.Join(em.certDir, "gateway.key"), []byte(keyPEM), 0600)
		_ = os.WriteFile(filepath.Join(em.certDir, "gateway.csr"), []byte(csrPEM), 0644)
	}

	if regResp.Status == "approved" && regResp.CertificatePEM != "" {
		if err := em.InstallCertificates(regResp.CertificatePEM, keyPEM, regResp.CACertificatePEM); err != nil {
			return nil, err
		}
	}

	return &regResp, nil
}

// PollCertificateApproval checks if the operator has approved the pending CSR.
func (em *EnrollmentManager) PollCertificateApproval(ctx context.Context, keyPEM string) (*RegistrationResponse, error) {
	url := fmt.Sprintf("%s/api/v1/gateways/%s/cert", em.controlPlaneURL, em.gatewayID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := em.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrEnrollmentPending
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mtls: cert poll returned status %d", resp.StatusCode)
	}

	var regResp RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, err
	}

	if regResp.Status == "rejected" {
		return &regResp, ErrEnrollmentRejected
	}
	if regResp.Status != "approved" || regResp.CertificatePEM == "" {
		return &regResp, ErrEnrollmentPending
	}

	if err := em.InstallCertificates(regResp.CertificatePEM, keyPEM, regResp.CACertificatePEM); err != nil {
		return nil, err
	}

	return &regResp, nil
}

// InstallCertificates parses and loads the client cert pair and CA cert pool into memory.
func (em *EnrollmentManager) InstallCertificates(certPEM, keyPEM, caPEM string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if keyPEM == "" {
		keyPEM = em.keyPEM
	}
	if keyPEM == "" && em.certDir != "" {
		if diskKey, err := os.ReadFile(filepath.Join(em.certDir, "gateway.key")); err == nil {
			keyPEM = string(diskKey)
		}
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("mtls: invalid client certificate or key: %w", err)
	}
	em.clientCert = &cert

	if caPEM != "" {
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM([]byte(caPEM)) {
			return fmt.Errorf("mtls: failed to append CA certificate to pool")
		}
		em.caCertPool = caPool
	}

	if em.certDir != "" {
		_ = os.WriteFile(filepath.Join(em.certDir, "gateway.crt"), []byte(certPEM), 0644)
		if caPEM != "" {
			_ = os.WriteFile(filepath.Join(em.certDir, "ca.crt"), []byte(caPEM), 0644)
		}
	}

	return nil
}

// BuildTLSClientConfig returns a *tls.Config configured for strict mTLS.
func (em *EnrollmentManager) BuildTLSClientConfig() (*tls.Config, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if em.clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*em.clientCert}
	}
	if em.caCertPool != nil {
		tlsConfig.RootCAs = em.caCertPool
	}

	return tlsConfig, nil
}

// ComputeFingerprint computes a SHA-256 fingerprint for a certificate or CSR.
func ComputeFingerprint(derBytes []byte) string {
	sum := sha256.Sum256(derBytes)
	return fmt.Sprintf("SHA256:%s", hex.EncodeToString(sum[:]))
}
