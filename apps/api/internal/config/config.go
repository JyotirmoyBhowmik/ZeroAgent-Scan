package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port              string
	Host              string
	Environment       string
	DatabaseURL       string
	VaultMasterKey    []byte
	AllowedOrigins    []string
	RateLimitRPS      int
	RateLimitBurst    int
	LogLevel          string
	ServiceName       string
	MTLSClientAuth    bool
	MTLSCACertPath    string
	MTLSServerCertPath string
	MTLSServerKeyPath  string
}

func LoadConfig() (*Config, error) {
	port := getEnv("PORT", "8080")
	host := getEnv("HOST", "0.0.0.0")
	env := getEnv("ENVIRONMENT", "development")
	dbURL := getEnv("DATABASE_URL", "postgres://endpointguard_app:endpointguard_secure_dev_password_change_in_prod@localhost:5432/endpointguard?sslmode=disable")
	
	vaultKeyHex := getEnv("VAULT_MASTER_KEY_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	vaultKey, err := hex.DecodeString(vaultKeyHex)
	if err != nil || len(vaultKey) != 32 {
		return nil, fmt.Errorf("invalid VAULT_MASTER_KEY_HEX: must be a 32-byte (64 char) hex string")
	}

	originsStr := getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
	origins := strings.Split(originsStr, ",")

	rps, _ := strconv.Atoi(getEnv("RATE_LIMIT_RPS", "100"))
	burst, _ := strconv.Atoi(getEnv("RATE_LIMIT_BURST", "200"))
	logLevel := getEnv("LOG_LEVEL", "info")
	serviceName := getEnv("SERVICE_NAME", "endpointguard-api")
	mtlsAuth := getEnv("MTLS_ENFORCE_CLIENT_AUTH", "false") == "true"

	return &Config{
		Port:               port,
		Host:               host,
		Environment:        env,
		DatabaseURL:        dbURL,
		VaultMasterKey:     vaultKey,
		AllowedOrigins:     origins,
		RateLimitRPS:       rps,
		RateLimitBurst:     burst,
		LogLevel:           logLevel,
		ServiceName:        serviceName,
		MTLSClientAuth:     mtlsAuth,
		MTLSCACertPath:     getEnv("MTLS_CA_CERT_PATH", ""),
		MTLSServerCertPath: getEnv("MTLSServerCertPath", ""),
		MTLSServerKeyPath:  getEnv("MTLSServerKeyPath", ""),
	}, nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}
