package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	totpStepSeconds = 30
	totpCodeDigits  = 6
)

// GenerateTOTPSecret generates a cryptographically secure 160-bit (20-byte) Base32 encoded secret.
func GenerateTOTPSecret() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("totp: failed to generate entropy: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes), nil
}

// GenerateTOTPCode generates the 6-digit TOTP code for a given timestamp using RFC 6238 / RFC 4226.
func GenerateTOTPCode(secretBase32 string, t time.Time) (string, error) {
	secretBase32 = strings.ToUpper(strings.TrimSpace(secretBase32))
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	if err != nil {
		// Try with standard padding
		secretBytes, err = base32.StdEncoding.DecodeString(secretBase32)
		if err != nil {
			return "", fmt.Errorf("totp: invalid base32 secret: %w", err)
		}
	}

	counter := uint64(t.Unix() / totpStepSeconds)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(buf[:])
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(hash[offset : offset+4])
	binaryCode &= 0x7fffffff

	code := binaryCode % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTPCode validates a user-provided 6-digit TOTP code, allowing clock skew (±skewSteps).
func ValidateTOTPCode(secretBase32 string, code string, t time.Time, skewSteps int) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpCodeDigits {
		return false
	}
	if skewSteps < 0 {
		skewSteps = 1
	}

	for i := -skewSteps; i <= skewSteps; i++ {
		targetTime := t.Add(time.Duration(i*totpStepSeconds) * time.Second)
		generated, err := GenerateTOTPCode(secretBase32, targetTime)
		if err == nil && hmac.Equal([]byte(generated), []byte(code)) {
			return true
		}
	}
	return false
}
