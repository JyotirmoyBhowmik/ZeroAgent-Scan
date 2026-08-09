package auth

import (
	"time"
)

const (
	StepUpAuthValidityWindow = 15 * time.Minute
)

// IsStepUpValid verifies if the step-up authentication timestamp is within the 15-minute validity window.
func IsStepUpValid(stepUpAuthAt time.Time) bool {
	if stepUpAuthAt.IsZero() {
		return false
	}
	now := time.Now().UTC()
	return now.Sub(stepUpAuthAt) <= StepUpAuthValidityWindow
}
