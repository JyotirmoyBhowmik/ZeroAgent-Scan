package drift

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// AlertEngine evaluates drift events against tenant alert rules and enforces suppression windows.
type AlertEngine struct {
	mu           sync.RWMutex
	suppressions map[string]time.Time // Key: tenantID + ":" + hostID + ":" + propertyName -> lastAlertTime
}

// NewAlertEngine creates an initialized alert evaluation engine.
func NewAlertEngine() *AlertEngine {
	return &AlertEngine{
		suppressions: make(map[string]time.Time),
	}
}

// EvaluateRules checks if a drift event matches any active alert rules, factoring in asset class and suppression.
func (e *AlertEngine) EvaluateRules(
	event DriftEvent,
	assetClass string,
	rules []AlertRule,
) []AlertRule {
	now := time.Now().UTC()
	var matchedRules []AlertRule

	for _, rule := range rules {
		if !rule.IsActive {
			continue
		}

		// 1. Severity Filter Match
		if rule.SeverityFilter != "" {
			if !strings.EqualFold(string(rule.SeverityFilter), string(event.Severity)) {
				continue
			}
		}

		// 2. Asset Class Filter Match (e.g. "Laptop", "Server")
		if rule.AssetClassFilter != "" {
			if !strings.EqualFold(rule.AssetClassFilter, assetClass) &&
				!strings.Contains(strings.ToLower(assetClass), strings.ToLower(rule.AssetClassFilter)) {
				continue
			}
		}

		// 3. Category Filter Match
		if rule.CategoryFilter != "" {
			if !strings.EqualFold(rule.CategoryFilter, event.DriftCategory) {
				continue
			}
		}

		// 4. Alert Suppression Window Check
		if e.isSuppressed(event.TenantID, event.HostID, event.PropertyName, rule.SuppressionWindowHours, now) {
			// Suppressed during window: do not dispatch webhook
			continue
		}

		matchedRules = append(matchedRules, rule)
	}

	return matchedRules
}

// MarkAlertDispatched updates the suppression timestamp for a host property.
func (e *AlertEngine) MarkAlertDispatched(tenantID, hostID, propertyName string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%s", tenantID, hostID, propertyName)
	e.suppressions[key] = at
}

// isSuppressed checks if an alert for this host and property was sent within windowHours.
func (e *AlertEngine) isSuppressed(tenantID, hostID, propertyName string, windowHours int, now time.Time) bool {
	if windowHours <= 0 {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	key := fmt.Sprintf("%s:%s:%s", tenantID, hostID, propertyName)
	lastAlert, exists := e.suppressions[key]
	if !exists {
		return false
	}

	windowDuration := time.Duration(windowHours) * time.Hour
	return now.Sub(lastAlert) < windowDuration
}

// ClearSuppression removes the suppression state for a host and property (used in tests).
func (e *AlertEngine) ClearSuppression(tenantID, hostID, propertyName string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%s", tenantID, hostID, propertyName)
	delete(e.suppressions, key)
}
