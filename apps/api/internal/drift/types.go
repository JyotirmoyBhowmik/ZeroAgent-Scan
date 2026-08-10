package drift

import (
	"time"
)

// DriftSeverity classifies the operational and security impact of a detected drift.
type DriftSeverity string

const (
	SeverityCritical DriftSeverity = "CRITICAL" // Security-breaking: BitLocker, TPM, Secure Boot, Admin, Defender, LSA
	SeverityWarning  DriftSeverity = "WARNING"  // Hardware/Operational: RAM, Disk, NIC, BIOS update
	SeverityInfo     DriftSeverity = "INFO"     // Minor: Software update, monitor/peripheral plugged in
)

// DriftEvent represents a single configuration or hardware state change on a host.
type DriftEvent struct {
	ID             string        `json:"id"`
	TenantID       string        `json:"tenant_id"`
	HostID         string        `json:"host_id"`
	Hostname       string        `json:"hostname"`
	DriftCategory  string        `json:"drift_category"` // "SecurityBaseline", "Firmware", "TPM", "UserAccess", "Hardware", "Software"
	PropertyName   string        `json:"property_name"`  // e.g. "security_baseline.bitlocker.protection_status"
	BaselineValue  string        `json:"baseline_value"`
	CurrentValue   string        `json:"current_value"`
	Severity       DriftSeverity `json:"severity"`
	IsAcknowledged bool          `json:"is_acknowledged"`
	AcknowledgedBy *string       `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time    `json:"acknowledged_at,omitempty"`
	DetectedAt     time.Time     `json:"detected_at"`
	CreatedAt      time.Time     `json:"created_at"`
}

// AlertChannel defines the delivery mechanism for an alert.
type AlertChannel string

const (
	ChannelSlack   AlertChannel = "SLACK"
	ChannelTeams   AlertChannel = "TEAMS"
	ChannelEmail   AlertChannel = "EMAIL"
	ChannelWebhook AlertChannel = "WEBHOOK"
)

// AlertRule specifies conditions under which a drift event triggers a webhook alert.
type AlertRule struct {
	ID                     string        `json:"id"`
	TenantID               string        `json:"tenant_id"`
	Name                   string        `json:"name"`
	Description            string        `json:"description"`
	SeverityFilter         DriftSeverity `json:"severity_filter"` // e.g. "CRITICAL"
	AssetClassFilter       string        `json:"asset_class_filter,omitempty"` // e.g. "Laptop", "Server", "Desktop" or "" (all)
	CategoryFilter         string        `json:"category_filter,omitempty"` // e.g. "SecurityBaseline" or "" (all)
	Channel                AlertChannel  `json:"channel"`
	WebhookURL             string        `json:"webhook_url"`
	SecretKey              string        `json:"secret_key"` // HMAC signing secret
	SuppressionWindowHours int           `json:"suppression_window_hours"` // e.g. 4 hours
	IsActive               bool          `json:"is_active"`
	CreatedAt              time.Time     `json:"created_at"`
	UpdatedAt              time.Time     `json:"updated_at"`
}

// WebhookNotificationPayload is the standardized JSON payload sent to receivers.
type WebhookNotificationPayload struct {
	DeliveryID   string      `json:"delivery_id"`
	TimestampUTC string      `json:"timestamp_utc"`
	TenantID     string      `json:"tenant_id"`
	RuleID       string      `json:"rule_id"`
	RuleName     string      `json:"rule_name"`
	HostID       string      `json:"host_id"`
	Hostname     string      `json:"hostname"`
	AssetClass   string      `json:"asset_class"`
	Event        DriftEvent  `json:"event"`
}

// WebhookDeliveryLog records the result of an HTTP webhook dispatch attempt.
type WebhookDeliveryLog struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	RuleID       string    `json:"rule_id"`
	EventID      string    `json:"event_id"`
	TargetURL    string    `json:"target_url"`
	StatusCode   int       `json:"status_code"`
	DurationMs   int64     `json:"duration_ms"`
	Attempts     int       `json:"attempts"`
	Status       string    `json:"status"` // "SUCCESS", "FAILED"
	ErrorMessage *string   `json:"error_message,omitempty"`
	DeliveredAt  time.Time `json:"delivered_at"`
}

// DriftQueryOptions holds filtering options for listing drift events.
type DriftQueryOptions struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	HostID         string `json:"host_id"`
	IsAcknowledged *bool  `json:"is_acknowledged"`
	Limit          int    `json:"limit"`
	Offset         int    `json:"offset"`
}

// DriftListResponse is the paginated response for drift events.
type DriftListResponse struct {
	TotalCount       int          `json:"total_count"`
	Unacknowledged   int          `json:"unacknowledged_count"`
	CriticalCount    int          `json:"critical_count"`
	WarningCount     int          `json:"warning_count"`
	InfoCount        int          `json:"info_count"`
	Limit            int          `json:"limit"`
	Offset           int          `json:"offset"`
	Items            []DriftEvent `json:"items"`
}

// TestAlertPayload defines the human-readable synthetic alert message sent to real webhook receivers.
type TestAlertPayload struct {
	AlertNotice         string                 `json:"alert_notice"` // "[SYNTHETIC TEST ALERT - NOT A REAL INCIDENT]"
	AlertType           string                 `json:"alert_type"`   // "FLEET_FAILURE_RATE_TEST"
	Message             string                 `json:"message"`
	DeliveryID          string                 `json:"delivery_id"`
	TimestampUTC        string                 `json:"timestamp_utc"`
	Operator            string                 `json:"triggered_by_operator"`
	System              string                 `json:"system"`
	SimulatedMetrics    map[string]interface{} `json:"simulated_metrics"`
	VerificationReceipt string                 `json:"verification_receipt"`
}

// TestAlertRequest specifies the parameters for firing a test alert.
type TestAlertRequest struct {
	WebhookURL    string `json:"webhook_url,omitempty"`
	SecretKey     string `json:"secret_key,omitempty"`
	Channel       string `json:"channel,omitempty"` // "WEBHOOK", "SLACK", "TEAMS", "EMAIL"
	TestReason    string `json:"test_reason,omitempty"`
}

// TestAlertResponse returns the delivery result of the synthetic test alert.
type TestAlertResponse struct {
	Status              string    `json:"status"` // "DELIVERED", "FAILED", "TIMEOUT"
	TargetURL           string    `json:"target_url"`
	StatusCode          int       `json:"status_code"`
	DurationMs          int64     `json:"duration_ms"`
	DeliveryID          string    `json:"delivery_id"`
	VerificationReceipt string    `json:"verification_receipt"`
	ErrorMessage        string    `json:"error_message,omitempty"`
	TestedAt            time.Time `json:"tested_at"`
	TestedBy            string    `json:"tested_by"`
	AlertNotice         string    `json:"alert_notice"`
}
