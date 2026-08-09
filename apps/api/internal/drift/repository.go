package drift

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DriftRepository defines storage operations for drift events, alert rules, and delivery logs.
type DriftRepository interface {
	SaveDriftEvents(events []DriftEvent) error
	QueryDriftEvents(tenantID string, opts DriftQueryOptions) (*DriftListResponse, error)
	AcknowledgeDriftEvent(tenantID, eventID, acknowledgedBy string) error

	SaveAlertRule(rule AlertRule) error
	ListAlertRules(tenantID string) []AlertRule
	GetAlertRuleByID(tenantID, ruleID string) (*AlertRule, bool)

	SaveDeliveryLog(log WebhookDeliveryLog) error
	ListDeliveryLogs(tenantID string, limit int) []WebhookDeliveryLog
}

// MemoryDriftRepository is a thread-safe in-memory store for drift events and alert logs.
type MemoryDriftRepository struct {
	mu           sync.RWMutex
	events       map[string]*DriftEvent        // Key: eventID
	rules        map[string]*AlertRule         // Key: ruleID
	deliveryLogs map[string]*WebhookDeliveryLog // Key: logID
}

// NewMemoryDriftRepository creates an initialized in-memory drift repository.
func NewMemoryDriftRepository() *MemoryDriftRepository {
	repo := &MemoryDriftRepository{
		events:       make(map[string]*DriftEvent),
		rules:        make(map[string]*AlertRule),
		deliveryLogs: make(map[string]*WebhookDeliveryLog),
	}

	// Pre-seed default enterprise alert rule
	defaultRule := AlertRule{
		ID:                     "rule-default-critical-laptop",
		TenantID:               "tenant-default-01",
		Name:                   "Critical Laptop Security Baseline Drift",
		Description:            "Sends an immediate webhook alert when BitLocker, TPM, Secure Boot, or Local Admin drifts on mobile laptops.",
		SeverityFilter:         SeverityCritical,
		AssetClassFilter:       "Laptop",
		CategoryFilter:         "",
		Channel:                ChannelWebhook,
		WebhookURL:             "https://hooks.slack.com/services/T000/B000/XXXX",
		SecretKey:              "default-webhook-hmac-secret-key-32b!",
		SuppressionWindowHours: 4,
		IsActive:               true,
		CreatedAt:              time.Now().UTC(),
		UpdatedAt:              time.Now().UTC(),
	}
	_ = repo.SaveAlertRule(defaultRule)

	return repo
}

// SaveDriftEvents persists new drift events.
func (r *MemoryDriftRepository) SaveDriftEvents(events []DriftEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range events {
		ev := events[i]
		if ev.ID == "" {
			ev.ID = uuid.New().String()
		}
		r.events[ev.ID] = &ev
	}
	return nil
}

// QueryDriftEvents filters and paginates drift events for a tenant.
func (r *MemoryDriftRepository) QueryDriftEvents(tenantID string, opts DriftQueryOptions) (*DriftListResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []DriftEvent
	unacked := 0
	critCount := 0
	warnCount := 0
	infoCount := 0

	for _, ev := range r.events {
		if ev.TenantID != tenantID {
			continue
		}

		if !ev.IsAcknowledged {
			unacked++
		}
		switch ev.Severity {
		case SeverityCritical:
			critCount++
		case SeverityWarning:
			warnCount++
		case SeverityInfo:
			infoCount++
		}

		// Filter Severity
		if opts.Severity != "" && !strings.EqualFold(opts.Severity, "ALL") {
			if !strings.EqualFold(string(ev.Severity), opts.Severity) {
				continue
			}
		}

		// Filter Category
		if opts.Category != "" {
			if !strings.EqualFold(ev.DriftCategory, opts.Category) {
				continue
			}
		}

		// Filter HostID
		if opts.HostID != "" {
			if ev.HostID != opts.HostID {
				continue
			}
		}

		// Filter Acknowledged
		if opts.IsAcknowledged != nil {
			if ev.IsAcknowledged != *opts.IsAcknowledged {
				continue
			}
		}

		filtered = append(filtered, *ev)
	}

	// Sort newest first
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].DetectedAt.After(filtered[j].DetectedAt)
	})

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 200 {
		limit = 200
	}

	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	var paginated []DriftEvent
	if offset < len(filtered) {
		end := offset + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		paginated = filtered[offset:end]
	} else {
		paginated = []DriftEvent{}
	}

	return &DriftListResponse{
		TotalCount:     len(filtered),
		Unacknowledged: unacked,
		CriticalCount:  critCount,
		WarningCount:   warnCount,
		InfoCount:      infoCount,
		Limit:          limit,
		Offset:         offset,
		Items:          paginated,
	}, nil
}

// AcknowledgeDriftEvent marks a drift event as acknowledged.
func (r *MemoryDriftRepository) AcknowledgeDriftEvent(tenantID, eventID, acknowledgedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ev, exists := r.events[eventID]
	if !exists || ev.TenantID != tenantID {
		return fmt.Errorf("drift_repo: drift event %s not found", eventID)
	}

	now := time.Now().UTC()
	ev.IsAcknowledged = true
	ev.AcknowledgedBy = &acknowledgedBy
	ev.AcknowledgedAt = &now
	return nil
}

// SaveAlertRule adds or updates an alert rule.
func (r *MemoryDriftRepository) SaveAlertRule(rule AlertRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}
	rule.UpdatedAt = time.Now().UTC()
	r.rules[rule.ID] = &rule
	return nil
}

// ListAlertRules returns all alert rules for a tenant.
func (r *MemoryDriftRepository) ListAlertRules(tenantID string) []AlertRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []AlertRule
	for _, rule := range r.rules {
		if rule.TenantID == tenantID {
			list = append(list, *rule)
		}
	}
	return list
}

// GetAlertRuleByID retrieves a single rule by ID.
func (r *MemoryDriftRepository) GetAlertRuleByID(tenantID, ruleID string) (*AlertRule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, exists := r.rules[ruleID]
	if !exists || rule.TenantID != tenantID {
		return nil, false
	}
	return rule, true
}

// SaveDeliveryLog records a webhook delivery attempt.
func (r *MemoryDriftRepository) SaveDeliveryLog(log WebhookDeliveryLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	r.deliveryLogs[log.ID] = &log
	return nil
}

// ListDeliveryLogs returns the most recent delivery logs for a tenant.
func (r *MemoryDriftRepository) ListDeliveryLogs(tenantID string, limit int) []WebhookDeliveryLog {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []WebhookDeliveryLog
	for _, log := range r.deliveryLogs {
		if log.TenantID == tenantID {
			list = append(list, *log)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].DeliveredAt.After(list[j].DeliveredAt)
	})

	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list
}
