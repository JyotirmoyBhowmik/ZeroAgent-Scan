package drift

import (
	"context"
	"fmt"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
)

// DriftWorker orchestrates snapshot diffing, drift persistence, and rule-based alert dispatching.
type DriftWorker struct {
	differ     *PayloadDiffer
	alertEng   *AlertEngine
	dispatcher *WebhookDispatcher
	repo       DriftRepository
}

// NewDriftWorker creates an initialized drift processing worker.
func NewDriftWorker(repo DriftRepository, dispatcher *WebhookDispatcher) *DriftWorker {
	if repo == nil {
		repo = NewMemoryDriftRepository()
	}
	if dispatcher == nil {
		dispatcher = NewWebhookDispatcher(nil, 3)
	}
	return &DriftWorker{
		differ:     NewPayloadDiffer(),
		alertEng:   NewAlertEngine(),
		dispatcher: dispatcher,
		repo:       repo,
	}
}

// ProcessSnapshot compares a new snapshot against the prior snapshot, persists drifts, and triggers webhooks.
func (w *DriftWorker) ProcessSnapshot(
	ctx context.Context,
	tenantID, hostID, hostname, assetClass string,
	newSnapshot, prevSnapshot *models.HostSnapshotPayload,
) ([]DriftEvent, []WebhookDeliveryLog, error) {
	if newSnapshot == nil {
		return nil, nil, fmt.Errorf("drift_worker: new snapshot cannot be nil")
	}
	if tenantID == "" {
		return nil, nil, fmt.Errorf("drift_worker: missing tenant_id")
	}
	if hostID == "" {
		return nil, nil, fmt.Errorf("drift_worker: missing host_id")
	}
	if hostname == "" {
		hostname = newSnapshot.SystemIdentity.Hostname
	}
	if assetClass == "" {
		assetClass = newSnapshot.SystemIdentity.ChassisType
	}

	// 1. Diff Snapshots (with payload hash short-circuit)
	events, err := w.differ.DiffSnapshots(tenantID, hostID, hostname, newSnapshot, prevSnapshot)
	if err != nil {
		return nil, nil, fmt.Errorf("drift_worker: diff failed: %w", err)
	}

	if len(events) == 0 {
		// No drift or short-circuited
		return nil, nil, nil
	}

	// 2. Persist Drift Events
	if err := w.repo.SaveDriftEvents(events); err != nil {
		middleware.LogJSON("error", "drift_worker", "drift", fmt.Sprintf("Failed to save drift events: %v", err))
	}

	middleware.LogJSON("info", "drift_worker", "drift",
		fmt.Sprintf("Detected %d drift events for host %s (%s)", len(events), hostname, hostID))

	// 3. Evaluate Alert Rules & Dispatch Webhooks
	rules := w.repo.ListAlertRules(tenantID)
	var deliveryLogs []WebhookDeliveryLog

	for _, ev := range events {
		matchedRules := w.alertEng.EvaluateRules(ev, assetClass, rules)
		for _, rule := range matchedRules {
			// Dispatch HMAC-signed webhook
			deliveryLog, err := w.dispatcher.Dispatch(ctx, rule, ev, assetClass)
			if deliveryLog != nil {
				_ = w.repo.SaveDeliveryLog(*deliveryLog)
				deliveryLogs = append(deliveryLogs, *deliveryLog)

				if deliveryLog.Status == "SUCCESS" {
					// Update suppression window
					w.alertEng.MarkAlertDispatched(tenantID, hostID, ev.PropertyName, time.Now().UTC())
				}
			}

			if err != nil {
				middleware.LogJSON("warn", "drift_worker", "drift",
					fmt.Sprintf("Webhook delivery failed for rule %s (event %s): %v", rule.Name, ev.ID, err))
			}
		}
	}

	return events, deliveryLogs, nil
}

// GetRepository returns the underlying drift repository.
func (w *DriftWorker) GetRepository() DriftRepository {
	return w.repo
}

// GetAlertEngine returns the alert engine for suppression inspection/clearing in tests.
func (w *DriftWorker) GetAlertEngine() *AlertEngine {
	return w.alertEng
}
