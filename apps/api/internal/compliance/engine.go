package compliance

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/middleware"
	"github.com/JyotirmoyBhowmik/ZeroAgent-Scan/apps/api/internal/models"
	"github.com/google/uuid"
)

// ComplianceEngine evaluates declarative compliance rules against host audit snapshots.
type ComplianceEngine struct {
	repo ComplianceRepository
}

// NewComplianceEngine creates an initialized compliance evaluation engine.
func NewComplianceEngine(repo ComplianceRepository) *ComplianceEngine {
	if repo == nil {
		repo = NewMemoryComplianceRepository()
	}
	return &ComplianceEngine{
		repo: repo,
	}
}

// EvaluateHost evaluates all rules in the specified framework against a host snapshot payload.
func (e *ComplianceEngine) EvaluateHost(
	tenantID string,
	hostID string,
	hostname string,
	snapshot *models.HostSnapshotPayload,
	frameworkCode string,
) ([]EvaluationResult, HostComplianceScore, error) {
	if snapshot == nil {
		return nil, HostComplianceScore{}, fmt.Errorf("compliance_engine: snapshot payload cannot be nil")
	}
	if tenantID == "" {
		return nil, HostComplianceScore{}, fmt.Errorf("compliance_engine: missing tenant_id")
	}
	if hostID == "" {
		return nil, HostComplianceScore{}, fmt.Errorf("compliance_engine: missing host_id")
	}
	if hostname == "" {
		hostname = snapshot.SystemIdentity.Hostname
	}
	if frameworkCode == "" {
		frameworkCode = CISWin11FrameworkCode
	}

	rules := e.repo.ListRulesByFramework(frameworkCode)
	if len(rules) == 0 {
		return nil, HostComplianceScore{}, fmt.Errorf("compliance_engine: no rules found for framework %s", frameworkCode)
	}

	now := time.Now().UTC()
	var results []EvaluationResult
	passedCount := 0
	failedCount := 0

	for _, rule := range rules {
		// Evaluate Rule CheckExpression (JSONLogic)
		passed, err := EvaluateExpression(rule.CheckExpression, snapshot)
		status := "PASS"
		if err != nil || !passed {
			status = "FAIL"
		}

		if status == "PASS" {
			passedCount++
		} else {
			failedCount++
		}

		// Extract actual value for reporting
		varPath := extractVarFromExpr(rule.CheckExpression)
		actualVal := "<evaluated>"
		if varPath != "" {
			actualVal = ExtractValue(snapshot, varPath)
		}

		res := EvaluationResult{
			ID:            uuid.New().String(),
			TenantID:      tenantID,
			HostID:        hostID,
			Hostname:      hostname,
			FrameworkID:   rule.FrameworkID,
			FrameworkCode: rule.FrameworkCode,
			RuleID:        rule.ID,
			RuleCode:      rule.RuleCode,
			RuleTitle:     rule.Title,
			Category:      rule.Category,
			Severity:      rule.Severity,
			Status:        status,
			ActualValue:   actualVal,
			ExpectedValue: rule.ExpectedValue,
			EvaluatedAt:   now,
		}

		results = append(results, res)
	}

	// Compute Host Score
	totalCount := passedCount + failedCount
	scorePct := 0.0
	if totalCount > 0 {
		scorePct = math.Round((float64(passedCount)/float64(totalCount))*10000) / 100.0
	}

	hostStatus := "NON_COMPLIANT"
	if scorePct >= 90.0 {
		hostStatus = "COMPLIANT"
	} else if scorePct >= 70.0 {
		hostStatus = "DEGRADED"
	}

	hostScore := HostComplianceScore{
		TenantID:        tenantID,
		HostID:          hostID,
		Hostname:        hostname,
		FrameworkCode:   frameworkCode,
		TotalRules:      totalCount,
		PassedRules:     passedCount,
		FailedRules:     failedCount,
		Score:           scorePct,
		Status:          hostStatus,
		LastEvaluatedAt: now,
	}

	// Persist in repository
	if err := e.repo.SaveEvaluations(tenantID, hostID, results, hostScore); err != nil {
		middleware.LogJSON("error", "compliance_engine", "compliance", fmt.Sprintf("Failed to save host evaluations: %v", err))
	}

	return results, hostScore, nil
}

func extractVarFromExpr(exprJSON string) string {
	idx := strings.Index(exprJSON, `"var":`)
	if idx == -1 {
		idx = strings.Index(exprJSON, `"var" :`)
	}
	if idx == -1 {
		return ""
	}

	rem := exprJSON[idx+6:]
	startQuote := strings.Index(rem, `"`)
	if startQuote == -1 {
		return ""
	}
	endQuote := strings.Index(rem[startQuote+1:], `"`)
	if endQuote == -1 {
		return ""
	}

	return rem[startQuote+1 : startQuote+1+endQuote]
}
