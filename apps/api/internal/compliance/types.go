package compliance

import (
	"time"
)

// ComplianceFramework represents a security standard (e.g. CIS Windows 11, DISA STIG, NIST SP 800-53).
type ComplianceFramework struct {
	ID          string    `json:"id"`
	Code        string    `json:"code"` // e.g. "cis_win11_v2.0", "cis_winserver_2022", "disa_stig_win11"
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	TargetOS    string    `json:"target_os"`
	Description string    `json:"description"`
	IsBuiltin   bool      `json:"is_builtin"`
	CreatedAt   time.Time `json:"created_at"`
}

// ComplianceRule represents a declarative check belonging to a compliance framework.
type ComplianceRule struct {
	ID                string    `json:"id"`
	FrameworkID       string    `json:"framework_id"`
	FrameworkCode     string    `json:"framework_code"`
	RuleCode          string    `json:"rule_code"` // e.g. "18.9.15.1", "1.1.1"
	Title             string    `json:"title"`
	Category          string    `json:"category"`
	Level             string    `json:"level"`    // "Level 1", "Level 2"
	Severity          string    `json:"severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Rationale         string    `json:"rationale"`
	ExpectedValue     string    `json:"expected_value"`
	CheckExpression   string    `json:"check_expression"` // JSONLogic declarative rule expression
	RemediationScript string    `json:"remediation_script"`
	CreatedAt         time.Time `json:"created_at"`
}

// EvaluationResult represents the evaluation result of a single compliance rule against a host snapshot.
type EvaluationResult struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	HostID        string    `json:"host_id"`
	Hostname      string    `json:"hostname"`
	FrameworkID   string    `json:"framework_id"`
	FrameworkCode string    `json:"framework_code"`
	RuleID        string    `json:"rule_id"`
	RuleCode      string    `json:"rule_code"`
	RuleTitle     string    `json:"rule_title"`
	Category      string    `json:"category"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"` // "PASS", "FAIL", "WARNING", "NOT_APPLICABLE"
	ActualValue   string    `json:"actual_value"`
	ExpectedValue string    `json:"expected_value"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

// HostComplianceScore aggregates rule results for a specific endpoint.
type HostComplianceScore struct {
	TenantID       string    `json:"tenant_id"`
	HostID         string    `json:"host_id"`
	Hostname       string    `json:"hostname"`
	FrameworkCode  string    `json:"framework_code"`
	TotalRules     int       `json:"total_rules"`
	PassedRules    int       `json:"passed_rules"`
	FailedRules    int       `json:"failed_rules"`
	Score          float64   `json:"score"` // 0.00 to 100.00
	Status         string    `json:"status"` // "COMPLIANT" (>= 90), "DEGRADED" (70-89), "NON_COMPLIANT" (< 70)
	LastEvaluatedAt time.Time `json:"last_evaluated_at"`
}

// TenantComplianceSummary aggregates compliance posture across all endpoints in a tenant.
type TenantComplianceSummary struct {
	TenantID          string    `json:"tenant_id"`
	FrameworkCode     string    `json:"framework_code"`
	TotalHosts        int       `json:"total_hosts"`
	CompliantHosts    int       `json:"compliant_hosts"`
	DegradedHosts     int       `json:"degraded_hosts"`
	NonCompliantHosts int       `json:"non_compliant_hosts"`
	AverageScore      float64   `json:"average_score"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}
