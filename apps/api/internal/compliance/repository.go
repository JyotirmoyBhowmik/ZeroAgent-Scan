package compliance

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ComplianceRepository defines persistence operations for compliance rules and evaluations.
type ComplianceRepository interface {
	SaveFramework(fw ComplianceFramework) error
	ListFrameworks() []ComplianceFramework
	GetFrameworkByCode(code string) (*ComplianceFramework, bool)

	SaveRule(rule ComplianceRule) error
	ListRulesByFramework(frameworkCode string) []ComplianceRule
	GetRuleByID(id string) (*ComplianceRule, bool)

	SaveEvaluations(tenantID, hostID string, results []EvaluationResult, score HostComplianceScore) error
	GetHostEvaluations(tenantID, hostID string) ([]EvaluationResult, *HostComplianceScore, error)
	GetHostScore(tenantID, hostID string) (*HostComplianceScore, bool)
	GetTenantSummary(tenantID, frameworkCode string) (*TenantComplianceSummary, error)
}

// MemoryComplianceRepository is a thread-safe in-memory store for compliance frameworks and results.
type MemoryComplianceRepository struct {
	mu          sync.RWMutex
	frameworks  map[string]*ComplianceFramework // Key: frameworkCode
	rules       map[string]*ComplianceRule      // Key: ruleID
	evaluations map[string][]EvaluationResult   // Key: tenantID + ":" + hostID
	hostScores  map[string]*HostComplianceScore // Key: tenantID + ":" + hostID
}

// NewMemoryComplianceRepository creates an initialized repository pre-seeded with CIS Windows 11 rules.
func NewMemoryComplianceRepository() *MemoryComplianceRepository {
	repo := &MemoryComplianceRepository{
		frameworks:  make(map[string]*ComplianceFramework),
		rules:       make(map[string]*ComplianceRule),
		evaluations: make(map[string][]EvaluationResult),
		hostScores:  make(map[string]*HostComplianceScore),
	}

	// Pre-seed CIS Windows 11 framework and 28 controls
	cisFw := DefaultCISWindows11Framework()
	_ = repo.SaveFramework(cisFw)

	for _, rule := range GetBuiltinCISWindows11Rules() {
		_ = repo.SaveRule(rule)
	}

	return repo
}

// SaveFramework persists or updates a compliance framework definition.
func (r *MemoryComplianceRepository) SaveFramework(fw ComplianceFramework) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if fw.Code == "" {
		return fmt.Errorf("compliance_repo: missing framework code")
	}
	if fw.ID == "" {
		fw.ID = uuid.New().String()
	}
	fw.Code = strings.ToLower(strings.TrimSpace(fw.Code))
	r.frameworks[fw.Code] = &fw
	return nil
}

// ListFrameworks returns all registered compliance frameworks.
func (r *MemoryComplianceRepository) ListFrameworks() []ComplianceFramework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ComplianceFramework, 0, len(r.frameworks))
	for _, fw := range r.frameworks {
		result = append(result, *fw)
	}
	return result
}

// GetFrameworkByCode retrieves a framework by its unique code (e.g. "cis_win11_v2.0").
func (r *MemoryComplianceRepository) GetFrameworkByCode(code string) (*ComplianceFramework, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fw, exists := r.frameworks[strings.ToLower(strings.TrimSpace(code))]
	return fw, exists
}

// SaveRule adds a declarative compliance rule to a framework (enabling dynamic STIG/NIST additions).
func (r *MemoryComplianceRepository) SaveRule(rule ComplianceRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if rule.RuleCode == "" {
		return fmt.Errorf("compliance_repo: missing rule_code")
	}
	if rule.FrameworkCode == "" {
		return fmt.Errorf("compliance_repo: missing framework_code")
	}
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	rule.FrameworkCode = strings.ToLower(strings.TrimSpace(rule.FrameworkCode))
	r.rules[rule.ID] = &rule
	return nil
}

// ListRulesByFramework returns all rules belonging to a framework code.
func (r *MemoryComplianceRepository) ListRulesByFramework(frameworkCode string) []ComplianceRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fwCode := strings.ToLower(strings.TrimSpace(frameworkCode))
	var list []ComplianceRule
	for _, rule := range r.rules {
		if strings.EqualFold(rule.FrameworkCode, fwCode) {
			list = append(list, *rule)
		}
	}
	return list
}

// GetRuleByID retrieves a single rule by its unique ID.
func (r *MemoryComplianceRepository) GetRuleByID(id string) (*ComplianceRule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, exists := r.rules[id]
	return rule, exists
}

// SaveEvaluations stores host rule evaluation results and computed host score.
func (r *MemoryComplianceRepository) SaveEvaluations(tenantID, hostID string, results []EvaluationResult, score HostComplianceScore) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", tenantID, hostID)
	r.evaluations[key] = results
	r.hostScores[key] = &score
	return nil
}

// GetHostEvaluations returns the latest evaluation rows and score for a host.
func (r *MemoryComplianceRepository) GetHostEvaluations(tenantID, hostID string) ([]EvaluationResult, *HostComplianceScore, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", tenantID, hostID)
	evals, exists := r.evaluations[key]
	if !exists {
		return nil, nil, fmt.Errorf("compliance_repo: no evaluations found for host %s", hostID)
	}

	score := r.hostScores[key]
	return evals, score, nil
}

// GetHostScore returns the current compliance score for a host.
func (r *MemoryComplianceRepository) GetHostScore(tenantID, hostID string) (*HostComplianceScore, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", tenantID, hostID)
	score, exists := r.hostScores[key]
	return score, exists
}

// GetTenantSummary computes the aggregate tenant compliance score across all evaluated hosts.
func (r *MemoryComplianceRepository) GetTenantSummary(tenantID, frameworkCode string) (*TenantComplianceSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fwCode := strings.ToLower(strings.TrimSpace(frameworkCode))
	if fwCode == "" {
		fwCode = CISWin11FrameworkCode
	}

	totalHosts := 0
	compliantHosts := 0
	degradedHosts := 0
	nonCompliantHosts := 0
	totalScoreSum := 0.0

	for key, score := range r.hostScores {
		if strings.HasPrefix(key, tenantID+":") {
			if fwCode != "" && !strings.EqualFold(score.FrameworkCode, fwCode) {
				continue
			}

			totalHosts++
			totalScoreSum += score.Score
			if score.Score >= 90.0 {
				compliantHosts++
			} else if score.Score >= 70.0 {
				degradedHosts++
			} else {
				nonCompliantHosts++
			}
		}
	}

	avgScore := 0.0
	if totalHosts > 0 {
		avgScore = totalScoreSum / float64(totalHosts)
	}

	return &TenantComplianceSummary{
		TenantID:          tenantID,
		FrameworkCode:     fwCode,
		TotalHosts:        totalHosts,
		CompliantHosts:    compliantHosts,
		DegradedHosts:     degradedHosts,
		NonCompliantHosts: nonCompliantHosts,
		AverageScore:      avgScore,
		EvaluatedAt:       time.Now().UTC(),
	}, nil
}
