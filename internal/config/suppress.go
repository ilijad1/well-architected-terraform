package config

import (
	"time"

	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// SuppressionResult holds the outcome of applying suppressions to findings.
type SuppressionResult struct {
	Kept                []model.Finding
	Suppressed          []model.Finding
	ExpiredSuppressions []Suppression
}

// Apply filters findings against the list of suppressions.
// A finding is suppressed if its RuleID and Resource match a suppression entry.
// Expired suppressions still suppress their findings but are tracked separately
// so callers can emit warnings.
func Apply(findings []model.Finding, suppressions []Suppression, now time.Time) SuppressionResult {
	if len(suppressions) == 0 {
		return SuppressionResult{Kept: findings}
	}

	// Track which suppressions are expired.
	expired := make(map[int]bool)
	for i, s := range suppressions {
		t, err := time.Parse("2006-01-02", s.Expires)
		if err != nil {
			continue
		}
		if now.After(t) {
			expired[i] = true
		}
	}

	var result SuppressionResult
	for _, s := range suppressions {
		if expired[suppressionIndex(suppressions, s)] {
			result.ExpiredSuppressions = append(result.ExpiredSuppressions, s)
		}
	}

	for _, f := range findings {
		if matchesSuppression(f, suppressions) {
			result.Suppressed = append(result.Suppressed, f)
		} else {
			result.Kept = append(result.Kept, f)
		}
	}

	return result
}

func matchesSuppression(f model.Finding, suppressions []Suppression) bool {
	for _, s := range suppressions {
		ruleMatch := s.RuleID == "*" || s.RuleID == f.RuleID
		resourceMatch := s.Resource == "*" || s.Resource == f.Resource
		if ruleMatch && resourceMatch {
			return true
		}
	}
	return false
}

func suppressionIndex(suppressions []Suppression, target Suppression) int {
	for i, s := range suppressions {
		if s.RuleID == target.RuleID && s.Resource == target.Resource {
			return i
		}
	}
	return -1
}
