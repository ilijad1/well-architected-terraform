package engine

import (
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

// Config controls which rules are executed.
type Config struct {
	Pillars     []model.Pillar
	MinSeverity model.Severity
	RuleIDs     []string
	ExcludeIDs  []string
}

// Engine runs rules against parsed Terraform resources.
type Engine struct {
	rules      []model.Rule
	crossRules []model.CrossResourceRule
}

// New creates an Engine with rules filtered by the given config.
func New(config Config) *Engine {
	return &Engine{
		rules:      filterRules(AllRules(), config),
		crossRules: filterCrossRules(AllCrossRules(), config),
	}
}

// NewWithRules creates an Engine with an explicit set of rules (useful for testing).
func NewWithRules(rules []model.Rule, crossRules []model.CrossResourceRule) *Engine {
	return &Engine{rules: rules, crossRules: crossRules}
}

// Rules returns the engine's active single-resource rules.
func (e *Engine) Rules() []model.Rule {
	return e.rules
}

// CrossRules returns the engine's active cross-resource rules.
func (e *Engine) CrossRules() []model.CrossResourceRule {
	return e.crossRules
}

// Analyze runs all applicable rules against the resources and returns findings.
// Single-resource rules are dispatched per resource type; cross-resource rules
// receive the full resource list.
func (e *Engine) Analyze(resources []model.TerraformResource) []model.Finding {
	// Build dispatch map: resource type -> applicable rules
	rulesByType := make(map[string][]model.Rule)
	for _, r := range e.rules {
		for _, rt := range r.Metadata().ResourceTypes {
			rulesByType[rt] = append(rulesByType[rt], r)
		}
	}

	var findings []model.Finding
	for _, resource := range resources {
		for _, rule := range rulesByType[resource.Type] {
			results := rule.Evaluate(resource)
			findings = append(findings, results...)
		}
	}

	// Run cross-resource rules against the full resource list.
	for _, rule := range e.crossRules {
		results := rule.EvaluateAll(resources)
		findings = append(findings, results...)
	}

	return findings
}

func filterCrossRules(rules []model.CrossResourceRule, config Config) []model.CrossResourceRule {
	if len(config.Pillars) == 0 && config.MinSeverity == "" && len(config.RuleIDs) == 0 && len(config.ExcludeIDs) == 0 {
		return rules
	}

	pillarSet := toStringSet(pillarsToStrings(config.Pillars))
	includeSet := toStringSet(config.RuleIDs)
	excludeSet := toStringSet(config.ExcludeIDs)
	minRank := model.SeverityRank(config.MinSeverity)

	var filtered []model.CrossResourceRule
	for _, r := range rules {
		meta := r.Metadata()

		if len(excludeSet) > 0 {
			if _, excluded := excludeSet[meta.ID]; excluded {
				continue
			}
		}

		if len(includeSet) > 0 {
			if _, included := includeSet[meta.ID]; !included {
				continue
			}
		}

		if len(pillarSet) > 0 {
			if _, ok := pillarSet[string(meta.Pillar)]; !ok {
				continue
			}
		}

		if minRank > 0 && model.SeverityRank(meta.Severity) < minRank {
			continue
		}

		filtered = append(filtered, r)
	}

	return filtered
}

func filterRules(rules []model.Rule, config Config) []model.Rule {
	if len(config.Pillars) == 0 && config.MinSeverity == "" && len(config.RuleIDs) == 0 && len(config.ExcludeIDs) == 0 {
		return rules
	}

	pillarSet := toStringSet(pillarsToStrings(config.Pillars))
	includeSet := toStringSet(config.RuleIDs)
	excludeSet := toStringSet(config.ExcludeIDs)
	minRank := model.SeverityRank(config.MinSeverity)

	var filtered []model.Rule
	for _, r := range rules {
		meta := r.Metadata()

		if len(excludeSet) > 0 {
			if _, excluded := excludeSet[meta.ID]; excluded {
				continue
			}
		}

		if len(includeSet) > 0 {
			if _, included := includeSet[meta.ID]; !included {
				continue
			}
		}

		if len(pillarSet) > 0 {
			if _, ok := pillarSet[string(meta.Pillar)]; !ok {
				continue
			}
		}

		if minRank > 0 && model.SeverityRank(meta.Severity) < minRank {
			continue
		}

		filtered = append(filtered, r)
	}

	return filtered
}

func toStringSet(strs []string) map[string]struct{} {
	set := make(map[string]struct{}, len(strs))
	for _, s := range strs {
		set[s] = struct{}{}
	}
	return set
}

func pillarsToStrings(pillars []model.Pillar) []string {
	strs := make([]string, len(pillars))
	for i, p := range pillars {
		strs[i] = string(p)
	}
	return strs
}
