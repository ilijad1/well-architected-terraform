package engine

import "github.com/ilijad1/well-architected-terraform/internal/model"

var globalRegistry []model.Rule
var globalCrossRegistry []model.CrossResourceRule

// Register adds a single-resource rule to the global registry. Called from init() in each rule package.
func Register(r model.Rule) {
	globalRegistry = append(globalRegistry, r)
}

// RegisterCross adds a cross-resource rule to the global registry. Called from init() in rule packages
// that need to evaluate findings across the full set of resources.
func RegisterCross(r model.CrossResourceRule) {
	globalCrossRegistry = append(globalCrossRegistry, r)
}

// AllRules returns all registered single-resource rules.
func AllRules() []model.Rule {
	return globalRegistry
}

// AllCrossRules returns all registered cross-resource rules.
func AllCrossRules() []model.CrossResourceRule {
	return globalCrossRegistry
}
