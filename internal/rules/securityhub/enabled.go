// Package securityhub contains Well-Architected rules for AWS SECURITYHUB resources.
package securityhub

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AccountEnabled{})
}

// AccountEnabled checks that AWS Security Hub is enabled at the account level.
type AccountEnabled struct{}

func (r *AccountEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "SHB-001",
		Name:          "Security Hub Account Enabled",
		Description:   "AWS Security Hub should be enabled to provide centralized security findings and compliance checks.",
		Severity:      model.SeverityHigh,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_securityhub_account"},
		DocURL:        "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html",
	}
}

func (r *AccountEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	// The presence of aws_securityhub_account resource means Security Hub is being enabled.
	// No additional attribute check needed — the resource itself enables Security Hub.
	return nil
}
