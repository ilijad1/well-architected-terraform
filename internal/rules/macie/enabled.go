package macie

import (
	"github.com/ilijad1/well-architected-terraform/internal/engine"
	"github.com/ilijad1/well-architected-terraform/internal/model"
)

func init() {
	engine.Register(&AccountEnabled{})
}

// AccountEnabled checks that AWS Macie is enabled for S3 sensitive data discovery.
type AccountEnabled struct{}

func (r *AccountEnabled) Metadata() model.RuleMetadata {
	return model.RuleMetadata{
		ID:            "MAC-001",
		Name:          "Macie Account Enabled",
		Description:   "AWS Macie should be enabled to discover and protect sensitive data stored in S3.",
		Severity:      model.SeverityMedium,
		Pillar:        model.PillarSecurity,
		ResourceTypes: []string{"aws_macie2_account"},
		DocURL:        "https://docs.aws.amazon.com/macie/latest/user/getting-started.html",
	}
}

func (r *AccountEnabled) Evaluate(resource model.TerraformResource) []model.Finding {
	status, ok := resource.GetStringAttr("status")
	if ok && status != "ENABLED" {
		return []model.Finding{{
			RuleID:      "MAC-001",
			RuleName:    r.Metadata().Name,
			Severity:    model.SeverityMedium,
			Pillar:      model.PillarSecurity,
			Resource:    resource.Address(),
			File:        resource.File,
			Line:        resource.Line,
			Description: "AWS Macie account is not set to ENABLED status.",
			Remediation: "Set status = \"ENABLED\" in the aws_macie2_account resource.",
			DocURL:      r.Metadata().DocURL,
		}}
	}
	return nil
}
